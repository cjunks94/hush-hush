package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const (
	maxValueBytes      = 64 * 1024
	maxBodyBytes       = maxValueBytes + 1024
	shutdownGrace      = 10 * time.Second
	cryptoVersion byte = 0x01
)

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,128}$`)

type server struct {
	db            *sql.DB
	gcm           cipher.AEAD
	authTokenHash [32]byte
}

type secretRow struct {
	Name      string `json:"name"`
	Value     string `json:"value,omitempty"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

func main() {
	keyB64 := mustEnv("MASTER_KEY")
	token := mustEnv("AUTH_TOKEN")
	dbPath := getenv("DB_PATH", "./hush.db")
	port := getenv("PORT", "8080")

	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		log.Fatalf("MASTER_KEY: invalid base64: %v", err)
	}
	if len(key) != 32 {
		log.Fatalf("MASTER_KEY: must decode to 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("aes init: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("gcm init: %v", err)
	}

	db, err := sql.Open("sqlite",
		dbPath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		log.Fatalf("sqlite open: %v", err)
	}
	defer db.Close()
	// SQLite serializes writers; capping the pool at 1 avoids spurious
	// SQLITE_BUSY at the database/sql layer for a single-user workload.
	db.SetMaxOpenConns(1)

	if err := initSchema(db); err != nil {
		log.Fatalf("schema: %v", err)
	}

	s := &server{
		db:            db,
		gcm:           gcm,
		authTokenHash: sha256.Sum256([]byte(token)),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /v1/secrets", s.requireAuth(s.list))
	mux.HandleFunc("GET /v1/secrets/{name}", s.requireAuth(s.get))
	mux.HandleFunc("PUT /v1/secrets/{name}", s.requireAuth(s.put))
	mux.HandleFunc("DELETE /v1/secrets/{name}", s.requireAuth(s.del))

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("hush-hush listening on :%s (db=%s)", port, dbPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutdown: draining connections")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	log.Println("shutdown: done")
}

func initSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS secrets (
			name       TEXT PRIMARY KEY,
			ciphertext BLOB NOT NULL,
			nonce      BLOB NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);
	`)
	return err
}

func (s *server) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		// Hash both sides so the compared slices are always 32 bytes;
		// ConstantTimeCompare short-circuits on length mismatch and would
		// otherwise leak the real token's length via timing.
		given := strings.TrimPrefix(auth, "Bearer ")
		givenHash := sha256.Sum256([]byte(given))
		if subtle.ConstantTimeCompare(givenHash[:], s.authTokenHash[:]) != 1 {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		h(w, r)
	}
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) list(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT name, created_at, updated_at FROM secrets ORDER BY name`)
	if err != nil {
		log.Printf("list query: %v", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	out := []secretRow{}
	for rows.Next() {
		var sr secretRow
		if err := rows.Scan(&sr.Name, &sr.CreatedAt, &sr.UpdatedAt); err != nil {
			log.Printf("list scan: %v", err)
			writeErr(w, http.StatusInternalServerError, "db error")
			return
		}
		out = append(out, sr)
	}
	if err := rows.Err(); err != nil {
		log.Printf("list rows: %v", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secrets": out})
}

func (s *server) get(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !nameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid name")
		return
	}
	var ct, nonce []byte
	var createdAt, updatedAt int64
	err := s.db.QueryRowContext(r.Context(),
		`SELECT ciphertext, nonce, created_at, updated_at FROM secrets WHERE name = ?`, name,
	).Scan(&ct, &nonce, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		log.Printf("get query: %v", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if len(ct) < 1 || ct[0] != cryptoVersion {
		log.Printf("get %q: unsupported ciphertext version", name)
		writeErr(w, http.StatusInternalServerError, "decrypt failed")
		return
	}
	pt, err := s.gcm.Open(nil, nonce, ct[1:], aad(name))
	if err != nil {
		log.Printf("decrypt %q: %v", name, err)
		writeErr(w, http.StatusInternalServerError, "decrypt failed")
		return
	}
	writeJSON(w, http.StatusOK, secretRow{
		Name:      name,
		Value:     string(pt),
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	})
}

func (s *server) put(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !nameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid name")
		return
	}
	// Read one byte beyond the cap so an oversized body returns a clear
	// "too large" error instead of a confusing "invalid json" from a
	// silently truncated payload.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body")
		return
	}
	if len(body) > maxBodyBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	var in struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.Value == "" {
		writeErr(w, http.StatusBadRequest, "value required")
		return
	}
	if len(in.Value) > maxValueBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "value too large")
		return
	}

	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		writeErr(w, http.StatusInternalServerError, "rng failed")
		return
	}
	// 1-byte version prefix lets us migrate algorithms later without
	// losing access to existing rows. Version is also bound into AAD
	// so flipping the prefix byte is rejected by the AEAD tag.
	ct := append([]byte{cryptoVersion}, s.gcm.Seal(nil, nonce, []byte(in.Value), aad(name))...)

	now := time.Now().Unix()
	var createdAt int64
	err = s.db.QueryRowContext(r.Context(), `
		INSERT INTO secrets (name, ciphertext, nonce, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			ciphertext = excluded.ciphertext,
			nonce      = excluded.nonce,
			updated_at = excluded.updated_at
		RETURNING created_at
	`, name, ct, nonce, now, now).Scan(&createdAt)
	if err != nil {
		log.Printf("put exec: %v", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":       name,
		"created_at": createdAt,
		"updated_at": now,
	})
}

func (s *server) del(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !nameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid name")
		return
	}
	// Idempotent: a network retry of a successful DELETE should not
	// surface as an error. We don't distinguish "deleted" from "wasn't
	// there" — both end states are identical.
	if _, err := s.db.ExecContext(r.Context(), `DELETE FROM secrets WHERE name = ?`, name); err != nil {
		log.Printf("delete exec: %v", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	// Defense in depth against any CDN (Fastly sits in front on Railway)
	// caching authenticated responses.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// aad binds both the secret name AND the ciphertext version into the AEAD
// associated data. Name binding prevents row-rebinding (moving ciphertext
// between names); version binding prevents algorithm-downgrade attacks if
// a future cryptoVersion is introduced.
func aad(name string) []byte {
	out := make([]byte, 0, 1+len(name))
	out = append(out, cryptoVersion)
	out = append(out, name...)
	return out
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("missing required env var: %s", k)
	}
	return v
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
