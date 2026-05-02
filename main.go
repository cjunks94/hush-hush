package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	maxValueBytes = 64 * 1024
	maxBodyBytes  = maxValueBytes + 1024
)

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,128}$`)

type server struct {
	db        *sql.DB
	gcm       cipher.AEAD
	authToken []byte
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

	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatalf("sqlite open: %v", err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		log.Fatalf("schema: %v", err)
	}

	s := &server{db: db, gcm: gcm, authToken: []byte(token)}

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
	log.Printf("hush-hush listening on :%s (db=%s)", port, dbPath)
	log.Fatal(srv.ListenAndServe())
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
		given := []byte(strings.TrimPrefix(auth, "Bearer "))
		if subtle.ConstantTimeCompare(given, s.authToken) != 1 {
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
	// AAD = name; rebinding ciphertext to a different row is rejected.
	pt, err := s.gcm.Open(nil, nonce, ct, []byte(name))
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
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body")
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
		writeErr(w, http.StatusBadRequest, "value too large")
		return
	}

	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		writeErr(w, http.StatusInternalServerError, "rng failed")
		return
	}
	ct := s.gcm.Seal(nil, nonce, []byte(in.Value), []byte(name))

	now := time.Now().Unix()
	_, err = s.db.ExecContext(r.Context(), `
		INSERT INTO secrets (name, ciphertext, nonce, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			ciphertext = excluded.ciphertext,
			nonce      = excluded.nonce,
			updated_at = excluded.updated_at
	`, name, ct, nonce, now, now)
	if err != nil {
		log.Printf("put exec: %v", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "updated_at": now})
}

func (s *server) del(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !nameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid name")
		return
	}
	res, err := s.db.ExecContext(r.Context(), `DELETE FROM secrets WHERE name = ?`, name)
	if err != nil {
		log.Printf("delete exec: %v", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
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
