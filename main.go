package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	// listLimit caps the LIST response to bound memory for accidental
	// bulk imports. Personal scale should never approach this.
	listLimit = 1000
)

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,128}$`)

// requestIDRe restricts inbound X-Request-ID values: permissive enough
// for common formats (UUID, ULID, hex) but strict enough to defeat
// log-injection (no CRLF, no quote, bounded length).
var requestIDRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

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
	// JSON to stdout — Railway's log viewer parses it; jq-friendly locally.
	// contextHandler picks up request_id from r.Context() so handlers don't
	// have to thread it manually.
	slog.SetDefault(slog.New(&contextHandler{
		Handler: slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
	}))

	keyB64 := mustEnv("MASTER_KEY")
	token := mustEnv("AUTH_TOKEN")
	dbPath := getenv("DB_PATH", "./hush.db")
	port := getenv("PORT", "8080")

	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		fatal("MASTER_KEY: invalid base64", "error", err)
	}
	if len(key) != 32 {
		fatal("MASTER_KEY: must decode to 32 bytes", "got", len(key))
	}

	db, err := sql.Open("sqlite",
		dbPath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		fatal("sqlite open failed", "error", err)
	}
	defer db.Close()
	// SQLite serializes writers; capping the pool at 1 avoids spurious
	// SQLITE_BUSY at the database/sql layer for a single-user workload.
	db.SetMaxOpenConns(1)

	if err := initSchema(db); err != nil {
		fatal("schema init failed", "error", err)
	}

	s, err := newServer(db, key, token)
	if err != nil {
		fatal("server init failed", "error", err)
	}

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           withRequestID(s.routes()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("listening", "port", port, "db_path", dbPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal("listen failed", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutdown: draining connections", "grace", shutdownGrace.String())
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown failed", "error", err)
	}
	slog.Info("shutdown: done")
}

// newServer constructs a server from already-validated dependencies.
// Extracted from main() so tests can build a server against an in-memory
// database without parsing env vars or duplicating crypto setup.
func newServer(db *sql.DB, key []byte, token string) (*server, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &server{
		db:            db,
		gcm:           gcm,
		authTokenHash: sha256.Sum256([]byte(token)),
	}, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /v1/secrets", s.requireAuth(s.list))
	mux.HandleFunc("GET /v1/secrets/{name}", s.requireAuth(s.get))
	mux.HandleFunc("PUT /v1/secrets/{name}", s.requireAuth(s.put))
	mux.HandleFunc("DELETE /v1/secrets/{name}", s.requireAuth(s.del))
	return mux
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
		`SELECT name, created_at, updated_at FROM secrets ORDER BY name LIMIT ?`,
		listLimit)
	if err != nil {
		slog.ErrorContext(r.Context(), "list query failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	out := []secretRow{}
	for rows.Next() {
		var sr secretRow
		if err := rows.Scan(&sr.Name, &sr.CreatedAt, &sr.UpdatedAt); err != nil {
			slog.ErrorContext(r.Context(), "list scan failed", "error", err)
			writeErr(w, http.StatusInternalServerError, "db error")
			return
		}
		out = append(out, sr)
	}
	if err := rows.Err(); err != nil {
		slog.ErrorContext(r.Context(), "list rows iteration failed", "error", err)
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
		slog.ErrorContext(r.Context(), "get query failed", "name", name, "error", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if len(ct) < 1 {
		slog.ErrorContext(r.Context(), "ciphertext empty", "name", name)
		writeErr(w, http.StatusInternalServerError, "decrypt failed")
		return
	}
	if ct[0] != cryptoVersion {
		slog.ErrorContext(r.Context(), "unsupported ciphertext version",
			"name", name,
			"version", fmt.Sprintf("0x%02x", ct[0]),
			"expected", fmt.Sprintf("0x%02x", cryptoVersion),
		)
		writeErr(w, http.StatusInternalServerError, "decrypt failed")
		return
	}
	pt, err := s.gcm.Open(nil, nonce, ct[1:], aad(name))
	if err != nil {
		slog.ErrorContext(r.Context(), "decrypt failed", "name", name, "error", err)
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
	// Strict JSON: reject unknown fields (so a future struct change can't
	// be silently mass-assigned) and reject trailing bytes after the
	// object (so a malformed body can't slip through past a valid prefix).
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if dec.More() {
		writeErr(w, http.StatusBadRequest, "trailing data after json")
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
		slog.ErrorContext(r.Context(), "put exec failed", "name", name, "error", err)
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
		slog.ErrorContext(r.Context(), "delete exec failed", "name", name, "error", err)
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
		fatal("missing required env var", "key", k)
	}
	return v
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ---- logging / request-id middleware ----

// ctxKey is unexported and unique-per-package, the canonical Go pattern
// for stuffing values into request context without colliding.
type ctxKey struct{}

// contextHandler wraps an slog.Handler so any record logged with a
// context-bearing call (slog.ErrorContext etc.) automatically gets the
// request_id attribute attached. Handlers therefore don't need to
// thread the ID through every log call manually.
type contextHandler struct{ slog.Handler }

func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if id, ok := ctx.Value(ctxKey{}).(string); ok && id != "" {
		r.AddAttrs(slog.String("request_id", id))
	}
	return h.Handler.Handle(ctx, r)
}

// withRequestID resolves a request ID for each request, stashes it in
// the request context, and echoes it in X-Request-ID so a client can
// correlate a server log line to the response they received.
//
// Resolution order:
//  1. Inbound X-Request-ID (e.g. an upstream Railway / CDN trace) if it
//     passes requestIDRe — preserves end-to-end correlation.
//  2. Fresh 16-hex-char value from crypto/rand.
//  3. The string "rng-failed" as a last-resort sentinel so log lines
//     are still correlatable instead of orphaned. rand.Read failing on
//     Linux is essentially impossible but the empty-ID branch was a
//     silent observability hole.
func withRequestID(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !requestIDRe.MatchString(id) {
			b := make([]byte, 8)
			if _, err := rand.Read(b); err == nil {
				id = hex.EncodeToString(b)
			} else {
				id = "rng-failed"
			}
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), ctxKey{}, id)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// fatal emits a structured error log line and exits 1. Used for startup
// failures where slog's lack of Fatal-level would otherwise force every
// caller to repeat the os.Exit(1) themselves.
func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}
