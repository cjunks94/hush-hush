package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

const testToken = "test-token-deadbeef"

// newTestServer builds a fresh in-memory server. Each call gets its own DB.
// SetMaxOpenConns(1) is critical here: SQLite's :memory: database lives
// inside a single connection — without the cap, a second pool connection
// would see an empty schema.
func newTestServer(t *testing.T) (*server, http.Handler) {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })

	if err := initSchema(db); err != nil {
		t.Fatalf("init schema: %v", err)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	s, err := newServer(db, key, testToken)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	return s, s.routes()
}

// authReq builds an authenticated request. body=nil for GET/DELETE.
func authReq(method, path string, body []byte) *http.Request {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Authorization", "Bearer "+testToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// ---- Case 1 & 2: auth ----

func TestAuth(t *testing.T) {
	_, h := newTestServer(t)
	tests := []struct {
		name     string
		header   string
		wantCode int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong token", "Bearer wrong-token", http.StatusUnauthorized},
		{"missing Bearer prefix", testToken, http.StatusUnauthorized},
		{"correct token", "Bearer " + testToken, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/v1/secrets", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			rr := do(h, req)
			if rr.Code != tt.wantCode {
				t.Errorf("got %d, want %d (body=%s)", rr.Code, tt.wantCode, rr.Body.String())
			}
		})
	}
}

// /healthz is intentionally unauthenticated — guard against a future
// middleware change accidentally putting it behind auth.
func TestHealthz_NoAuthRequired(t *testing.T) {
	_, h := newTestServer(t)
	rr := do(h, httptest.NewRequest("GET", "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// ---- Case 3: PUT/GET round-trip exercises encrypt + decrypt + AAD ----

func TestPutGet_RoundTrip(t *testing.T) {
	_, h := newTestServer(t)
	const value = "sk-very-secret-12345"

	rr := do(h, authReq("PUT", "/v1/secrets/openai-key", []byte(`{"value":"`+value+`"}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT got %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}

	rr = do(h, authReq("GET", "/v1/secrets/openai-key", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET got %d, want 200", rr.Code)
	}
	var got secretRow
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Value != value {
		t.Errorf("value = %q, want %q", got.Value, value)
	}
	if got.Name != "openai-key" {
		t.Errorf("name = %q, want %q", got.Name, "openai-key")
	}
	if got.CreatedAt == 0 || got.UpdatedAt == 0 {
		t.Errorf("timestamps zero: created=%d updated=%d", got.CreatedAt, got.UpdatedAt)
	}
}

// ---- Case 4: GET non-existent ----

func TestGet_NotFound(t *testing.T) {
	_, h := newTestServer(t)
	rr := do(h, authReq("GET", "/v1/secrets/nope", nil))
	if rr.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", rr.Code)
	}
}

// ---- Case 5: PUT validation (empty value, missing field, malformed JSON) ----

func TestPut_BodyValidation(t *testing.T) {
	_, h := newTestServer(t)
	tests := []struct {
		name string
		body string
		want int
	}{
		{"empty value string", `{"value":""}`, http.StatusBadRequest},
		{"missing value field", `{}`, http.StatusBadRequest},
		{"malformed json", `not json`, http.StatusBadRequest},
		{"valid", `{"value":"x"}`, http.StatusOK},
		// Strict JSON: unknown fields rejected so a future struct change
		// can't be silently mass-assigned.
		{"unknown field rejected", `{"value":"x","admin":true}`, http.StatusBadRequest},
		// Trailing data after a valid object rejected so a malformed
		// body can't slip past a valid prefix.
		{"trailing junk after object", `{"value":"x"}JUNK`, http.StatusBadRequest},
		{"trailing second object", `{"value":"x"}{"value":"y"}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := do(h, authReq("PUT", "/v1/secrets/test", []byte(tt.body)))
			if rr.Code != tt.want {
				t.Errorf("got %d, want %d (body=%s)", rr.Code, tt.want, rr.Body.String())
			}
		})
	}
}

// ---- PUT enforces Content-Type: application/json ----

func TestPut_ContentTypeEnforcement(t *testing.T) {
	_, h := newTestServer(t)
	tests := []struct {
		name  string
		ctype string // empty = header not set
		want  int
	}{
		{"application/json", "application/json", http.StatusOK},
		{"json with charset", "application/json; charset=utf-8", http.StatusOK},
		{"case insensitive per RFC", "Application/JSON", http.StatusOK},
		{"missing content-type", "", http.StatusUnsupportedMediaType},
		{"text/plain", "text/plain", http.StatusUnsupportedMediaType},
		{"form encoded", "application/x-www-form-urlencoded", http.StatusUnsupportedMediaType},
		{"text/json (incorrect mime)", "text/json", http.StatusUnsupportedMediaType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/v1/secrets/ctype-test",
				bytes.NewReader([]byte(`{"value":"x"}`)))
			req.Header.Set("Authorization", "Bearer "+testToken)
			if tt.ctype != "" {
				req.Header.Set("Content-Type", tt.ctype)
			}
			rr := do(h, req)
			if rr.Code != tt.want {
				t.Errorf("got %d, want %d (body=%s)", rr.Code, tt.want, rr.Body.String())
			}
		})
	}
}

// ---- Case 6 & 7: value-size boundary at maxValueBytes ----

func TestPut_ValueSizeBoundary(t *testing.T) {
	_, h := newTestServer(t)
	tests := []struct {
		name   string
		valLen int
		want   int
	}{
		{"under limit", maxValueBytes - 1, http.StatusOK},
		{"exactly at limit", maxValueBytes, http.StatusOK},
		{"one byte over", maxValueBytes + 1, http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]string{"value": strings.Repeat("x", tt.valLen)})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			rr := do(h, authReq("PUT", "/v1/secrets/sized", body))
			if rr.Code != tt.want {
				t.Errorf("got %d, want %d", rr.Code, tt.want)
			}
		})
	}
}

// ---- Case 8: name length and charset boundaries ----

func TestNameValidation(t *testing.T) {
	_, h := newTestServer(t)
	tests := []struct {
		name string
		path string
		want int
	}{
		{"128 chars max length", "/v1/secrets/" + strings.Repeat("a", 128), http.StatusOK},
		{"129 chars over limit", "/v1/secrets/" + strings.Repeat("a", 129), http.StatusBadRequest},
		{"underscore + dot + dash allowed", "/v1/secrets/AWS_PROD.db-pw", http.StatusOK},
		{"slash rejected", "/v1/secrets/aws%2Fprod%2Fkey", http.StatusBadRequest},
		{"space rejected", "/v1/secrets/with%20space", http.StatusBadRequest},
		{"bang rejected", "/v1/secrets/bad!", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := do(h, authReq("PUT", tt.path, []byte(`{"value":"x"}`)))
			if rr.Code != tt.want {
				t.Errorf("got %d, want %d (body=%s)", rr.Code, tt.want, rr.Body.String())
			}
		})
	}
}

// ---- Case 9: DELETE is idempotent ----

func TestDelete_Idempotent(t *testing.T) {
	_, h := newTestServer(t)

	if rr := do(h, authReq("PUT", "/v1/secrets/del-test", []byte(`{"value":"x"}`))); rr.Code != http.StatusOK {
		t.Fatalf("PUT setup failed: %d", rr.Code)
	}

	for i, want := range []int{http.StatusNoContent, http.StatusNoContent, http.StatusNoContent} {
		rr := do(h, authReq("DELETE", "/v1/secrets/del-test", nil))
		if rr.Code != want {
			t.Errorf("DELETE attempt %d: got %d, want %d", i+1, rr.Code, want)
		}
	}

	// Never-existed name also 204 (idempotent contract).
	if rr := do(h, authReq("DELETE", "/v1/secrets/never-existed", nil)); rr.Code != http.StatusNoContent {
		t.Errorf("DELETE missing: got %d, want 204", rr.Code)
	}
}

// ---- Case 10: empty list returns [] not null ----

func TestList_EmptyArrayNotNull(t *testing.T) {
	_, h := newTestServer(t)
	rr := do(h, authReq("GET", "/v1/secrets", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rr.Code)
	}
	// Decode into a typed struct rather than string-matching the body.
	// JSON `null` decodes to a nil slice; JSON `[]` decodes to an empty
	// non-nil slice. The contract is the latter — clients can iterate
	// without nil-checking.
	var resp struct {
		Secrets []secretRow `json:"secrets"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Secrets == nil {
		t.Errorf("secrets must be [], not null/nil")
	}
	if len(resp.Secrets) != 0 {
		t.Errorf("expected empty slice, got %d items", len(resp.Secrets))
	}
}

// ---- Case 11: upsert preserves created_at, advances ciphertext ----

func TestPut_UpsertPreservesCreatedAt(t *testing.T) {
	_, h := newTestServer(t)

	rr := do(h, authReq("PUT", "/v1/secrets/upsert-test", []byte(`{"value":"first"}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("first PUT: %d", rr.Code)
	}
	var first struct{ CreatedAt int64 `json:"created_at"` }
	if err := json.NewDecoder(rr.Body).Decode(&first); err != nil {
		t.Fatalf("decode first: %v", err)
	}

	// Second PUT with different value — should preserve created_at.
	rr = do(h, authReq("PUT", "/v1/secrets/upsert-test", []byte(`{"value":"second"}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("second PUT: %d", rr.Code)
	}
	var second struct{ CreatedAt int64 `json:"created_at"` }
	if err := json.NewDecoder(rr.Body).Decode(&second); err != nil {
		t.Fatalf("decode second: %v", err)
	}

	if first.CreatedAt != second.CreatedAt {
		t.Errorf("created_at changed across upsert: %d → %d", first.CreatedAt, second.CreatedAt)
	}

	// And the latest value reads back.
	rr = do(h, authReq("GET", "/v1/secrets/upsert-test", nil))
	var got secretRow
	_ = json.NewDecoder(rr.Body).Decode(&got)
	if got.Value != "second" {
		t.Errorf("value after upsert = %q, want %q", got.Value, "second")
	}
}

// ---- Case 12: tampering the version byte must be rejected by the AEAD tag ----

func TestGet_TamperedCiphertextRejected(t *testing.T) {
	s, h := newTestServer(t)

	if rr := do(h, authReq("PUT", "/v1/secrets/tamper", []byte(`{"value":"original"}`))); rr.Code != http.StatusOK {
		t.Fatalf("PUT setup: %d", rr.Code)
	}

	// Flip the version byte (first byte of stored ciphertext) directly.
	// AAD = (cryptoVersion || name) so the AEAD tag must reject this.
	var ct []byte
	if err := s.db.QueryRow(`SELECT ciphertext FROM secrets WHERE name = ?`, "tamper").Scan(&ct); err != nil {
		t.Fatalf("read row: %v", err)
	}
	ct[0] ^= 0xFF
	if _, err := s.db.Exec(`UPDATE secrets SET ciphertext = ? WHERE name = ?`, ct, "tamper"); err != nil {
		t.Fatalf("tamper write: %v", err)
	}

	rr := do(h, authReq("GET", "/v1/secrets/tamper", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("got %d, want 500 (decrypt should fail on tampered ciphertext)", rr.Code)
	}

	// Restore byte; GET should succeed again.
	ct[0] ^= 0xFF
	if _, err := s.db.Exec(`UPDATE secrets SET ciphertext = ? WHERE name = ?`, ct, "tamper"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	rr = do(h, authReq("GET", "/v1/secrets/tamper", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("after restore got %d, want 200", rr.Code)
	}
}

// ---- aad() binds version byte AND name (unit-level helper test) ----

func TestAAD_IncludesVersionAndName(t *testing.T) {
	const name = "hello"
	got := aad(name)
	want := 1 + len(name)
	if len(got) != want {
		t.Fatalf("len(aad) = %d, want %d (1 version + %d name)", len(got), want, len(name))
	}
	if got[0] != cryptoVersion {
		t.Errorf("aad[0] = %#x, want %#x", got[0], cryptoVersion)
	}
	if string(got[1:]) != name {
		t.Errorf("aad[1:] = %q, want %q", string(got[1:]), name)
	}
}

// ---- AAD-binds-name as a runtime claim, not just a unit assertion ----
//
// Forge an attack: take name-a's stored ciphertext+nonce and overwrite
// name-b's row with them. AAD = (cryptoVersion || name), so name-a's
// AEAD tag does NOT authenticate under name-b. GET name-b must 500.
func TestGet_CrossNameRebindingRejected(t *testing.T) {
	s, h := newTestServer(t)

	for name, val := range map[string]string{"name-a": "value-a", "name-b": "value-b"} {
		body := []byte(`{"value":"` + val + `"}`)
		if rr := do(h, authReq("PUT", "/v1/secrets/"+name, body)); rr.Code != http.StatusOK {
			t.Fatalf("PUT %s: %d", name, rr.Code)
		}
	}

	var ct, nonce []byte
	if err := s.db.QueryRow(
		`SELECT ciphertext, nonce FROM secrets WHERE name = ?`, "name-a",
	).Scan(&ct, &nonce); err != nil {
		t.Fatalf("read name-a: %v", err)
	}
	if _, err := s.db.Exec(
		`UPDATE secrets SET ciphertext = ?, nonce = ? WHERE name = ?`, ct, nonce, "name-b",
	); err != nil {
		t.Fatalf("rebind: %v", err)
	}

	if rr := do(h, authReq("GET", "/v1/secrets/name-b", nil)); rr.Code != http.StatusInternalServerError {
		t.Errorf("got %d, want 500 — moving ciphertext between names must fail AEAD verification", rr.Code)
	}
}

// ---- withRequestID middleware behavior ----

func TestRequestID_Middleware(t *testing.T) {
	s, _ := newTestServer(t)
	h := withRequestID(s.routes())

	t.Run("generates 16-hex ID when none provided", func(t *testing.T) {
		rr := do(h, httptest.NewRequest("GET", "/healthz", nil))
		got := rr.Header().Get("X-Request-ID")
		if len(got) != 16 {
			t.Errorf("X-Request-ID = %q (len=%d), want 16-char hex", got, len(got))
		}
	})

	t.Run("preserves valid inbound ID for end-to-end correlation", func(t *testing.T) {
		const inbound = "01HK4P6V2ZR9G7X8F0D3M1ABCD"
		req := httptest.NewRequest("GET", "/healthz", nil)
		req.Header.Set("X-Request-ID", inbound)
		rr := do(h, req)
		if got := rr.Header().Get("X-Request-ID"); got != inbound {
			t.Errorf("X-Request-ID = %q, want %q (inbound should pass through)", got, inbound)
		}
	})

	t.Run("rejects malicious inbound ID and generates fresh", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/healthz", nil)
		// Attempt log injection via newline / semicolons / quotes.
		req.Header.Set("X-Request-ID", "evil\nfake_log_line; \"injected\"")
		rr := do(h, req)
		got := rr.Header().Get("X-Request-ID")
		if got == "" {
			t.Errorf("expected fresh fallback ID, got empty")
		}
		if strings.ContainsAny(got, "\n;\"") {
			t.Errorf("malicious chars leaked through: %q", got)
		}
	})
}
