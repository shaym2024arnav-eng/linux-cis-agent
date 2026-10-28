package sender

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func init() { backoff = func(int) time.Duration { return 0 } }

// server answers with the given status codes in order and records what it received.
func server(t *testing.T, statuses ...int) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-api-key"); got != "secret" {
			t.Errorf("x-api-key = %q, want secret", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["hello"] != "world" {
			t.Errorf("body = %v, err %v", body, err)
		}
		w.WriteHeader(statuses[min(calls, len(statuses)-1)])
		calls++
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestSendSuccess(t *testing.T) {
	srv, calls := server(t, http.StatusOK)
	if err := Send(srv.URL, "secret", map[string]string{"hello": "world"}); err != nil {
		t.Fatal(err)
	}
	if *calls != 1 {
		t.Errorf("calls = %d, want 1", *calls)
	}
}

func TestSendRetriesServerErrors(t *testing.T) {
	srv, calls := server(t, http.StatusInternalServerError, http.StatusBadGateway, http.StatusOK)
	if err := Send(srv.URL, "secret", map[string]string{"hello": "world"}); err != nil {
		t.Fatal(err)
	}
	if *calls != 3 {
		t.Errorf("calls = %d, want 3", *calls)
	}
}

func TestSendGivesUpAfterMaxAttempts(t *testing.T) {
	srv, calls := server(t, http.StatusServiceUnavailable)
	if err := Send(srv.URL, "secret", map[string]string{"hello": "world"}); err == nil {
		t.Fatal("expected an error")
	}
	if *calls != maxAttempts {
		t.Errorf("calls = %d, want %d", *calls, maxAttempts)
	}
}

func TestSendDoesNotRetryClientErrors(t *testing.T) {
	srv, calls := server(t, http.StatusUnauthorized)
	if err := Send(srv.URL, "secret", map[string]string{"hello": "world"}); err == nil {
		t.Fatal("expected an error")
	}
	if *calls != 1 {
		t.Errorf("calls = %d, want 1 (no retry on 4xx)", *calls)
	}
}
