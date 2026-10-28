package main

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
)

func main() {
	apiKey := os.Getenv("AGENT_API_KEY")
	if apiKey == "" {
		log.Fatal("AGENT_API_KEY must be set")
	}
	store, err := OpenStore(env("DB_PATH", "cis.db"))
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	s := &server{store: store, apiKey: apiKey}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /ingest", s.ingest)
	mux.HandleFunc("GET /hosts", s.listHosts)
	mux.HandleFunc("GET /hosts/{id}", s.getHost)
	mux.HandleFunc("GET /hosts/{id}/apps", s.listApps)
	mux.HandleFunc("GET /hosts/{id}/cis-results", s.listCIS)
	mux.HandleFunc("GET /apps", s.listApps)                               // ?host_id=
	mux.HandleFunc("GET /cis-results", s.listCIS)                         // ?host_id=
	mux.Handle("GET /", http.FileServer(http.Dir(env("WEB_DIR", "web")))) // frontend

	addr := env("ADDR", "127.0.0.1:8080")
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, logRequests(mux)))
}

type server struct {
	store  *Store
	apiKey string
}

func (s *server) ingest(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("x-api-key")
	if subtle.ConstantTimeCompare([]byte(key), []byte(s.apiKey)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var p IngestPayload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 10<<20)).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	if p.Host.HostID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host.host_id is required"})
		return
	}
	if err := s.store.Save(p); err != nil {
		serverError(w, err)
		return
	}
	log.Printf("ingested %s: %d packages, %d CIS results", p.Host.Hostname, len(p.Packages), len(p.CISResults))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "host_id": p.Host.HostID})
}

func (s *server) listHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.store.Hosts()
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (s *server) getHost(w http.ResponseWriter, r *http.Request) {
	h, err := s.store.Host(r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "host not found"})
		return
	}
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *server) listApps(w http.ResponseWriter, r *http.Request) {
	id, ok := hostID(w, r)
	if !ok {
		return
	}
	pkgs, err := s.store.Packages(id)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pkgs)
}

func (s *server) listCIS(w http.ResponseWriter, r *http.Request) {
	id, ok := hostID(w, r)
	if !ok {
		return
	}
	results, err := s.store.CISResults(id)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, results)
}

// hostID reads the host from the path (/hosts/{id}/...) or the query (?host_id=).
func hostID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if id == "" {
		id = r.URL.Query().Get("host_id")
	}
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host_id query parameter is required"})
		return "", false
	}
	return id, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func serverError(w http.ResponseWriter, err error) {
	log.Printf("error: %v", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
