package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

const testKey = "test-key"

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	s := &server{store: store, apiKey: testKey}
	srv := httptest.NewServer(s.routes(t.TempDir()))
	t.Cleanup(srv.Close)
	return srv
}

func ingest(t *testing.T, srv *httptest.Server, key, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/ingest", strings.NewReader(body))
	req.Header.Set("x-api-key", key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func getJSON(t *testing.T, srv *httptest.Server, path string, wantStatus int, v any) {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Fatalf("GET %s = %d, want %d", path, resp.StatusCode, wantStatus)
	}
	if v != nil {
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			t.Fatalf("GET %s: decode: %v", path, err)
		}
	}
}

const payload = `{
  "agent_version": "0.2.0",
  "host": {"host_id": "h1", "hostname": "web-1", "os_name": "Ubuntu", "os_version": "24.04", "kernel": "6.8"},
  "packages": [{"name": "bash", "version": "5.2", "arch": "amd64", "manager": "dpkg"},
               {"name": "openssh-server", "version": "9.6", "arch": "amd64", "manager": "dpkg"}],
  "cis_results": [{"id": "CIS-01", "title": "a", "cis_ref": "5.4.1.1", "status": "pass", "evidence": "ok"},
                  {"id": "CIS-02", "title": "b", "cis_ref": "5.1.20", "status": "fail", "evidence": "permitrootlogin yes"}]
}`

func TestIngestRejectsBadRequests(t *testing.T) {
	srv := newTestServer(t)
	tests := []struct {
		name, key, body string
		want            int
	}{
		{"missing key", "", payload, http.StatusUnauthorized},
		{"wrong key", "nope", payload, http.StatusUnauthorized},
		{"invalid JSON", testKey, "{not json", http.StatusBadRequest},
		{"no host id", testKey, `{"host": {"hostname": "x"}}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if resp := ingest(t, srv, tt.key, tt.body); resp.StatusCode != tt.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}
	var hosts []Host
	getJSON(t, srv, "/hosts", http.StatusOK, &hosts)
	if len(hosts) != 0 {
		t.Errorf("rejected requests stored %d hosts", len(hosts))
	}
}

func TestIngestThenRead(t *testing.T) {
	srv := newTestServer(t)
	if resp := ingest(t, srv, testKey, payload); resp.StatusCode != http.StatusOK {
		t.Fatalf("ingest status = %d", resp.StatusCode)
	}

	var hosts []Host
	getJSON(t, srv, "/hosts", http.StatusOK, &hosts)
	if len(hosts) != 1 || hosts[0].Hostname != "web-1" || hosts[0].PackageCount != 2 ||
		hosts[0].CISPass != 1 || hosts[0].CISTotal != 2 || hosts[0].LastSeen == "" {
		t.Errorf("hosts = %+v", hosts)
	}

	var host Host
	getJSON(t, srv, "/hosts/h1", http.StatusOK, &host)
	if host.AgentVersion != "0.2.0" {
		t.Errorf("agent_version = %q", host.AgentVersion)
	}

	for _, path := range []string{"/hosts/h1/apps", "/apps?host_id=h1"} {
		var pkgs []Package
		getJSON(t, srv, path, http.StatusOK, &pkgs)
		if len(pkgs) != 2 || pkgs[0].Name != "bash" {
			t.Errorf("%s = %+v", path, pkgs)
		}
	}

	for _, path := range []string{"/hosts/h1/cis-results", "/cis-results?host_id=h1"} {
		var results []CISResult
		getJSON(t, srv, path, http.StatusOK, &results)
		if len(results) != 2 || results[1].CheckID != "CIS-02" || results[1].Status != "fail" ||
			results[1].Evidence != "permitrootlogin yes" {
			t.Errorf("%s = %+v", path, results)
		}
	}
}

func TestReingestReplacesPreviousScan(t *testing.T) {
	srv := newTestServer(t)
	ingest(t, srv, testKey, payload)
	fixed := strings.Replace(payload, `"status": "fail", "evidence": "permitrootlogin yes"`, `"status": "pass", "evidence": "permitrootlogin no"`, 1)
	fixed = strings.Replace(fixed, `{"name": "bash", "version": "5.2", "arch": "amd64", "manager": "dpkg"},`, "", 1)
	ingest(t, srv, testKey, fixed)

	var hosts []Host
	getJSON(t, srv, "/hosts", http.StatusOK, &hosts)
	if len(hosts) != 1 || hosts[0].CISPass != 2 || hosts[0].PackageCount != 1 {
		t.Errorf("hosts after rescan = %+v", hosts)
	}
	var pkgs []Package
	getJSON(t, srv, "/hosts/h1/apps", http.StatusOK, &pkgs)
	if len(pkgs) != 1 {
		t.Errorf("old packages were not replaced: %+v", pkgs)
	}
}

func TestNotFoundAndMissingHostID(t *testing.T) {
	srv := newTestServer(t)
	getJSON(t, srv, "/hosts/unknown", http.StatusNotFound, nil)
	getJSON(t, srv, "/apps", http.StatusBadRequest, nil)
	getJSON(t, srv, "/cis-results", http.StatusBadRequest, nil)

	var pkgs []Package
	getJSON(t, srv, "/hosts/unknown/apps", http.StatusOK, &pkgs)
	if pkgs == nil || len(pkgs) != 0 {
		t.Errorf("unknown host apps = %#v, want empty list", pkgs)
	}
}
