package main

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS hosts (
	host_id       TEXT PRIMARY KEY,
	hostname      TEXT,
	os_name       TEXT,
	os_version    TEXT,
	os_id         TEXT,
	kernel        TEXT,
	agent_version TEXT,
	last_seen     TEXT,
	package_count INTEGER,
	cis_pass      INTEGER,
	cis_total     INTEGER
);
CREATE TABLE IF NOT EXISTS packages (
	host_id TEXT,
	name    TEXT,
	version TEXT,
	arch    TEXT,
	manager TEXT
);
CREATE INDEX IF NOT EXISTS idx_packages_host ON packages(host_id);
CREATE TABLE IF NOT EXISTS cis_results (
	host_id    TEXT,
	check_id   TEXT,
	title      TEXT,
	cis_ref    TEXT,
	status     TEXT,
	evidence   TEXT,
	checked_at TEXT,
	PRIMARY KEY (host_id, check_id)
);`

type Host struct {
	HostID       string `json:"host_id"`
	Hostname     string `json:"hostname"`
	OSName       string `json:"os_name"`
	OSVersion    string `json:"os_version"`
	OSID         string `json:"os_id"`
	Kernel       string `json:"kernel"`
	AgentVersion string `json:"agent_version"`
	LastSeen     string `json:"last_seen"`
	PackageCount int    `json:"package_count"`
	CISPass      int    `json:"cis_pass"`
	CISTotal     int    `json:"cis_total"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	Manager string `json:"manager"`
}

type CISResult struct {
	CheckID   string `json:"check_id"`
	Title     string `json:"title"`
	CISRef    string `json:"cis_ref"`
	Status    string `json:"status"`
	Evidence  string `json:"evidence"`
	CheckedAt string `json:"checked_at"`
}

// IngestPayload is the JSON document the agent POSTs to /ingest.
type IngestPayload struct {
	AgentVersion string `json:"agent_version"`
	Host         struct {
		HostID    string `json:"host_id"`
		Hostname  string `json:"hostname"`
		OSName    string `json:"os_name"`
		OSVersion string `json:"os_version"`
		OSID      string `json:"os_id"`
		Kernel    string `json:"kernel"`
	} `json:"host"`
	Packages   []Package `json:"packages"`
	CISResults []struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		CISRef   string `json:"cis_ref"`
		Status   string `json:"status"`
		Evidence string `json:"evidence"`
	} `json:"cis_results"`
}

type Store struct{ db *sql.DB }

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite allows one writer at a time
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// Save replaces everything stored for the host with the latest scan, in one transaction.
func (s *Store) Save(p IngestPayload) error {
	now := time.Now().UTC().Format(time.RFC3339)
	pass := 0
	for _, r := range p.CISResults {
		if r.Status == "pass" {
			pass++
		}
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	h := p.Host
	if _, err := tx.Exec(`INSERT OR REPLACE INTO hosts VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		h.HostID, h.Hostname, h.OSName, h.OSVersion, h.OSID, h.Kernel, p.AgentVersion, now,
		len(p.Packages), pass, len(p.CISResults)); err != nil {
		return err
	}

	if _, err := tx.Exec(`DELETE FROM packages WHERE host_id = ?`, h.HostID); err != nil {
		return err
	}
	for _, pkg := range p.Packages {
		if _, err := tx.Exec(`INSERT INTO packages VALUES (?,?,?,?,?)`,
			h.HostID, pkg.Name, pkg.Version, pkg.Arch, pkg.Manager); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(`DELETE FROM cis_results WHERE host_id = ?`, h.HostID); err != nil {
		return err
	}
	for _, r := range p.CISResults {
		if _, err := tx.Exec(`INSERT INTO cis_results VALUES (?,?,?,?,?,?,?)`,
			h.HostID, r.ID, r.Title, r.CISRef, r.Status, r.Evidence, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const hostColumns = `host_id, hostname, os_name, os_version, os_id, kernel, agent_version,
	last_seen, package_count, cis_pass, cis_total`

func scanHost(row interface{ Scan(...any) error }) (Host, error) {
	var h Host
	err := row.Scan(&h.HostID, &h.Hostname, &h.OSName, &h.OSVersion, &h.OSID, &h.Kernel,
		&h.AgentVersion, &h.LastSeen, &h.PackageCount, &h.CISPass, &h.CISTotal)
	return h, err
}

func (s *Store) Hosts() ([]Host, error) {
	rows, err := s.db.Query(`SELECT ` + hostColumns + ` FROM hosts ORDER BY hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hosts := []Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, rows.Err()
}

// Host returns sql.ErrNoRows when the host is unknown.
func (s *Store) Host(id string) (Host, error) {
	return scanHost(s.db.QueryRow(`SELECT `+hostColumns+` FROM hosts WHERE host_id = ?`, id))
}

func (s *Store) Packages(hostID string) ([]Package, error) {
	rows, err := s.db.Query(`SELECT name, version, arch, manager FROM packages WHERE host_id = ? ORDER BY name`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pkgs := []Package{}
	for rows.Next() {
		var p Package
		if err := rows.Scan(&p.Name, &p.Version, &p.Arch, &p.Manager); err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, rows.Err()
}

func (s *Store) CISResults(hostID string) ([]CISResult, error) {
	rows, err := s.db.Query(`SELECT check_id, title, cis_ref, status, evidence, checked_at
		FROM cis_results WHERE host_id = ? ORDER BY check_id`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	results := []CISResult{}
	for rows.Next() {
		var r CISResult
		if err := rows.Scan(&r.CheckID, &r.Title, &r.CISRef, &r.Status, &r.Evidence, &r.CheckedAt); err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, rows.Err()
}
