package cis

import (
	"os"
	"os/exec"
	"strings"
)

type Status string

const (
	Pass  Status = "pass"
	Fail  Status = "fail"
	Error Status = "error"
)

type Result struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	CISRef   string `json:"cis_ref"`
	Status   Status `json:"status"`
	Evidence string `json:"evidence"`
}

type check struct {
	id, title, ref string
	run            func() (ok bool, evidence string, err error)
}

// RunAll executes every registered check and never stops on a single failure.
func RunAll() []Result {
	var results []Result
	for _, c := range checks {
		ok, evidence, err := c.run()
		r := Result{ID: c.id, Title: c.title, CISRef: c.ref, Status: Fail, Evidence: evidence}
		switch {
		case err != nil:
			r.Status, r.Evidence = Error, err.Error()
		case ok:
			r.Status = Pass
		}
		results = append(results, r)
	}
	return results
}

// sh runs a command and returns trimmed combined output.
func sh(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func has(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// configValue reads "key value" or "key = value" style config files, ignoring comments.
func configValue(path, key string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(strings.Replace(line, "=", " ", 1))
		if len(f) >= 2 && f[0] == key {
			return f[1], true
		}
	}
	return "", false
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
