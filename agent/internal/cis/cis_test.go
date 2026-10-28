package cis

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "conf")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfigValue(t *testing.T) {
	p := writeFile(t, "# PASS_MAX_DAYS 1\nPASS_MAX_DAYS\t365\nminlen = 14\nflag=on\n")
	tests := []struct {
		key, want string
		found     bool
	}{
		{"PASS_MAX_DAYS", "365", true}, // commented line is skipped, tab separator works
		{"minlen", "14", true},         // "key = value"
		{"flag", "on", true},           // "key=value"
		{"missing", "", false},
	}
	for _, tt := range tests {
		got, found := configValue(p, tt.key)
		if got != tt.want || found != tt.found {
			t.Errorf("configValue(%q) = %q, %v; want %q, %v", tt.key, got, found, tt.want, tt.found)
		}
	}
	if _, found := configValue(filepath.Join(t.TempDir(), "nope"), "x"); found {
		t.Error("missing file should report not found")
	}
}

func TestPasswordPolicy(t *testing.T) {
	tests := []struct {
		name, loginDefs, pwquality string
		want                       bool
	}{
		{"compliant", "PASS_MAX_DAYS 365", "minlen = 14", true},
		{"ubuntu default", "PASS_MAX_DAYS 99999", "# minlen = 8", false},
		{"short password allowed", "PASS_MAX_DAYS 90", "minlen = 8", false},
		{"expiry disabled", "PASS_MAX_DAYS 0", "minlen = 14", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loginDefsPath = writeFile(t, tt.loginDefs)
			pwqualityPath = writeFile(t, tt.pwquality)
			if got, _, _ := checkPasswordPolicy(); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGDMAutoLogin(t *testing.T) {
	tests := []struct {
		name string
		conf *string // nil = GDM not installed
		want bool
	}{
		{"gdm not installed", nil, true},
		{"autologin enabled", ptr("[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=bob\n"), false},
		{"autologin commented out", ptr("[daemon]\n#AutomaticLoginEnable=true\n"), true},
		{"autologin false", ptr("[daemon]\nAutomaticLoginEnable = False\n"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gdmConfPaths = []string{filepath.Join(t.TempDir(), "absent")}
			if tt.conf != nil {
				gdmConfPaths = []string{writeFile(t, *tt.conf)}
			}
			if got, _, _ := checkGDMAutoLogin(); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestShadowPermsOK(t *testing.T) {
	tests := []struct {
		mode os.FileMode
		uid  uint32
		want bool
	}{
		{0o640, 0, true},
		{0o600, 0, true},
		{0o000, 0, true},
		{0o644, 0, false},    // readable by everyone
		{0o660, 0, false},    // group can write
		{0o740, 0, false},    // owner execute bit set
		{0o640, 1000, false}, // not owned by root
	}
	for _, tt := range tests {
		if got := shadowPermsOK(tt.mode, tt.uid); got != tt.want {
			t.Errorf("shadowPermsOK(%#o, %d) = %v, want %v", tt.mode, tt.uid, got, tt.want)
		}
	}
}

func TestEvaluateTimeSync(t *testing.T) {
	active := func(names ...string) func(string) bool {
		return func(svc string) bool {
			for _, n := range names {
				if n == svc {
					return true
				}
			}
			return false
		}
	}
	tests := []struct {
		name   string
		active func(string) bool
		want   bool
	}{
		{"chrony only", active("chrony"), true},
		{"chrony seen through its alias too", active("chrony", "chronyd"), true},
		{"timesyncd only", active("systemd-timesyncd"), true},
		{"none", active(), false},
		{"two daemons", active("chrony", "systemd-timesyncd"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, ev := evaluateTimeSync(timeSyncGroups, tt.active); got != tt.want {
				t.Errorf("got %v (%s), want %v", got, ev, tt.want)
			}
		})
	}
}

func TestRunAllMapsStatuses(t *testing.T) {
	saved := checks
	defer func() { checks = saved }()
	checks = []check{
		{"T-1", "passes", "1.1", func() (bool, string, error) { return true, "ok", nil }},
		{"T-2", "fails", "1.2", func() (bool, string, error) { return false, "bad value", nil }},
		{"T-3", "breaks", "1.3", func() (bool, string, error) { return false, "", errors.New("boom") }},
	}
	got := RunAll()
	want := []struct {
		status   Status
		evidence string
	}{{Pass, "ok"}, {Fail, "bad value"}, {Error, "boom"}}
	if len(got) != len(want) {
		t.Fatalf("got %d results, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Status != w.status || got[i].Evidence != w.evidence {
			t.Errorf("result %d = %s/%q, want %s/%q", i, got[i].Status, got[i].Evidence, w.status, w.evidence)
		}
	}
}

func TestEveryCheckHasIDAndRef(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range checks {
		if c.id == "" || c.title == "" || c.ref == "" || c.run == nil {
			t.Errorf("incomplete check: %+v", c)
		}
		if seen[c.id] {
			t.Errorf("duplicate check id %s", c.id)
		}
		seen[c.id] = true
	}
	if len(checks) != 10 {
		t.Errorf("got %d checks, want 10", len(checks))
	}
}
