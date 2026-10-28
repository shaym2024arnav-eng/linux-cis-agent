package hostinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseOSRelease(t *testing.T) {
	p := filepath.Join(t.TempDir(), "os-release")
	content := "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := parseOSRelease(p)
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"NAME": "Ubuntu", "VERSION_ID": "24.04", "ID": "ubuntu"} {
		if m[k] != want {
			t.Errorf("%s = %q, want %q", k, m[k], want)
		}
	}
}
