package hostinfo

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
	"time"
)

type HostInfo struct {
	HostID      string    `json:"host_id"`
	Hostname    string    `json:"hostname"`
	OSName      string    `json:"os_name"`
	OSVersion   string    `json:"os_version"`
	OSID        string    `json:"os_id"`
	Kernel      string    `json:"kernel"`
	CollectedAt time.Time `json:"collected_at"`
}

func Collect() (HostInfo, error) {
	h := HostInfo{CollectedAt: time.Now().UTC()}
	h.Hostname, _ = os.Hostname()
	if id, err := os.ReadFile("/etc/machine-id"); err == nil {
		h.HostID = strings.TrimSpace(string(id))
	}
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		h.Kernel = strings.TrimSpace(string(out))
	}
	osRel, err := parseOSRelease("/etc/os-release")
	if err != nil {
		return h, err
	}
	h.OSName = osRel["NAME"]
	h.OSVersion = osRel["VERSION_ID"]
	h.OSID = osRel["ID"]
	return h, nil
}

func parseOSRelease(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok {
			m[k] = strings.Trim(v, `"`)
		}
	}
	return m, sc.Err()
}
