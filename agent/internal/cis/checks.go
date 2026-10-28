package cis

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// CIS refs point at sections of the CIS Ubuntu 22.04 LTS Benchmark (Level 1).
// Replace them with the exact recommendation numbers from the PDF you download.
var checks = []check{
	{"CIS-01", "Password expiration and complexity configured", "5.4 / 5.5", checkPasswordPolicy},
	{"CIS-02", "SSH root login disabled", "5.2", checkSSHRootLogin},
	{"CIS-03", "Unused filesystems (cramfs, freevxfs, udf) disabled", "1.1.1", checkUnusedFS},
	{"CIS-04", "Host firewall (ufw/firewalld) active", "3.5", checkFirewall},
	{"CIS-05", "Time synchronization running", "2.1", checkTimeSync},
	{"CIS-06", "auditd installed and running", "4.1.1", checkAuditd},
	{"CIS-07", "AppArmor/SELinux enabled", "1.6.1", checkMAC},
	{"CIS-08", "No world-writable files", "6.1", checkWorldWritable},
	{"CIS-09", "GDM automatic login disabled", "1.8", checkGDMAutoLogin},
	{"CIS-10", "/etc/shadow permissions restricted", "6.1", checkShadowPerms},
}

func checkPasswordPolicy() (bool, string, error) {
	maxDays, _ := configValue("/etc/login.defs", "PASS_MAX_DAYS")
	minLen, _ := configValue("/etc/security/pwquality.conf", "minlen")
	md, _ := strconv.Atoi(maxDays)
	ml, _ := strconv.Atoi(minLen)
	ok := md > 0 && md <= 365 && ml >= 14
	return ok, fmt.Sprintf("PASS_MAX_DAYS=%q (want 1-365); pwquality minlen=%q (want >=14)", maxDays, minLen), nil
}

func checkSSHRootLogin() (bool, string, error) {
	if !has("sshd") {
		return true, "openssh-server not installed", nil
	}
	out, err := sh("sshd", "-T")
	if err != nil {
		return false, "", fmt.Errorf("sshd -T failed (run as root?): %v: %s", err, firstLines(out, 3))
	}
	for _, line := range strings.Split(out, "\n") {
		if v, found := strings.CutPrefix(line, "permitrootlogin "); found {
			return v == "no", line, nil
		}
	}
	return false, "permitrootlogin not found in sshd -T output", nil
}

func checkUnusedFS() (bool, string, error) {
	// squashfs is deliberately skipped: Ubuntu snaps depend on it (CIS notes this too).
	loaded, _ := sh("lsmod")
	ok := true
	var ev []string
	for _, mod := range []string{"cramfs", "freevxfs", "udf"} {
		out, _ := sh("modprobe", "-n", "-v", mod)
		disabled := strings.Contains(out, "install /bin/true") ||
			strings.Contains(out, "install /bin/false") ||
			strings.Contains(out, "not found")
		isLoaded := strings.Contains("\n"+loaded, "\n"+mod+" ")
		if !disabled || isLoaded {
			ok = false
		}
		ev = append(ev, fmt.Sprintf("%s: modprobe=%q loaded=%v", mod, out, isLoaded))
	}
	return ok, strings.Join(ev, "\n"), nil
}

func checkFirewall() (bool, string, error) {
	if has("ufw") {
		out, err := sh("ufw", "status")
		if err != nil {
			return false, "", fmt.Errorf("ufw status (run as root?): %v: %s", err, out)
		}
		return strings.Contains(out, "Status: active"), firstLines(out, 1), nil
	}
	if has("firewall-cmd") {
		out, _ := sh("firewall-cmd", "--state")
		return out == "running", "firewalld: " + out, nil
	}
	return false, "neither ufw nor firewalld is installed", nil
}

func checkTimeSync() (bool, string, error) {
	for _, svc := range []string{"chrony", "chronyd", "systemd-timesyncd", "ntp", "ntpd"} {
		if out, _ := sh("systemctl", "is-active", svc); out == "active" {
			return true, svc + " is active", nil
		}
	}
	return false, "no time sync service active (checked chrony, systemd-timesyncd, ntp)", nil
}

func checkAuditd() (bool, string, error) {
	active, _ := sh("systemctl", "is-active", "auditd")
	enabled, _ := sh("systemctl", "is-enabled", "auditd")
	return active == "active" && enabled == "enabled",
		fmt.Sprintf("auditd is-active=%q is-enabled=%q", active, enabled), nil
}

func checkMAC() (bool, string, error) {
	if has("aa-status") {
		_, err := sh("aa-status", "--enabled")
		out, _ := sh("aa-status")
		return err == nil, firstLines(out, 4), nil
	}
	if has("getenforce") {
		out, _ := sh("getenforce")
		return out == "Enforcing", "SELinux: " + out, nil
	}
	return false, "no AppArmor or SELinux tooling found", nil
}

func checkWorldWritable() (bool, string, error) {
	// -xdev stays on the root filesystem, so /proc, /sys etc. are skipped.
	out, _ := exec.Command("find", "/", "-xdev", "-type", "f", "-perm", "-0002").Output()
	var files []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			files = append(files, l)
		}
	}
	if len(files) == 0 {
		return true, "no world-writable files on the root filesystem", nil
	}
	return false, fmt.Sprintf("%d world-writable files, e.g.:\n%s",
		len(files), strings.Join(files[:min(10, len(files))], "\n")), nil
}

func checkGDMAutoLogin() (bool, string, error) {
	for _, p := range []string{"/etc/gdm3/custom.conf", "/etc/gdm/custom.conf"} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if v, found := configValue(p, "AutomaticLoginEnable"); found && strings.EqualFold(v, "true") {
			return false, p + ": AutomaticLoginEnable=" + v, nil
		}
		return true, p + ": automatic login not enabled", nil
	}
	return true, "GDM not installed (no custom.conf) - not applicable", nil
}

func checkShadowPerms() (bool, string, error) {
	fi, err := os.Stat("/etc/shadow")
	if err != nil {
		return false, "", err
	}
	mode := fi.Mode().Perm()
	st := fi.Sys().(*syscall.Stat_t)
	// 0640 or stricter: no owner execute, no group write/execute, nothing for others
	ok := mode&0o137 == 0 && st.Uid == 0
	return ok, fmt.Sprintf("/etc/shadow mode=%#o uid=%d gid=%d (want 0640 or stricter, owned by root)",
		mode, st.Uid, st.Gid), nil
}
