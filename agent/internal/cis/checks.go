package cis

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// CIS refs are recommendation numbers from the CIS Ubuntu Linux 22.04 LTS
// Benchmark v2.0.0, Level 1 - Server.
var checks = []check{
	{"CIS-01", "Password expiration and minimum length configured", "5.4.1.1, 5.3.3.2.2", checkPasswordPolicy},
	{"CIS-02", "SSH root login disabled", "5.1.20", checkSSHRootLogin},
	{"CIS-03", "Unused filesystem kernel modules (cramfs, freevxfs, udf) not available", "1.1.1.1, 1.1.1.2, 1.1.1.7", checkUnusedFS},
	{"CIS-04", "Host firewall (ufw/firewalld) enabled", "4.1.3", checkFirewall},
	{"CIS-05", "A single time synchronization daemon is in use", "2.3.1.1", checkTimeSync},
	{"CIS-06", "auditd installed, enabled and active", "6.3.1.1, 6.3.1.2", checkAuditd},
	{"CIS-07", "AppArmor/SELinux enabled", "1.3.1.2", checkMAC},
	{"CIS-08", "No world-writable files", "7.1.11", checkWorldWritable},
	// Not a standalone 22.04 recommendation: it's from the assignment and sits in the GDM section (1.7).
	{"CIS-09", "GDM automatic login disabled", "1.7 (GDM)", checkGDMAutoLogin},
	{"CIS-10", "/etc/shadow permissions restricted", "7.1.5", checkShadowPerms},
}

// File locations, overridable in tests.
var (
	loginDefsPath  = "/etc/login.defs"
	pwqualityPath  = "/etc/security/pwquality.conf"
	gdmConfPaths   = []string{"/etc/gdm3/custom.conf", "/etc/gdm/custom.conf"}
	shadowPath     = "/etc/shadow"
	timeSyncGroups = [][]string{{"chrony", "chronyd"}, {"systemd-timesyncd"}, {"ntp", "ntpd"}}
)

func checkPasswordPolicy() (bool, string, error) {
	maxDays, _ := configValue(loginDefsPath, "PASS_MAX_DAYS")
	minLen, _ := configValue(pwqualityPath, "minlen")
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
	ok, evidence := evaluateTimeSync(timeSyncGroups, func(svc string) bool {
		out, _ := sh("systemctl", "is-active", svc)
		return out == "active"
	})
	return ok, evidence, nil
}

// evaluateTimeSync passes when exactly one daemon is active. Each group lists the
// unit names of one daemon (chrony is also reachable through its chronyd alias).
func evaluateTimeSync(groups [][]string, isActive func(string) bool) (bool, string) {
	var active []string
	for _, names := range groups {
		for _, n := range names {
			if isActive(n) {
				active = append(active, n)
				break
			}
		}
	}
	switch len(active) {
	case 0:
		return false, "no time sync daemon active (checked chrony, systemd-timesyncd, ntp)"
	case 1:
		return true, active[0] + " is the only active time sync daemon"
	default:
		return false, "multiple time sync daemons active: " + strings.Join(active, ", ")
	}
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
	for _, p := range gdmConfPaths {
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
	fi, err := os.Stat(shadowPath)
	if err != nil {
		return false, "", err
	}
	st := fi.Sys().(*syscall.Stat_t)
	return shadowPermsOK(fi.Mode().Perm(), st.Uid), fmt.Sprintf("%s mode=%#o uid=%d gid=%d (want 0640 or stricter, owned by root)",
		shadowPath, fi.Mode().Perm(), st.Uid, st.Gid), nil
}

// shadowPermsOK accepts 0640 or stricter (no owner execute, no group write/execute,
// nothing for others) owned by root.
func shadowPermsOK(mode os.FileMode, uid uint32) bool {
	return mode&0o137 == 0 && uid == 0
}
