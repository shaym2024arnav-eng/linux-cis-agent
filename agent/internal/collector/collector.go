package collector

import (
	"fmt"
	"os/exec"
	"strings"
)

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	Manager string `json:"manager"`
}

// Collect detects the package manager and returns installed packages.
func Collect() ([]Package, error) {
	switch {
	case has("dpkg-query"):
		return dpkg()
	case has("rpm"):
		return rpm()
	}
	return nil, fmt.Errorf("no supported package manager (dpkg/rpm) found")
}

func has(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

func dpkg() ([]Package, error) {
	out, err := exec.Command("dpkg-query", "-W",
		"-f=${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n").Output()
	if err != nil {
		return nil, fmt.Errorf("dpkg-query: %w", err)
	}
	var pkgs []Package
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, "\t")
		// "ii" = installed; skip removed packages that only left config files ("rc")
		if len(f) != 4 || !strings.HasPrefix(f[0], "ii") {
			continue
		}
		pkgs = append(pkgs, Package{Name: f[1], Version: f[2], Arch: f[3], Manager: "dpkg"})
	}
	return pkgs, nil
}

func rpm() ([]Package, error) {
	out, err := exec.Command("rpm", "-qa", "--queryformat",
		"%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n").Output()
	if err != nil {
		return nil, fmt.Errorf("rpm -qa: %w", err)
	}
	var pkgs []Package
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			continue
		}
		pkgs = append(pkgs, Package{Name: f[0], Version: f[1], Arch: f[2], Manager: "rpm"})
	}
	return pkgs, nil
}
