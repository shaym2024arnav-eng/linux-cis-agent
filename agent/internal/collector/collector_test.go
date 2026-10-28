package collector

import (
	"reflect"
	"testing"
)

func TestParseDpkg(t *testing.T) {
	out := "ii \tbash\t5.2.21-2ubuntu4\tamd64\n" +
		"rc \told-pkg\t1.0\tamd64\n" + // removed, only config left: skipped
		"ii \ttzdata\t2024a-3ubuntu1\tall\n" +
		"garbage line\n"
	want := []Package{
		{Name: "bash", Version: "5.2.21-2ubuntu4", Arch: "amd64", Manager: "dpkg"},
		{Name: "tzdata", Version: "2024a-3ubuntu1", Arch: "all", Manager: "dpkg"},
	}
	if got := parseDpkg(out); !reflect.DeepEqual(got, want) {
		t.Errorf("parseDpkg() = %+v, want %+v", got, want)
	}
}

func TestParseRPM(t *testing.T) {
	out := "bash\t5.1.8-9.el9\tx86_64\nopenssl\t3.0.7-27.el9\tx86_64\n\n"
	want := []Package{
		{Name: "bash", Version: "5.1.8-9.el9", Arch: "x86_64", Manager: "rpm"},
		{Name: "openssl", Version: "3.0.7-27.el9", Arch: "x86_64", Manager: "rpm"},
	}
	if got := parseRPM(out); !reflect.DeepEqual(got, want) {
		t.Errorf("parseRPM() = %+v, want %+v", got, want)
	}
}
