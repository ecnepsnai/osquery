package osquery_test

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/ecnepsnai/osquery"
)

func TestQuery(t *testing.T) {
	info, err := osquery.Get()
	if err != nil {
		t.Fatalf("Error getting OS info: %s", err.Error())
	}
	if info == nil {
		t.Fatalf("No OS info returned")
	}
	if info.Platform != runtime.GOOS {
		t.Fatalf("Invalid OS platform. Got '%s' expected '%s'", info.Platform, runtime.GOOS)
	}
	t.Logf("OS Info: %#v", *info)
}

func ExampleGet() {
	info, err := osquery.Get()
	if err != nil {
		panic(err)
	}

	if info.Variant == "ubuntu" {
		if strings.HasPrefix(info.VariantVersion, "20.04") {
			fmt.Printf("You're using Ubuntu Focal Fossa\n")
		} else if strings.HasPrefix(info.VariantVersion, "18.04") {
			fmt.Printf("You're using Ubuntu Bionic Beaver\n")
		} else if strings.HasPrefix(info.VariantVersion, "16.04") {
			fmt.Printf("You're using Ubuntu Xinial Xerus\n")
		} else {
			fmt.Printf("I'm not sure what version of Ubuntu you're using!\n")
		}
	}
}
