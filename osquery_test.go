package osquery_test

import (
	"fmt"
	"os"
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

func TestQueryGithubActions(t *testing.T) {
	if os.Getenv("GITHUB_ACTION") == "" {
		t.SkipNow()
	}

	info, err := osquery.Get()
	if err != nil {
		panic(err)
	}

	variant := strings.ToLower(info.Variant)

	if runtime.GOOS == "win32" {
		if !strings.HasPrefix(variant, "microsoft windows server") {
			t.Errorf("Unexpected variant '%s', expected to start with 'microsoft windows server'", variant)
		}
	} else {
		expectedVariant := ""

		switch runtime.GOOS {
		case "linux":
			expectedVariant = "ubuntu"
		case "darwin":
			expectedVariant = "macos"
		default:
			t.Fatalf("Unknown goos %s", runtime.GOOS)
		}

		if variant != expectedVariant {
			t.Errorf("Unexpected variant '%s' expected '%s'", variant, expectedVariant)
		}
	}
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
