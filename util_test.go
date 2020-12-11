package osquery

import (
	"testing"
)

func TestKvSplit(t *testing.T) {
	check := func(testValue, expectedKey, expectedValue string) {
		gotKey, gotValue := kvSplit(testValue, "=")

		if gotKey != expectedKey {
			t.Errorf("Unexpected key. Got '%s' expected '%s'", gotKey, expectedKey)
		}
		if gotValue != expectedValue {
			t.Errorf("Unexpected value. Got '%s' expected '%s'", gotValue, expectedValue)
		}
	}

	check("foo=bar", "foo", "bar")
	check("foo=bar=bar", "foo", "bar=bar")
}

func TestParseKeyValueList(t *testing.T) {
	list := `
Something That's not a param

BuildNumber=19042
Caption=Microsoft Windows 10 Pro
Version=10.0.19042`
	params := parseKeyValueList(list)

	if params["BuildNumber"] != "19042" {
		t.Errorf("Invalid parameter from KV list")
	}
}

func TestParseParamsList(t *testing.T) {
	list := `ProductName:     Mac OS X
ProductVersion:  10.15.7
BuildVersion:    19H15`

	params := parseParamsList(list)

	if params["BuildVersion"] != "19H15" {
		t.Errorf("Unexpected parameter from params list. Got '%s' expected '19H15'", params["BuildVersion"])
	}
}
