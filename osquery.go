// Package osquery provides information about the running operating system. It can be used to derive more information
// about the specific variant of operating system that is running. For example, you can use osquery to determine that
// which distribution of Linux is being used, which release of FreeBSD, or which edition of Windows.
//
// It currently only supports traditional operating systems:
// Linux, macOS (darwin), FreeBSD, NetBSD, OpenBSD, Windows, and Solaris.
//
// The OSInfo object contains details into the specific operating system that is running. For example, this is
// what is returned for a Fedora Linux device:
//
//     osquery.OSInfo{
//         Platform:       "linux",
//         Kernel:         "Linux",
//         KernelVersion:  "5.9.11-200.fc33.x86_64",
//         Variant:        "Fedora",
//         VariantVersion: "33 (Workstation Edition)",
//     }
//
// or, for a Windows device:
//
//     osquery.OSInfo{
//         Platform:       "windows",
//         Kernel:         "NT",
//         KernelVersion:  "19042",
//         Variant:        "Microsoft Windows 10 Pro",
//         VariantVersion: "10.0.19042",
//     }
//
package osquery

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// OSInfo describes information about an operating system
type OSInfo struct {
	// The platform is a high-level description of the OS. This maps to GOOS.
	Platform string
	// The name of the kernel used by the operating system.
	Kernel string
	// The specific version of the kernel.
	KernelVersion string
	// The variant or distribution of the kernel
	Variant string
	// The version of the variant
	VariantVersion string
}

// Get will attempt to determine the current operating system and return information about it, or an error.
func Get() (*OSInfo, error) {

	switch runtime.GOOS {
	case "darwin":
		return getDarwin()
	case "freebsd", "netbsd", "openbsd":
		return getBSD()
	case "linux":
		return getLinux()
	case "windows":
		return getWindows()
	case "solaris":
		return getSolaris()
	}

	return getOther()
}

func getDarwin() (*OSInfo, error) {
	kernel := "Darwin"
	kernelVersion, err := getSystemUname("-r")
	if err != nil {
		return nil, err
	}

	out, err := exec.Command("/usr/bin/sw_vers").CombinedOutput()
	if err != nil {
		return nil, err
	}

	params := parseParamsList(string(out))
	variantName := params["ProductName"]
	variantVersion := params["ProductVersion"]

	return &OSInfo{
		Platform:       runtime.GOOS,
		Kernel:         kernel,
		KernelVersion:  kernelVersion,
		Variant:        variantName,
		VariantVersion: variantVersion,
	}, nil
}

func getLinux() (*OSInfo, error) {
	kernel := "Linux"
	kernelVersion, err := getSystemUname("-r")
	if err != nil {
		return nil, err
	}

	out, err := exec.Command("/bin/sh", "-c", "cat /etc/*-release").CombinedOutput()
	if err != nil {
		return nil, err
	}

	params := parseKeyValueList(string(out))

	// Look for common keys first: NAME and VERSION
	variantName := params["NAME"]
	variantVersion := params["VERSION"]

	// Fall back to using ID and VERSION_ID
	if variantName == "" {
		variantName = params["ID"]
	}
	if variantVersion == "" {
		variantVersion = params["VERSION_ID"]
	}

	// This is some weird Linux that doesn't play by the rules
	if variantName == "" {
		variantName = "unknown"
	}
	if variantVersion == "" {
		variantVersion = "unknown"
	}

	return &OSInfo{
		Platform:       runtime.GOOS,
		Kernel:         kernel,
		KernelVersion:  kernelVersion,
		Variant:        variantName,
		VariantVersion: variantVersion,
	}, nil
}

func getBSD() (*OSInfo, error) {
	// Will output something to the format of:
	// - FreeBSD 12.2-RELEASE
	// - NetBSD 9.1
	// - OpenBSD 6.8
	uname, err := getSystemUname("-rs")
	if err != nil {
		return nil, err
	}

	parts := strings.Split(uname, " ")
	variantName := parts[0]
	variantVersion := parts[1]

	return &OSInfo{
		Platform:       runtime.GOOS,
		Kernel:         variantName,
		KernelVersion:  variantVersion,
		Variant:        variantName,
		VariantVersion: variantVersion,
	}, nil
}

func getWindows() (*OSInfo, error) {
	out, err := exec.Command("wmic", "os", "get", "Caption,Version,BuildNumber", "/value").CombinedOutput()
	if err != nil {
		return nil, err
	}

	params := parseKeyValueList(string(out))

	buildNumber := params["BuildNumber"]
	variantName := params["Caption"]
	variantVersion := params["Version"]

	if buildNumber == "" {
		buildNumber = "unknown"
	}
	if variantName == "" {
		variantName = "unknown"
	}
	if variantVersion == "" {
		variantVersion = "unknown"
	}

	return &OSInfo{
		Platform:       runtime.GOOS,
		Kernel:         "NT",
		KernelVersion:  buildNumber,
		Variant:        variantName,
		VariantVersion: variantVersion,
	}, nil
}

func getSolaris() (*OSInfo, error) {
	kernel := "SunOS"
	kernelVersion, err := getSystemUname("-r")
	if err != nil {
		return nil, err
	}

	out, err := exec.Command("/bin/sh", "-c", "cat /etc/*-release").CombinedOutput()
	if err != nil {
		return nil, err
	}

	params := parseKeyValueList(string(out))

	variantName := params["NAME"]
	variantVersion := params["VERSION"]

	return &OSInfo{
		Platform:       runtime.GOOS,
		Kernel:         kernel,
		KernelVersion:  kernelVersion,
		Variant:        variantName,
		VariantVersion: variantVersion,
	}, nil
}

func getOther() (*OSInfo, error) {
	return &OSInfo{
		Platform:       runtime.GOOS,
		Kernel:         "unknown",
		KernelVersion:  "unknown",
		Variant:        "unknown",
		VariantVersion: "unknown",
	}, nil
}
