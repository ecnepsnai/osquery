# OSQuery

[![Go Report Card](https://goreportcard.com/badge/github.com/ecnepsnai/osquery?style=flat-square)](https://goreportcard.com/report/github.com/ecnepsnai/osquery)
[![Godoc](https://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://pkg.go.dev/github.com/ecnepsnai/osquery)
[![Releases](https://img.shields.io/github/release/ecnepsnai/osquery/all.svg?style=flat-square)](https://github.com/ecnepsnai/osquery/releases)
[![LICENSE](https://img.shields.io/github/license/ecnepsnai/osquery.svg?style=flat-square)](https://github.com/ecnepsnai/osquery/blob/master/LICENSE)

Package osquery provides information about the running operating system. It can be used to derive more information
about the specific variant of operating system that is running. For example, you can use osquery to determine that
which distribution of Linux is being used, which release of FreeBSD, or which edition of Windows.

It currently only supports traditional operating systems:
Linux, macOS (darwin), FreeBSD, NetBSD, OpenBSD, Windows, and Solaris.

The OSInfo object contains details into the specific operating system that is running. For example, this is
what is returned for a Fedora Linux device:

```
osquery.OSInfo{
    Platform:       "linux",
    Kernel:         "Linux",
    KernelVersion:  "5.9.11-200.fc33.x86_64",
    Variant:        "Fedora",
    VariantVersion: "33 (Workstation Edition)",
}
```

or, for a Windows device:

```
osquery.OSInfo{
    Platform:       "windows",
    Kernel:         "NT",
    KernelVersion:  "19042",
    Variant:        "Microsoft Windows 10 Pro",
    VariantVersion: "10.0.19042",
}
```

# Usage & Examples

Examples can be found on the [documentation for the library](https://pkg.go.dev/github.com/ecnepsnai/osquery)
