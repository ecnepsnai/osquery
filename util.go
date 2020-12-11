package osquery

import (
	"os/exec"
	"strings"
)

func kvSplit(in string, delim string) (key string, value string) {
	components := strings.SplitN(in, delim, 2)
	key = components[0]
	value = components[1]
	return
}

func parseKeyValueList(kvlist string) map[string]string {
	params := map[string]string{}

	for _, line := range strings.Split(kvlist, lineEnding) {
		if !strings.ContainsRune(line, '=') {
			continue
		}

		key, value := kvSplit(line, "=")
		params[key] = strings.ReplaceAll(value, "\"", "")
	}

	return params
}

func parseParamsList(list string) map[string]string {
	params := map[string]string{}

	for _, line := range strings.Split(list, lineEnding) {
		if !strings.ContainsRune(line, ':') {
			continue
		}

		key, value := kvSplit(line, ":")
		params[key] = strings.TrimSpace(strings.ReplaceAll(value, "\"", ""))
	}

	return params
}

func getSystemUname(args string) (string, error) {
	out, err := exec.Command("uname", args).CombinedOutput()
	return strings.ReplaceAll(string(out), lineEnding, ""), err
}
