package utils

import (
	"regexp"
	"strings"
)

func GetPemContent(pem string, template string) string {
	regex, _ := regexp.Compile(strings.Replace(strings.Replace(template, "\n", "", -1), "{content}", "(.*)", -1))
	return regex.FindStringSubmatch(strings.Replace(pem, "\n", "", -1))[1]
}

func CreatePem(content string, template string) string {
	var lines []string
	for start := 0; start < len(content); start += 64 {
		end := start + 64
		if end > len(content) {
			end = len(content)
		}
		lines = append(lines, content[start:end])
	}
	return strings.Replace(template, "{content}", strings.Join(lines[:], ""), -1)
}
