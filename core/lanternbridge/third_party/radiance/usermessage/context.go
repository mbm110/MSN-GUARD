package usermessage

import (
	"strings"

	"golang.org/x/text/language"
)

// NormalizeLocale returns a canonical BCP 47 tag with a safe fallback.
func NormalizeLocale(locale string) string {
	tag, err := language.Parse(strings.TrimSpace(locale))
	if err != nil || tag == language.Und {
		return "en-US"
	}
	return tag.String()
}

// NormalizePlatform maps runtime platform names to the public targeting vocabulary.
func NormalizePlatform(platform string) string {
	platform = strings.ToLower(strings.TrimSpace(platform))
	if platform == "darwin" {
		return "macos"
	}
	return platform
}
