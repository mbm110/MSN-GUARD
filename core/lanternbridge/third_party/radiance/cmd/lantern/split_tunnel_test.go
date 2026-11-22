package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/getlantern/radiance/vpn"
)

func TestFilterTypeFromArg(t *testing.T) {
	for arg, want := range map[string]string{
		"domain":             vpn.TypeDomain,
		"domain-suffix":      vpn.TypeDomainSuffix,
		"domain-keyword":     vpn.TypeDomainKeyword,
		"domain-regex":       vpn.TypeDomainRegex,
		"process-name":       vpn.TypeProcessName,
		"process-path":       vpn.TypeProcessPath,
		"process-path-regex": vpn.TypeProcessPathRegex,
		"package-name":       vpn.TypePackageName,
		"package-name-regex": vpn.TypePackageNameRegex,
	} {
		assert.Equal(t, want, filterTypeFromArg(arg), arg)
	}
}
