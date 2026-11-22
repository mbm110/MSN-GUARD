package common

import "runtime"

const Platform = runtime.GOOS

func IsAndroid() bool {
	return Platform == "android"
}

func IsIOS() bool {
	return Platform == "ios"
}

func IsMacOS() bool {
	return Platform == "darwin"
}

func IsWindows() bool {
	return Platform == "windows"
}

func IsMobile() bool {
	return IsAndroid() || IsIOS()
}
