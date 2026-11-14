package main

import "testing"

func TestIsLoopbackAddress(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{"127.0.0.1:1831", true},
		{"127.0.0.1:1832", true},
		{"[::1]:1831", true},
		{"0.0.0.0:1831", false},
		{"192.168.1.2:1831", false},
		{"localhost:1831", false},
		{"127.0.0.1", false},
		{"", false},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			if got := isLoopbackAddress(test.address); got != test.want {
				t.Fatalf("isLoopbackAddress(%q) = %v, want %v", test.address, got, test.want)
			}
		})
	}
}
