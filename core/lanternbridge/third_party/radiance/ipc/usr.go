package ipc

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"time"
)

var executable string

func init() {
	exe, err := os.Executable()
	if err != nil {
		// Fall back to a benign always-present binary so the sudo --list probe still works.
		executable = "ls"
	} else {
		executable = exe
	}
}

type usr struct {
	uid     string
	uname   string
	isAdmin bool
}

func canSudo(usr string) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "sudo", "--other-user="+usr, "--list", executable).Run(); err != nil {
		return false
	}
	return true
}
