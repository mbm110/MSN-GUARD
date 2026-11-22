package env

import (
	"os"
	"testing"
)

// Guards the precedence promised by the package docstring: OS env > dotenv.
func TestGet_OSEnvWinsOverDotenv(t *testing.T) {
	saved := cloneDotenv()
	defer restoreDotenv(saved)

	// Test-only key — don't mutate real RADIANCE_* vars that sibling
	// packages may read during parallel test execution.
	const testKey = "RADIANCE_UNIT_TEST_OS_WINS_KEY_DOES_NOT_EXIST"
	t.Setenv(testKey, "prod")
	Set(testKey, "staging")

	got, ok := Get(_key(testKey))
	if !ok {
		t.Fatal("Get returned ok=false")
	}
	if got != "prod" {
		t.Fatalf("OS env should win; got %q, want %q", got, "prod")
	}
}

// Other half of the contract: dotenv is still consulted when OS env is unset,
// so runtime instrumentation like SetStagingEnv keeps working.
func TestGet_DotenvFallsBackWhenOSUnset(t *testing.T) {
	saved := cloneDotenv()
	defer restoreDotenv(saved)

	const testKey = "RADIANCE_UNIT_TEST_KEY_DOES_NOT_EXIST"
	_ = os.Unsetenv(testKey)

	Set(testKey, "from-dotenv")
	got, ok := Get(_key(testKey))
	if !ok {
		t.Fatal("Get returned ok=false when only dotenv had the value")
	}
	if got != "from-dotenv" {
		t.Fatalf("dotenv should be used when OS env unset; got %q", got)
	}
}

func cloneDotenv() map[string]string {
	mu.RLock()
	defer mu.RUnlock()
	out := make(map[string]string, len(dotenv))
	for k, v := range dotenv {
		out[k] = v
	}
	return out
}

func restoreDotenv(m map[string]string) {
	mu.Lock()
	defer mu.Unlock()
	dotenv = m
}
