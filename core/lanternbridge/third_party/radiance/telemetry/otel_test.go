package telemetry

import (
	"testing"

	semconv "github.com/getlantern/semconv"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"
)

func TestBuildResourcesIdentifiesTheBuild(t *testing.T) {
	res := attribute.NewSet(buildResources("radiance", Attributes{
		AppVersion:  "10.0.3",
		BuildCommit: "25a8d99",
		BuildTime:   "2026-10-18T22:30:00Z",
	})...)
	for key, want := range map[attribute.Key]string{
		semconv.ServiceVersionKey:     "10.0.3",
		semconv.VCSRefHeadRevisionKey: "25a8d99",
		semconv.BuildTimeKey:          "2026-10-18T22:30:00Z",
	} {
		got, ok := res.Value(key)
		assert.True(t, ok, "missing %s", key)
		assert.Equal(t, want, got.AsString(), key)
	}
}
