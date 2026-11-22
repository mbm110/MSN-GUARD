base_tags := "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme"
tags := if os() == "macos" { "standalone," + base_tags } else { base_tags }
lanternd := if os() == "windows" { "lanternd.exe" } else { "lanternd" }
lantern := if os() == "windows" { "lantern.exe" } else { "lantern" }
logleak := if os() == "windows" { "logleak.exe" } else { "logleak" }
version := env("VERSION", "")
# Commit and build time identify the exact build in telemetry (vcs.ref.head.revision, build.time).
commit := `git rev-parse --short=7 HEAD 2>/dev/null || echo unknown`
build_time := `date -u +%Y-%m-%dT%H:%M:%SZ`
version_flag := if version != "" { "-X 'github.com/getlantern/radiance/common.Version=" + version + "' " } else { "" }
ldflags := "-ldflags \"" + version_flag + "-X 'github.com/getlantern/radiance/common.Commit=" + commit + "' -X 'github.com/getlantern/radiance/common.BuildTime=" + build_time + "'\""

cli_tags := if os() == "macos" { "standalone" } else { "" }
cli_tags_flag := if cli_tags != "" { "-tags " + cli_tags } else { "" }

build-daemon:
    go build -tags "{{tags}}" {{ldflags}} -o bin/{{lanternd}} ./cmd/lanternd

run-daemon *args:
    go run -tags={{tags}} ./cmd/lanternd run {{args}}

build-cli:
    go build {{cli_tags_flag}} {{ldflags}} -o bin/{{lantern}} ./cmd/lantern

build: build-daemon build-cli

# install* recipes compile binaries into $GOBIN. They do NOT register
# lanternd as a system service — use `lanternd install` for that.
install-daemon:
    go install -tags "{{tags}}" {{ldflags}} ./cmd/lanternd

install-cli:
    go install {{cli_tags_flag}} {{ldflags}} ./cmd/lantern

install: install-daemon install-cli

# logleak checks every package for GOOS, the host by default; the analyzer itself is
# always built for the host.
logleak:
    GOOS= GOARCH= go build -o bin/{{logleak}} ./cmd/logleak
    GOFLAGS="${GOFLAGS:-} -tags={{tags}}" bin/{{logleak}} -test=false ./...

proto:
    go build -o build/protoc-gen-go google.golang.org/protobuf/cmd/protoc-gen-go
    protoc --go_out=. --plugin=build/protoc-gen-go --go_opt=paths=source_relative account/protos/auth.proto
    protoc --go_out=. --plugin=build/protoc-gen-go --go_opt=paths=source_relative account/protos/subscription.proto
    protoc --go_out=. --plugin=build/protoc-gen-go --go_opt=paths=source_relative issue/issue.proto

test:
    go test -v -tags "{{tags}}" ./...

# Runs on a connected device or emulator. Set RADIANCE_SMART_NETWORK_TEST=1 to
# include the tests that need real egress.
test-android *packages:
    ./scripts/android-test.sh {{packages}}
