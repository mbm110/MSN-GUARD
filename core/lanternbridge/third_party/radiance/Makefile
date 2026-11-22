TAGS=with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
   TAGS := standalone,$(TAGS)
endif

ifeq ($(OS),Windows_NT)
   LANTERND := lanternd.exe
   LANTERN := lantern.exe
   LOGLEAK := logleak.exe
else
   LANTERND := lanternd
   LANTERN := lantern
   LOGLEAK := logleak
endif

VERSION ?=
# Commit and build time identify the exact build in telemetry (vcs.ref.head.revision, build.time).
COMMIT := $(or $(strip $(shell git rev-parse --short=7 HEAD 2>/dev/null)),unknown)
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -ldflags "$(if $(VERSION),-X 'github.com/getlantern/radiance/common.Version=$(VERSION)' )-X 'github.com/getlantern/radiance/common.Commit=$(COMMIT)' -X 'github.com/getlantern/radiance/common.BuildTime=$(BUILD_TIME)'"

.PHONY: build-daemon
build-daemon:
	go build -tags "$(TAGS)" $(LDFLAGS) -o bin/$(LANTERND) ./cmd/lanternd

.PHONY: run-daemon
run-daemon:
	go run -tags=$(TAGS) ./cmd/lanternd run \
		$(if $(data-path),--data-path=$(data-path)) \
		$(if $(log-path),--log-path=$(log-path)) \
		$(if $(log-level),--log-level=$(log-level))

.PHONY: build-cli
build-cli:
ifeq ($(UNAME_S),Darwin)
	go build -tags "standalone" $(LDFLAGS) -o bin/$(LANTERN) ./cmd/lantern
else
	go build $(LDFLAGS) -o bin/$(LANTERN) ./cmd/lantern
endif

.PHONY: build
build: build-daemon build-cli

# install* recipes compile binaries into $GOBIN. They do NOT register
# lanternd as a system service — use `lanternd install` for that.
.PHONY: install-daemon
install-daemon:
	go install -tags "$(TAGS)" $(LDFLAGS) ./cmd/lanternd

.PHONY: install-cli
install-cli:
ifeq ($(UNAME_S),Darwin)
	go install -tags "standalone" $(LDFLAGS) ./cmd/lantern
else
	go install $(LDFLAGS) ./cmd/lantern
endif

.PHONY: install
install: install-daemon install-cli

# logleak checks every package for GOOS, the host by default; the analyzer itself is
# always built for the host.
.PHONY: logleak
logleak:
	GOOS= GOARCH= go build -o bin/$(LOGLEAK) ./cmd/logleak
	GOFLAGS="$${GOFLAGS:-} -tags=$(TAGS)" bin/$(LOGLEAK) -test=false ./...

.PHONY: proto
proto:
	go build -o build/protoc-gen-go google.golang.org/protobuf/cmd/protoc-gen-go
	protoc --go_out=. --plugin=build/protoc-gen-go --go_opt=paths=source_relative account/protos/auth.proto
	protoc --go_out=. --plugin=build/protoc-gen-go --go_opt=paths=source_relative account/protos/subscription.proto
	protoc --go_out=. --plugin=build/protoc-gen-go --go_opt=paths=source_relative issue/issue.proto

.PHONY: test
test:
	go test -v -tags "$(TAGS)" ./...

# Runs on a connected device or emulator. Set RADIANCE_SMART_NETWORK_TEST=1 to
# include the tests that need real egress.
.PHONY: test-android
test-android:
	./scripts/android-test.sh
