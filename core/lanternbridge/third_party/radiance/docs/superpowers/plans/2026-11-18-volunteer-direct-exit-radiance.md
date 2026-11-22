# Volunteer Direct Exit (radiance) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make radiance's app volunteer exit Unbounded users' traffic itself, through lantern-box's direct exit, whenever config-new turns `direct_exit` on, and make the user's app ask for direct exits.

**Architecture:**
- lantern-box v0.0.239 owns the direct exit:
  - `exit.Exit` serves Hysteria2 over each ICE path broflake hands it;
  - `node.RunExit` registers with lantern-cloud in WebRTC-only mode, and builds and rotates the exit boxes.
- radiance only wires these into its broflake widget (`unbounded/`):
  - it makes one `exit.Exit` per widget run and passes its hooks to broflake as `WebRTCOptions.Exit`;
  - it turns the exit on and off from config-new's `direct_exit` feature;
  - it runs `RunExit` while the exit is on.
- The user's side needs no code. lantern-box's `unbounded` outbound takes direct exits once config-new sends it `direct_exit`, which it does only for clients advertising `common.CapabilityUnboundedDirectExit`.

**Tech Stack:** Go; lantern-box v0.0.239 (`node`, `protocol/unbounded/exit`); broflake (getlantern/unbounded) `clientcore` at 4875108; getlantern/common at 055d272b7f4a; sing-box (getlantern/sing-box-minimal).

**Spec:** `getlantern/unbounded` `docs/superpowers/specs/2026-11-17-volunteer-direct-exit-design.md`, at `/Users/afisk/go/src/github.com/getlantern/unbounded-direct-exit/docs/superpowers/specs/2026-11-17-volunteer-direct-exit-design.md`.

**Binding contracts:**
- The lantern-box plan: `/Users/afisk/go/src/github.com/getlantern/lantern-box-direct-exit/docs/superpowers/plans/2026-11-18-volunteer-direct-exit-lantern-box.md`. See its "lantern-cloud contract" and "After this plan" sections.
- lantern-box v0.0.239's `node/exit.go` doc comments on `ExitConfig`, `ExitBox` and `RunExit`. Read them before Task 4. `git -C ../lantern-box show v0.0.239:node/exit.go`.
- lantern-cloud (getlantern/lantern-cloud#4032, merged):
  - `POST /v1/peer/register` with `{"mode":"webrtc","serve_pool":bool}`;
  - 404 for a device the peer gate doesn't admit;
  - 403 when the flag is off, for the country, or when there is nothing to serve;
  - 400 for `X-Lantern-App: lantern-box`;
  - config-new's `Features["direct_exit"]`;
  - the consumer's `direct_exit.server_name`, sent only with the capability.

## Rulings made while writing this plan

1. **radiance#781 does not block.** It was closed unmerged, and main already pins lantern-box v0.0.238, which supersedes it.
2. **The exit exists for every widget run, off until wanted.** Each run makes an `exit.Exit` on every supported platform and passes `e.Options()` to broflake whether or not the flag is on, because broflake reads `WebRTCOptions.Exit` only at `NewBroflake`. A disabled exit offers no direct exit, so sessions take today's path. This lets `direct_exit` and the country gate turn the exit on and off without restarting the widget.
3. **No direct exit on iOS.** The backend runs inside the network extension there, which can't hold a second sing-box (see `backend/peer_share.go`, `peerShareUnsupported`). The exit box is a second sing-box, so iOS volunteers keep relaying.
4. **Same country gate as the pairings-only route.** The country must be known and not censored, with the override winning (`pairingRouteCountryAllowed`, backend/peer_pairings.go). `RunExit`'s doc asks for exactly this. The backend injects the check as `unbounded.SetDirectExitAllowed`, because `unbounded` can't import `backend`. Without one, the exit is never on. On Android the check also needs the VPN connected (ruling 13).

   The backend also re-checks the exit whenever the saved country changes (`CountryCodeChanged` calls `unbounded.RecheckDirectExit`), so the exit turns on with the same config that set the country and stops at once when the country becomes unknown or censored. radiance stays on upstream quic-go (c44dd97). The exit's Hysteria2 runs on sagernet/quic-go, so lantern-box's quic-go fork replace isn't needed.
5. **Debounce off, not on.** The exit turns on with the first config that has `direct_exit`. It turns off only once `direct_exit` has stayed off for `directExitOffDelay` (15 minutes, longer than config-new's 10-minute poll). It's a timer rather than a count of configs because config-new emits no event for an unchanged config or a 304. (The task code below shows the original count, which the Codex gate replaced.) lantern-cloud can drop the flag from a single config when a pairing lookup times out. Turning off ends every running session, so one bad fetch shouldn't do that.
6. **Registration headers are config-new's.** `ExitConfig.Header` copies every header `common.NewRequestWithHeaders` sets onto the request, plus `X-Lantern-Feature-Override`, as `peer.API.do` does. That replaces lantern-box's `X-Lantern-App: lantern-box`, which lantern-cloud refuses with 400. It also sends `X-Lantern-User-Id` as `settings.GetString(UserIDKey)`, which formats the same base-10 string config-new's `ConfigRequest.UserID` carries, so the flag's stickiness agrees. `X-Lantern-Device-Id` is left as `RunExit` sets it, from `ExitConfig.DeviceID`, which is the same `settings.DeviceIDKey`.
7. **The HTTP client is `bypassHTTPClient`.** `ExitConfig.HTTPClient`'s doc requires a client that dials around the VPN's tunnel. `RunExit` wraps it in its own same-origin guard.
8. **Exit boxes are checked by hostaccess.** radiance refuses any peer box whose options grant host access (`internal/hostaccess`). Every exit box gets the same treatment:
   - `RunExit`'s context is `hostaccess.Context(box.BaseContext())`, which wraps the registries (with a platform interface, `hostaccess.ContextWithDNSTransport`, per ruling 13);
   - `ExitConfig.NewBox` is radiance's own `newExitBox`. It mirrors lantern-box's `newExitSingBox` (a clone of ctx's registry and a log factory that logs nothing) and adds `hostaccess.CheckOptions`.
9. **The Linux routing mark is set explicitly.** `RoutingMark` is `0x2024`. That is sing-tun's `DefaultAutoRedirectOutputMark`, and radiance's Linux tun keeps it: `vpn/boxoptions_default.go` sets `AutoRedirect` without an output mark. `RunExit`'s fallback (0) reads the mark from the VPN box's context, and the exit's context isn't that one. The field is ignored on other platforms.
10. **Hold-offs survive widget restarts within a process.** The manager keeps the time `OnHoldOff` last reported and passes it as `NotBefore` to the next `RunExit`, so a restart can't hammer a busy lantern-cloud. They are not persisted across process restarts.
11. **`NetworkReset` is left unset.** The exit boxes' own interface monitors handle interface changes. The macOS address-only change that radiance resets the VPN box for is a follow-up, if the end-to-end check shows exit streams stuck after a network change.
12. **`peer/validate.go` moves to `peerrules`.** lantern-box's plan moved this check into `peerrules` verbatim so both repos share one copy. radiance switches to it here.
13. **On Android, exit boxes run on the VPN service's platform interface, and only while the VPN is connected.** `RunExit` forces `auto_detect_interface` on every exit box, and without a platform interface sing-box falls back to a netlink monitor, which Android bans, so every box would fail to build. The platform's `AutoDetectInterfaceControl` (`VpnService.protect`) is also what keeps exit sockets out of Lantern's own tunnel. The app's platform takes a single default interface monitor listener, so on Android `vpn.VPNClient` wraps it once (`BoxPlatform`) in a fan-out that the tunnel's box and every exit box share. Each platform monitor start gets its own forwarder, so an update queued for a closed monitor is dropped, and `ResetNetworkForMonitor` accepts the current forwarder as the tunnel's monitor. The backend hands it to `unbounded.SetPlatformInterface`. Every other platform's tunnel runs on the platform interface itself, as before: macOS's network extension has one too, and passes the listener it holds back to `ResetNetworkForMonitor`. Its exit boxes keep sing-box's own monitor. `RunExit`'s context carries it, with the platform's local DNS (built from an empty context, as the tunnel's is, since `box.BaseContext` already holds a DNS registry), and `newExitBox` gives each box its own `libbox.NewPlatformInterfaceWrapper`, since sing-box initializes the wrapper with the box's network manager. The app starts the monitor and protect only with the VPN, so on Android the allowed check also needs a platform interface and `vpn.Connected`, and the backend re-checks the exit on every VPN status change. Every other platform's exit context is unchanged. (The task code below predates this ruling.)

## Global Constraints

- Never log IP addresses, destinations, ICE credentials, cert pins, session passwords, device IDs, user IDs, pairing IDs, tickets or route IDs. A logged error must not wrap a value that can carry any of these.
- After any `go get`, run `go mod tidy` and commit `go.mod` and `go.sum` together, in the same commit as the bump.
- radiance's `replace` directives must match lantern-box v0.0.239's `go.mod`:
  - `github.com/sagernet/sing-box` => `github.com/getlantern/sing-box-minimal v1.14.2-lantern.3`;
  - `outline-sdk/x v0.3.0-lantern.1`;
  - gvisor `sing-box-mod.1`.
- Tests: `make test` (that is, `go test -v -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme" ./...`) must pass. So must `go test -race` on the touched packages with the same tags, and `go vet` with the same tags.
- Port-mapped direct mode (samizdat), reverse direct mode and the browser web widget are unchanged.
- The exit's sessions and RunExit's registration never run on iOS, or from an unknown or censored country.
- Never use `git stash` in any form.
- Implementers and reviewers use the strongest model (opus).

## File structure

| File | Responsibility |
|---|---|
| `go.mod`, `go.sum` | Pins lantern-box v0.0.239, broflake 4875108 and common 055d272b7f4a |
| `peer/validate.go`, `peer/validate_test.go` | Removed. Call sites use `peerrules.ValidateAbuseRules` |
| `peer/peer.go`, `peer/bridgebox.go` | Call `peerrules.ValidateAbuseRules` |
| `config/fetcher.go`, `config/fetcher_test.go` | Advertise `C.CapabilityUnboundedDirectExit` |
| `unbounded/exitbox.go`, `unbounded/exitbox_test.go` | `newExitBox`: an exit box checked by hostaccess |
| `unbounded/exit.go`, `unbounded/exit_test.go` | The debounced flag, registration headers, `exitRun` (one widget run's exit and its RunExit), and `SetDirectExitAllowed` |
| `unbounded/unbounded.go` | The manager drives `exitRun` from config events, widget start and stop, and serve-pool changes |
| `unbounded/unbounded_test.go` | `resetManager` installs fake exits so existing tests stay hermetic |
| `backend/radiance.go` | Wires `unbounded.SetDirectExitAllowed` (the country gate, and on Android a connected VPN) and `unbounded.SetPlatformInterface` |
| `vpn/shared_platform.go`, `vpn/vpn.go` | `VPNClient.BoxPlatform`: on Android, the platform interface with its default interface monitor fanned out to several boxes |

---

### Task 1: Bump lantern-box, broflake and common

**Files:**
- Modify: `go.mod`, `go.sum`

**Interfaces:**
- Produces:
  - `github.com/getlantern/lantern-box/node` (`RunExit`, `ExitConfig`, `ExitBox`);
  - `github.com/getlantern/lantern-box/protocol/unbounded/exit` (`New`, `Exit`);
  - `github.com/getlantern/lantern-box/peerrules` (`ValidateAbuseRules(optionsJSON string) error`);
  - `C.CapabilityUnboundedDirectExit`;
  - `clientcore.WebRTCOptions.Exit *clientcore.ExitOptions`.

- [ ] **Step 1: Bump**

```bash
go get github.com/getlantern/lantern-box@v0.0.239 github.com/getlantern/broflake@4875108 github.com/getlantern/common@055d272b7f4a
go mod tidy
```

- [ ] **Step 2: Check the replace directives against lantern-box's**

```bash
diff <(git -C ../lantern-box show v0.0.239:go.mod | grep -A1 '=>' | grep -v '^--') <(grep -A1 '=>' go.mod | grep -v '^--')
```

Every `replace` that lantern-box v0.0.239 has must appear in radiance with the same target version, except lantern-box's `github.com/quic-go/quic-go` replace (its quic-go fork), which radiance leaves out on purpose (ruling 4). radiance may have extra replaces of its own. Fix any mismatch by editing radiance's `replace` lines, then run `go mod tidy` again.

Also check that the bump resolves broflake to 4875108 or later, not to an earlier version lantern-box requires:

```bash
go list -m github.com/getlantern/broflake github.com/getlantern/lantern-box github.com/getlantern/common
```

Expected:
- broflake's version ends in `4875108` plus the rest of its hash (or is later);
- lantern-box is `v0.0.239`;
- common ends in `055d272b7f4a`.

- [ ] **Step 3: Build and test**

```bash
make build
make test 2>&1 | tail -40
```

Expected: the build succeeds and tests pass. If a test fails, run the same test at `origin/main` in a separate worktree. A failure that happens there too is pre-existing: record it in the report and don't fix it. Fix anything the bump breaks: an API change in broflake `clientcore` or lantern-box.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "Bump lantern-box to v0.0.239, broflake to 4875108 and common for direct exits"
```

---

### Task 2: Use lantern-box's peerrules for the abuse-rule check

**Files:**
- Delete: `peer/validate.go`, `peer/validate_test.go`
- Modify: `peer/peer.go` (calls at about lines 575 and 1469), `peer/bridgebox.go` (about line 70)

**Interfaces:**
- Consumes: `peerrules.ValidateAbuseRules(optionsJSON string) error` from Task 1.

- [ ] **Step 1: Confirm the move was verbatim**

```bash
diff <(sed -n '/^func validateAbuseRules/,$p' peer/validate.go) <(git -C ../lantern-box show v0.0.239:peerrules/peerrules.go | sed -n '/^func ValidateAbuseRules(/,$p') | head -80
```

The differences should only be:
- the exported names;
- `box.BaseContext()` in place of `box.Context(context.Background())`;
- additions after the moved functions (the direct-exit checks).

If radiance's copy has a check that lantern-box's lacks, stop and report it. Don't delete it.

Also list what else in `peer/` uses the helpers being deleted:

```bash
grep -rn "validateAbuseRule\|validateStaticRejectCanaries\|isUnconditionalReject" peer/ | grep -v "peer/validate"
```

Expected: only the three `validateAbuseRules(` call sites. If tests in other files call the helpers, switch them to `peerrules.ValidateAbuseRules` with the same inputs.

- [ ] **Step 2: Switch the call sites and delete the copy**

In `peer/peer.go` and `peer/bridgebox.go`, replace `validateAbuseRules(` with `peerrules.ValidateAbuseRules(`, and add the import `"github.com/getlantern/lantern-box/peerrules"` in the getlantern import group. Then:

```bash
git rm peer/validate.go peer/validate_test.go
```

`peer/validate_test.go` moved with the code: lantern-box's `peerrules/peerrules_test.go` is that file.

- [ ] **Step 3: Test**

```bash
go test -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme" ./peer/... 2>&1 | tail -20
go vet -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme" ./peer/...
```

Expected: PASS. The tests that drive a registration with a config missing its abuse rules still fail registration, now through `peerrules`.

- [ ] **Step 4: Commit**

```bash
git add peer/
git commit -m "peer: check abuse rules with lantern-box's peerrules"
```

---

### Task 3: Advertise CapabilityUnboundedDirectExit

**Files:**
- Modify: `config/fetcher.go:82-90`
- Test: `config/fetcher_test.go:32` and the assertions near line 119

**Interfaces:**
- Consumes: `C.CapabilityUnboundedDirectExit` (`"unbounded_direct_exit"`) from Task 1.

- [ ] **Step 1: Write the failing test**

In `config/fetcher_test.go`, add the capability to `baseCapabilities`:

```go
	baseCapabilities := []string{C.CapabilityNonSelectableOutbounds, C.CapabilityUnboundedTuning, C.CapabilityOutlineSmartDialer, C.CapabilityUnboundedDirectExit}
```

And next to the `CapabilityOutlineSmartDialer` assertions:

```go
			assert.Equal(t, "unbounded_direct_exit", C.CapabilityUnboundedDirectExit,
				"the server matches this exact wire string")
			assert.Contains(t, confReq.Capabilities, C.CapabilityUnboundedDirectExit,
				"the server sends the Unbounded outbound's direct_exit only to clients advertising this")
```

- [ ] **Step 2: Run it to see it fail**

Run: `go test -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme" ./config/ -run TestFetchConfig -v 2>&1 | tail -20`
Expected: FAIL, because the capability is missing from `confReq.Capabilities`. If the test function has another name, find it with `grep -n "baseCapabilities" config/fetcher_test.go` and run that one.

- [ ] **Step 3: Implement**

In `config/fetcher.go`, extend the comment and the slice:

```go
	// Advertise OutlineSmartDialer only with lantern-box v0.0.219 or later,
	// whose outline outbound accepts the server's smart-dialer config and
	// dials a rule-set download's host.
	// Advertise UnboundedDirectExit because our lantern-box (v0.0.239 or
	// later) has the Unbounded outbound's direct_exit option, which the
	// server withholds from older clients: sing-box rejects unknown fields.
	capabilities := []string{C.CapabilityNonSelectableOutbounds, C.CapabilityUnboundedTuning, C.CapabilityOutlineSmartDialer, C.CapabilityUnboundedDirectExit}
```

- [ ] **Step 4: Run it to see it pass**

Run: `go test -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme" ./config/... 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add config/fetcher.go config/fetcher_test.go
git commit -m "config: advertise unbounded_direct_exit"
```

---

### Task 4: An exit box checked by hostaccess

**Files:**
- Create: `unbounded/exitbox.go`
- Test: `unbounded/exitbox_test.go`

**Interfaces:**
- Consumes:
  - `node.ExitBox` (`Router() adapter.ConnectionRouterEx`, `ResetNetwork()`, `Close() error`);
  - `hostaccess.Context(ctx) context.Context`, `hostaccess.CheckOptions(option.Options) error`, `hostaccess.ErrDenied`.
- Produces: `newExitBox(ctx context.Context, options string) (node.ExitBox, error)`, for `ExitConfig.NewBox` in Task 5.

- [ ] **Step 1: Write the failing tests**

`unbounded/exitbox_test.go`:

```go
package unbounded

import (
	"context"
	"testing"

	box "github.com/getlantern/lantern-box"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/internal/hostaccess"
)

func exitBoxContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(box.BaseContext())
	t.Cleanup(cancel)
	return hostaccess.Context(ctx)
}

func TestNewExitBoxStartsAMinimalBox(t *testing.T) {
	b, err := newExitBox(exitBoxContext(t), `{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`)
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	require.NotNil(t, b.Router())
	// RunExit checks rule sets through the router, so it must keep sing-box's lookup.
	_, ok := b.Router().(interface {
		RuleSet(tag string) (adapter.RuleSet, bool)
	})
	assert.True(t, ok, "the router must look up rule sets by tag")
	b.ResetNetwork()
}

func TestNewExitBoxRefusesHostAccess(t *testing.T) {
	_, err := newExitBox(exitBoxContext(t), `{"outbounds":[{"type":"tor","tag":"tor"},{"type":"direct","tag":"direct"}]}`)
	require.Error(t, err)
	assert.ErrorIs(t, err, hostaccess.ErrDenied)
}

func TestNewExitBoxRejectsBadJSON(t *testing.T) {
	_, err := newExitBox(exitBoxContext(t), `{`)
	require.Error(t, err)
}
```

Add `"github.com/sagernet/sing-box/adapter"` to the imports. Check that the method set matches what `RunExit` asserts: `git -C ../lantern-box show v0.0.239:internal/directexit/directexit.go | grep -n "RuleSetLookup" -A4`. If `RuleSetLookup` has a different method shape, assert that shape instead. If `tor` isn't in this build's registry, so that decoding fails before `CheckOptions`, use another type from `hostaccess`'s `deniedTypes` that is registered (`openconnect`, say). Either way the error must wrap `ErrDenied`.

- [ ] **Step 2: Run them to see them fail**

Run: `go test -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme" ./unbounded/ -run TestNewExitBox -v 2>&1 | tail -20`
Expected: FAIL to compile with `undefined: newExitBox`.

- [ ] **Step 3: Implement**

`unbounded/exitbox.go`:

```go
package unbounded

import (
	"context"
	"fmt"

	"github.com/getlantern/lantern-box/node"
	sbox "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	sblog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/getlantern/radiance/internal/hostaccess"
)

// newExitBox builds and starts a direct exit box, as lantern-box's own does: sing-box in a
// clone of ctx's service registry, so it keeps ctx's registries but registers its managers
// only in its own, with a log factory that logs nothing, since the box carries strangers'
// destinations. It also refuses options that grant host access, as radiance does for every
// peer box. ctx must come from hostaccess.Context.
func newExitBox(ctx context.Context, options string) (node.ExitBox, error) {
	ctx = service.ExtendContext(ctx)
	service.MustRegister[sblog.Factory](ctx, sblog.NewNOPFactory())
	opts, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(options))
	if err != nil {
		return nil, fmt.Errorf("decode exit box options: %w", err)
	}
	if err := hostaccess.CheckOptions(opts); err != nil {
		return nil, fmt.Errorf("check exit box options: %w", err)
	}
	b, err := sbox.New(sbox.Options{Context: ctx, Options: opts})
	if err != nil {
		return nil, fmt.Errorf("build exit box: %w", err)
	}
	if err := b.Start(); err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("start exit box: %w", err)
	}
	return exitBox{b: b, ctx: ctx}, nil
}

type exitBox struct {
	b   *sbox.Box
	ctx context.Context
}

func (x exitBox) Router() adapter.ConnectionRouterEx { return x.b.Router() }
func (x exitBox) ResetNetwork()                      { x.b.Network().ResetNetwork(x.ctx) }
func (x exitBox) Close() error                       { return x.b.Close() }
```

Match the import paths for `json` and `service` that `peer/peer.go` already uses (`grep -n "sing/common/json\|sing/service" peer/peer.go`). Put the imports in radiance's grouping: standard library, third party, then `github.com/getlantern/radiance/...`.

- [ ] **Step 4: Run them to see them pass**

Run: `go test -race -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme" ./unbounded/ -run TestNewExitBox -v 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add unbounded/exitbox.go unbounded/exitbox_test.go
git commit -m "unbounded: build direct exit boxes through hostaccess"
```

---

### Task 5: Run the direct exit with the widget

**Files:**
- Create: `unbounded/exit.go`
- Test: `unbounded/exit_test.go`
- Modify:
  - `unbounded/unbounded.go`: manager fields (around lines 157-249), `syncRooms` (524-550), `applyConfig` (684-719), and the worker in `startLocked` (877-1035);
  - `unbounded/unbounded_test.go`: `resetManager` (77-110).

**Interfaces:**
- Consumes:
  - `newExitBox` from Task 4;
  - `node.RunExit(ctx, node.ExitConfig) error`;
  - `exit.New(ctx, logger.ContextLogger) (*exit.Exit, error)`;
  - `(*exit.Exit).Options() *clientcore.ExitOptions`, `SetEnabled(bool)`, `Close()`.
- Produces:
  - `unbounded.SetDirectExitAllowed(allowed func() bool)`, for Task 6;
  - `const directExitFeature = "direct_exit"`.

Read lantern-box v0.0.239's `node/exit.go`, lines 28-93 and 153-180, first. `RunExit` sets only the exit's routers. The embedder owns `SetEnabled`, and cancels `RunExit`'s context while the exit is off.

- [ ] **Step 1: Make the existing tests hermetic**

In `unbounded/unbounded_test.go`, have `resetManager` install fakes for the new hooks. In real runs the exit generates a certificate, and `RunExit` would call lantern-cloud:

```go
	prevNewExit, prevRunExit, prevUnsupported := newDirectExit, runDirectExit, directExitUnsupported
	newDirectExit = func(context.Context) (directExit, error) { return &fakeExit{}, nil }
	runDirectExit = func(ctx context.Context, _ directExit, _ node.ExitConfig) error {
		<-ctx.Done()
		return nil
	}
	directExitUnsupported = func() bool { return false }
```

Put that next to `prevManager := manager`, and restore all three in the `t.Cleanup` alongside `newWidget = prevWidget`. Add `"github.com/getlantern/lantern-box/node"` to the test imports. `fakeExit` is defined in Step 2.

- [ ] **Step 2: Write the failing tests**

`unbounded/exit_test.go`:

```go
package unbounded

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getlantern/broflake/clientcore"
	C "github.com/getlantern/common"
	"github.com/getlantern/lantern-box/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rcommon "github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/config"
)

// fakeExit records what the manager does to the exit.
type fakeExit struct {
	mu      sync.Mutex
	enabled []bool
	closed  bool
}

func (f *fakeExit) Options() *clientcore.ExitOptions { return &clientcore.ExitOptions{} }
func (f *fakeExit) SetEnabled(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = append(f.enabled, on)
}
func (f *fakeExit) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
}
func (f *fakeExit) state() (last bool, closed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n := len(f.enabled); n > 0 {
		last = f.enabled[n-1]
	}
	return last, f.closed
}

// exitHarness installs a fake exit and a RunExit that records each run until its context ends.
type exitHarness struct {
	exit    *fakeExit
	runs    atomic.Int32
	running atomic.Int32
	mu      sync.Mutex
	cfgs    []node.ExitConfig
	rtcExit atomic.Bool
}

func newExitHarness(t *testing.T) *exitHarness {
	t.Helper()
	h := &exitHarness{exit: &fakeExit{}}
	resetManager(t, func(_ *clientcore.BroflakeOptions, rtcOpt *clientcore.WebRTCOptions, _ *clientcore.EgressOptions) (widget, error) {
		h.rtcExit.Store(rtcOpt.Exit != nil)
		return &fakeWidget{}, nil
	})
	newDirectExit = func(context.Context) (directExit, error) { return h.exit, nil }
	runDirectExit = func(ctx context.Context, _ directExit, cfg node.ExitConfig) error {
		h.mu.Lock()
		h.cfgs = append(h.cfgs, cfg)
		h.mu.Unlock()
		h.runs.Add(1)
		h.running.Add(1)
		defer h.running.Add(-1)
		<-ctx.Done()
		return nil
	}
	return h
}

func (h *exitHarness) lastCfg() node.ExitConfig {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cfgs[len(h.cfgs)-1]
}

func directExitConfig(on bool) config.Config {
	return config.Config{
		Unbounded: testCfg(),
		Features:  map[string]bool{C.UNBOUNDED: true, directExitFeature: on},
	}
}

func eventually(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	require.Eventually(t, cond, 2*time.Second, 5*time.Millisecond, msg)
}

func TestExitFlagTurnsOnAtOnceAndOffAfterTwoMisses(t *testing.T) {
	var f exitFlag
	assert.False(t, f.update(false))
	assert.True(t, f.update(true))
	assert.True(t, f.update(false), "one config without direct_exit must not stop the exit")
	assert.False(t, f.update(false), "the second in a row does")
	assert.True(t, f.update(true))
	assert.True(t, f.update(false))
	assert.True(t, f.update(true), "a config with the flag resets the count")
	assert.True(t, f.update(false))
}

func TestDirectExitRunsWhileTheFlagIsOn(t *testing.T) {
	h := newExitHarness(t)
	SetDirectExitAllowed(func() bool { return true })
	require.NoError(t, settings.Set(settings.UnboundedKey, true))

	applyConfig(directExitConfig(true))
	eventually(t, func() bool { return h.running.Load() == 1 }, "RunExit should start with the flag on")
	assert.True(t, h.rtcExit.Load(), "broflake must get the exit's options")
	last, _ := h.exit.state()
	assert.True(t, last, "the exit must be enabled")

	cfg := h.lastCfg()
	assert.Equal(t, rcommon.GetBaseURL(), cfg.APIURL)
	assert.Equal(t, settings.GetString(settings.DeviceIDKey), cfg.DeviceID)
	assert.NotNil(t, cfg.HTTPClient)
	assert.NotNil(t, cfg.Header)
	assert.NotNil(t, cfg.NewBox)
	assert.NotNil(t, cfg.ServePool)
	assert.NotNil(t, cfg.Reregister)
	assert.NotNil(t, cfg.OnHoldOff)
	assert.Equal(t, uint32(0x2024), cfg.RoutingMark)

	applyConfig(directExitConfig(false))
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, int32(1), h.running.Load(), "one config without the flag keeps the exit")

	applyConfig(directExitConfig(false))
	eventually(t, func() bool { return h.running.Load() == 0 }, "two in a row stop RunExit")
	last, _ = h.exit.state()
	assert.False(t, last, "and disable the exit")
	assert.Equal(t, int32(1), h.runs.Load(), "turning the flag off must not restart the widget")
}

func TestDirectExitNeedsAnAllowedCountry(t *testing.T) {
	h := newExitHarness(t)
	SetDirectExitAllowed(func() bool { return false })
	require.NoError(t, settings.Set(settings.UnboundedKey, true))

	applyConfig(directExitConfig(true))
	waitForRunning(t, manager, true, 2*time.Second)
	eventually(t, h.rtcExit.Load, "the exit is offered to broflake, off")
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, int32(0), h.runs.Load(), "no registration from a disallowed country")

	SetDirectExitAllowed(func() bool { return true })
	eventually(t, func() bool { return h.running.Load() == 1 }, "allowing the country starts RunExit")
}

func TestDirectExitNeverOnWithoutAnAllowedCheck(t *testing.T) {
	h := newExitHarness(t)
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	applyConfig(directExitConfig(true))
	waitForRunning(t, manager, true, 2*time.Second)
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, int32(0), h.runs.Load())
}

func TestDirectExitClosesWithTheWidget(t *testing.T) {
	h := newExitHarness(t)
	SetDirectExitAllowed(func() bool { return true })
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	applyConfig(directExitConfig(true))
	eventually(t, func() bool { return h.running.Load() == 1 }, "RunExit should start")

	require.NoError(t, Stop(context.Background()))
	assert.Equal(t, int32(0), h.running.Load(), "Stop must end RunExit before it returns")
	_, closed := h.exit.state()
	assert.True(t, closed, "Stop must close the exit")
}

func TestNoDirectExitOnUnsupportedPlatforms(t *testing.T) {
	h := newExitHarness(t)
	directExitUnsupported = func() bool { return true }
	var made atomic.Bool
	newDirectExit = func(context.Context) (directExit, error) { made.Store(true); return h.exit, nil }
	SetDirectExitAllowed(func() bool { return true })
	require.NoError(t, settings.Set(settings.UnboundedKey, true))

	applyConfig(directExitConfig(true))
	waitForRunning(t, manager, true, 2*time.Second)
	time.Sleep(20 * time.Millisecond)
	assert.False(t, made.Load())
	assert.False(t, h.rtcExit.Load())
	assert.Equal(t, int32(0), h.runs.Load())
}

func TestWidgetRunsWhenTheExitCantBeMade(t *testing.T) {
	h := newExitHarness(t)
	newDirectExit = func(context.Context) (directExit, error) { return nil, errors.New("no quic") }
	SetDirectExitAllowed(func() bool { return true })
	require.NoError(t, settings.Set(settings.UnboundedKey, true))

	applyConfig(directExitConfig(true))
	waitForRunning(t, manager, true, 2*time.Second)
	time.Sleep(20 * time.Millisecond)
	assert.False(t, h.rtcExit.Load(), "no exit, so broflake relays as before")
	assert.Equal(t, int32(0), h.runs.Load())
}

func TestExitHoldOffOutlivesAWidgetRun(t *testing.T) {
	h := newExitHarness(t)
	until := time.Now().Add(time.Hour).Truncate(time.Second)
	runDirectExit = func(ctx context.Context, _ directExit, cfg node.ExitConfig) error {
		h.mu.Lock()
		h.cfgs = append(h.cfgs, cfg)
		h.mu.Unlock()
		h.runs.Add(1)
		cfg.OnHoldOff(until)
		<-ctx.Done()
		return nil
	}
	SetDirectExitAllowed(func() bool { return true })
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	applyConfig(directExitConfig(true))
	eventually(t, func() bool { return h.runs.Load() == 1 }, "first run")

	manager.stop()
	manager.start()
	eventually(t, func() bool { return h.runs.Load() == 2 }, "second run")
	assert.True(t, h.lastCfg().NotBefore.Equal(until), "the next run must wait out the hold-off")
}

func TestServePoolChangeReregisters(t *testing.T) {
	h := newExitHarness(t)
	prevInterval := roomSyncInterval
	roomSyncInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		roomSyncInterval = prevInterval
		_ = settings.Set(settings.PeerServePoolKey, true)
	})
	require.NoError(t, settings.Set(settings.PeerServePoolKey, false))
	SetDirectExitAllowed(func() bool { return true })
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	applyConfig(directExitConfig(true))
	eventually(t, func() bool { return h.running.Load() == 1 }, "RunExit should start")
	rereg := h.lastCfg().Reregister

	require.NoError(t, settings.Set(settings.PeerServePoolKey, true))
	select {
	case <-rereg:
	case <-time.After(2 * time.Second):
		t.Fatal("turning helping others on must re-register the exit")
	}
}

func TestExitHeadersAreConfigNews(t *testing.T) {
	require.NoError(t, settings.Set(settings.UserIDKey, int64(1234567890)))
	h := http.Header{}
	h.Set("X-Lantern-App", "lantern-box")
	h.Set(rcommon.DeviceIDHeader, "set-by-runexit")
	h.Set("Content-Type", "application/json")

	exitHeaders(h)

	assert.Equal(t, rcommon.Name, h.Get(rcommon.AppNameHeader), "lantern-cloud refuses lantern-box's app name in webrtc mode")
	assert.Equal(t, "1234567890", h.Get(rcommon.UserIDHeader), "the same user ID config-new gets, for the flag's stickiness")
	assert.Equal(t, rcommon.Platform, h.Get(rcommon.PlatformHeader))
	assert.Equal(t, "set-by-runexit", h.Get(rcommon.DeviceIDHeader), "RunExit's device ID stays")
	assert.Equal(t, "application/json", h.Get("Content-Type"))
}
```

Add `"errors"` to the imports. If `Stop` disarms the manager in a way that breaks later steps of the same test, that's expected: each test calls `resetManager` through `newExitHarness`. `SetDirectExitAllowed` writes `manager.exitAllowed`, and `resetManager` replaces `manager`, so no test's check leaks into another. Check what `settings.UserIDKey` stores: `config/fetcher_test.go` sets it with a bare integer. If `settings.Set` normalizes integers differently, match that test.

- [ ] **Step 3: Run them to see them fail**

Run: `go test -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme" ./unbounded/ 2>&1 | tail -20`
Expected: FAIL to compile, with undefined `directExit`, `newDirectExit`, `runDirectExit`, `directExitUnsupported`, `exitFlag`, `directExitFeature`, `SetDirectExitAllowed` and `exitHeaders`.

- [ ] **Step 4: Write `unbounded/exit.go`**

```go
package unbounded

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/getlantern/broflake/clientcore"
	box "github.com/getlantern/lantern-box"
	lblog "github.com/getlantern/lantern-box/log"
	"github.com/getlantern/lantern-box/node"
	"github.com/getlantern/lantern-box/protocol/unbounded/exit"

	rcommon "github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/internal/hostaccess"
	rlog "github.com/getlantern/radiance/log"
)

// directExitFeature is config-new's feature for a volunteer that exits users' traffic itself
// rather than relaying it to the egress server.
const directExitFeature = "direct_exit"

// directExitOffAfter is how many configs in a row must leave direct_exit off before a running
// exit stops. lantern-cloud can drop the flag from one config when a lookup behind it fails, and
// stopping ends every session the exit serves.
const directExitOffAfter = 2

// autoRedirectOutputMark is sing-tun's DefaultAutoRedirectOutputMark, which radiance's Linux tun
// keeps (it sets auto_redirect with no output mark). The exit box's sockets carry it, so the
// tun's nftables rules don't redirect exit traffic into the volunteer's own tunnel.
const autoRedirectOutputMark = 0x2024

// directExitUnsupported: on iOS the backend runs in the network extension, which can't hold the
// exit's second sing-box, as for peer sharing (backend/peer_share.go).
var directExitUnsupported = rcommon.IsIOS

// directExit is the part of exit.Exit the manager drives.
type directExit interface {
	Options() *clientcore.ExitOptions
	SetEnabled(on bool)
	Close()
}

// newDirectExit makes the widget's exit. It fails without with_quic.
var newDirectExit = func(ctx context.Context) (directExit, error) {
	e, err := exit.New(ctx, lblog.NewFactory(rlog.RedactConnectionInfo(slog.Default().Handler())).NewLogger("unbounded-exit"))
	if err != nil {
		return nil, err
	}
	return e, nil
}

// runDirectExit is node.RunExit for the exit newDirectExit made.
var runDirectExit = func(ctx context.Context, e directExit, cfg node.ExitConfig) error {
	cfg.Exit = e.(*exit.Exit)
	return node.RunExit(ctx, cfg)
}

// exitFlag is config-new's direct_exit, which turns on at once and off only after
// directExitOffAfter configs in a row without it.
type exitFlag struct {
	on     bool
	misses int
}

func (f *exitFlag) update(on bool) bool {
	if on {
		f.on, f.misses = true, 0
		return true
	}
	f.misses++
	if f.misses >= directExitOffAfter {
		f.on = false
	}
	return f.on
}

// exitHeaders gives RunExit's registrations the headers config-new's requests carry, as the peer
// API's do. That replaces lantern-box's X-Lantern-App, which lantern-cloud refuses in webrtc
// mode, and sends the user ID config-new gets, so the direct_exit flag's percentage agrees.
// RunExit's device ID and content type stay.
func exitHeaders(h http.Header) {
	r, err := rcommon.NewRequestWithHeaders(context.Background(), http.MethodPost, "http://exit.invalid", nil)
	if err != nil {
		return
	}
	for k, v := range r.Header {
		if k == http.CanonicalHeaderKey(rcommon.DeviceIDHeader) {
			continue
		}
		h[k] = v
	}
	if val := settings.GetString(settings.FeatureOverridesKey); val != "" {
		h.Set("X-Lantern-Feature-Override", val)
	}
}

// SetDirectExitAllowed sets the check for whether this device may exit users' traffic at all:
// its country is known and not censored. nil, the default, never allows it.
func SetDirectExitAllowed(allowed func() bool) {
	manager.mu.Lock()
	manager.exitAllowed = allowed
	run := manager.exitRun
	manager.mu.Unlock()
	if run != nil {
		run.sync()
	}
}

// exitWantedLocked reports whether the exit should be on. Caller must hold m.mu.
func (m *unboundedManager) exitWantedLocked() bool {
	return m.exitFlag.on && m.exitAllowed != nil && m.exitAllowed()
}

func (m *unboundedManager) exitWanted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.exitWantedLocked()
}

func (m *unboundedManager) setExitHoldOff(until time.Time) {
	m.mu.Lock()
	m.exitNotBefore = until
	m.mu.Unlock()
}

func (m *unboundedManager) exitHoldOff() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.exitNotBefore
}

// reregisterExit asks the running exit, if any, to register again, as the serve-pool setting
// changed.
func (m *unboundedManager) reregisterExit() {
	m.mu.Lock()
	run := m.exitRun
	m.mu.Unlock()
	if run != nil {
		run.reregisterNow()
	}
}

// startExit makes a widget run's exit, or returns nil where there is none: on iOS, or where
// the exit can't be made. It starts off.
func (m *unboundedManager) startExit() *exitRun {
	if directExitUnsupported() {
		return nil
	}
	e, err := newDirectExit(box.BaseContext())
	if err != nil {
		slog.Warn("Unbounded: no direct exit", "error", err)
		return nil
	}
	return newExitRun(e, node.ExitConfig{
		APIURL:      rcommon.GetBaseURL(),
		DeviceID:    settings.GetString(settings.DeviceIDKey),
		HTTPClient:  bypassHTTPClient,
		Header:      exitHeaders,
		Version:     rcommon.GetVersion(),
		NewBox:      newExitBox,
		OnHoldOff:   m.setExitHoldOff,
		RoutingMark: autoRedirectOutputMark,
		ServePool:   servePool,
	}, m.exitWanted, m.exitHoldOff)
}

// exitRun is one widget run's direct exit: the exit broflake offers sessions through, and
// RunExit keeping its registration and boxes current while the exit is on.
type exitRun struct {
	e          directExit
	cfg        node.ExitConfig
	wanted     func() bool
	notBefore  func() time.Time
	reregister chan struct{}

	mu     sync.Mutex
	closed bool
	cancel context.CancelFunc
	done   chan struct{}
}

func newExitRun(e directExit, cfg node.ExitConfig, wanted func() bool, notBefore func() time.Time) *exitRun {
	r := &exitRun{e: e, cfg: cfg, wanted: wanted, notBefore: notBefore, reregister: make(chan struct{}, 1)}
	r.cfg.Reregister = r.reregister
	return r
}

// sync turns the exit on or off to match wanted: on, it enables the exit and starts RunExit;
// off, it disables the exit, ending its sessions, and waits for RunExit to close its boxes.
func (r *exitRun) sync() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if !r.wanted() {
		r.e.SetEnabled(false)
		r.stopLocked()
		return
	}
	r.e.SetEnabled(true)
	if r.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(hostaccess.Context(box.BaseContext()))
	done := make(chan struct{})
	r.cancel, r.done = cancel, done
	cfg := r.cfg
	cfg.NotBefore = r.notBefore()
	go func() {
		defer close(done)
		// RunExit logs and retries lantern-cloud's and the boxes' failures itself. It returns an
		// error only for a config it can't run with, which names no address or ID.
		if err := runDirectExit(ctx, r.e, cfg); err != nil && ctx.Err() == nil {
			slog.Error("Unbounded: direct exit can't run", "error", err)
		}
	}()
}

func (r *exitRun) stopLocked() {
	if r.cancel == nil {
		return
	}
	r.cancel()
	<-r.done
	r.cancel, r.done = nil, nil
}

// reregisterNow asks RunExit to register again at once, without blocking.
func (r *exitRun) reregisterNow() {
	select {
	case r.reregister <- struct{}{}:
	default:
	}
}

// close stops RunExit and closes the exit for good. Call it once the widget has stopped, so
// broflake hands the exit no more paths.
func (r *exitRun) close() {
	r.mu.Lock()
	r.closed = true
	r.e.SetEnabled(false)
	r.stopLocked()
	r.mu.Unlock()
	r.e.Close()
}
```

Check these signatures against the code before relying on them, and adjust the calls (not the behavior) if they differ:
- `lblog.NewFactory`: `git -C ../lantern-box show v0.0.239:log/log.go | sed -n 40,110p`.
- `rcommon.IsIOS` is a `func() bool` in `common/platform.go`.
- `settings.FeatureOverridesKey`, which `peer/api.go` uses.
- The `Logger` type `exit.New` takes.

Lock order: `exitRun.mu`, then `unboundedManager.mu` (`sync` calls `wanted`, which takes `m.mu`). Never call into an `exitRun` while holding `m.mu`.

- [ ] **Step 5: Wire the manager**

In `unbounded/unbounded.go`:

1. Add these fields to `unboundedManager`, after `runHook`:

```go
	// exitFlag is config-new's direct_exit, debounced.
	exitFlag exitFlag
	// exitAllowed reports whether this device may exit users' traffic at
	// all (SetDirectExitAllowed). nil: never.
	exitAllowed func() bool
	// exitRun is the running widget's direct exit. nil with none.
	exitRun *exitRun
	// exitNotBefore is the hold-off lantern-cloud last asked the exit for,
	// kept across widget runs so a restart can't cut it short.
	exitNotBefore time.Time
```

2. In `applyConfig`, under `manager.mu` and right after `manager.lastFeatureOn = ...`:

```go
	manager.exitFlag.update(cfg.Features[directExitFeature])
	run := manager.exitRun
```

   After `manager.mu.Unlock()` and before the `switch`:

```go
	// The exit turns on and off without restarting the widget.
	if run != nil {
		run.sync()
	}
```

3. In the worker in `startLocked`, right after `served := applyRooms(rtcOpt, tickets)`:

```go
		// The exit is offered to broflake off, and turned on and off later
		// with direct_exit: broflake reads WebRTCOptions.Exit only here.
		exitRun := m.startExit()
		if exitRun != nil {
			rtcOpt.Exit = exitRun.e.Options()
		}
```

   In the `newWidget` error branch, before `cancel()`:

```go
			if exitRun != nil {
				exitRun.close()
			}
```

   Replace the block that sets `m.running` after a successful `newWidget` with:

```go
		m.mu.Lock()
		m.running = ctx.Err() == nil
		m.exitRun = exitRun
		m.mu.Unlock()
		if exitRun != nil {
			exitRun.sync()
		}
```

   After `ui.Stop()` and `<-syncDone`, and before the final `m.mu.Lock()`:

```go
		if exitRun != nil {
			exitRun.close()
		}
```

   In the final block that clears `m.cancel`, `m.done` and `m.runningCfg`, add `m.exitRun = nil`.

4. In `syncRooms`, right after `rtcOpt.SetServePool(pool)`:

```go
		if pool != prevPool {
			// The exit's next registration says whether it serves the pool.
			m.reregisterExit()
		}
```

- [ ] **Step 6: Run the tests**

```bash
go test -race -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme" ./unbounded/ 2>&1 | tail -30
go vet -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme" ./unbounded/
go test ./unbounded/ 2>&1 | tail -5
```

Expected: all PASS, including every existing test, with no race reports. The last command runs without `with_quic`, where `exit.New` fails; it must still build and pass.

Also run `-count=5` on the new tests to catch flakes:

```bash
go test -race -count=5 -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme" ./unbounded/ -run 'Exit|ServePool' 2>&1 | tail -5
```

- [ ] **Step 7: Commit**

```bash
git add unbounded/exit.go unbounded/exit_test.go unbounded/unbounded.go unbounded/unbounded_test.go
git commit -m "unbounded: exit users' traffic directly when config-new turns direct_exit on"
```

---

### Task 6: Gate the exit on the device's country

**Files:**
- Modify: `backend/radiance.go` (the unbounded wiring block, around lines 460-477)
- Test: `backend/peer_pairings_test.go`, or the existing test that covers `pairingRouteCountryAllowed`

**Interfaces:**
- Consumes: `unbounded.SetDirectExitAllowed(func() bool)` from Task 5, and `pairingRouteCountryAllowed() bool` (backend/peer_pairings.go:59).

- [ ] **Step 1: Wire it**

In `backend/radiance.go`, before `unbounded.InitSubscription(cachedCfg)`:

```go
	// The widget exits users' traffic itself only from a country that is
	// known and not censored, as for the pairings-only route.
	unbounded.SetDirectExitAllowed(pairingRouteCountryAllowed)
```

- [ ] **Step 2: Test the gate's inputs**

`pairingRouteCountryAllowed` already has tests: `grep -n "pairingRouteCountryAllowed" backend/*_test.go`. If none covers these cases, add a table test to `backend/peer_pairings_test.go`:
- no country at all → false;
- a censored country (take one key from `censoredCountries`) → false;
- `"us"` (lowercase, trimmed) → true;
- the env override set to a censored country while settings say `"US"` → false.

Use the setters the existing tests use for `env.Country` and `settings.CountryCodeKey`, and restore both in `t.Cleanup`.

- [ ] **Step 3: Run the backend tests**

```bash
go test -race -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme" ./backend/ 2>&1 | tail -20
```

Expected: PASS.

- [ ] **Step 4: Run the whole suite**

```bash
make test 2>&1 | grep -E "^(ok|FAIL|---)" | tail -60
go vet -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme" ./...
```

Expected: everything that passed at `origin/main` passes. Record pre-existing failures, comparing against an `origin/main` worktree.

- [ ] **Step 5: Commit**

```bash
git add backend/
git commit -m "backend: allow direct exits only from known, uncensored countries"
```

---

### Task 7: End-to-end check on staging

This needs two devices, lantern-cloud's staging flags, and the user's go-ahead: Unleash changes are the user's. Don't change flags yourself. Ask the user to turn on `unbounded`, `direct_exit` and `direct_exit_consumer` for the test devices on staging, or to give you a `RADIANCE_FEATURE_OVERRIDES` value that does. Report every result as pass or fail. Never record addresses, IDs or destinations in notes, the PR or logs you paste.

- [ ] **Step 1: Volunteer registers with the VPN on**

On a desktop volunteer (macOS first, then Windows and Linux):
1. Build with `make build`.
2. Turn on the VPN and Unbounded.
3. Watch the log for the exit's registration.

Pass:
- there is no `direct exit: register` warning after the first rotation;
- the exit's log lines name no address.

Fail on a 400, which means `X-Lantern-App` wasn't overridden. A 403 means the flag or the country is wrong; check those before blaming the code.

- [ ] **Step 2: Exit traffic doesn't use the volunteer's tunnel**

1. With the volunteer's VPN on, make a user's app (a second device with `direct_exit_consumer`) take this volunteer.
2. On the user's device, fetch an IP-echo page through Lantern.

Pass: the page shows the volunteer's residential network, not the volunteer's own Lantern server. Compare only whether the two match; don't copy either address anywhere.

Repeat on Linux, where the routing mark matters, and on Android.

- [ ] **Step 3: Pool and personal stay apart**

1. Pair the user with the volunteer as a helper.
2. Turn the volunteer's "help others too" off.

Pass:
- the paired user exits through the volunteer;
- a stranger's app gets no direct exit from it (its session relays or it picks another volunteer);
- turning "help others too" back on makes the exit register again within a sync interval (30s), without restarting the widget.

- [ ] **Step 4: Flag off**

Ask the user to turn `direct_exit` off for the volunteer.

Pass: once `directExitOffDelay` (15 minutes) has passed since the first config without the flag, with no further config event needed, new sessions from the user take the relayed path, and the volunteer's exit log shows no further registrations.

- [ ] **Step 5: iOS**

On an iOS volunteer, turn on Unbounded.

Pass: no exit registration ever, and sessions relay as before.

- [ ] **Step 6: Record**

Write the results as a pass/fail table in the PR body's Testing section.

---

## After this plan

- Open the PR through `/create-pr` with `--copilot-budget 3`.
- **lantern** then bumps radiance (and lantern-box to v0.0.239), with `go mod tidy`.
- Lamplighter nodes need lantern-box v0.0.239 or later to serve direct exits.
- Flag rollout belongs to the user:
  - target `direct_exit` and `direct_exit_consumer` by country only;
  - keep the unbounded strategy to country, user and percentage.
- Follow-ups:
  - `NetworkReset` for the exit boxes, if Step 2 shows streams stuck after a network change on macOS or iOS;
  - persisting the hold-off across process restarts.
