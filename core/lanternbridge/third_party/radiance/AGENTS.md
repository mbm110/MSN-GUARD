- Telemetry attributes: follow rules in https://github.com/getlantern/semconv/blob/main/AGENTS.md

## Comments and Documentation

**Default: no new comment.** Add a comment only when it documents a contract, invariant, concurrency rule, error condition, zero-value behavior, or surprising rationale that is not clear from the code.

- Prefer clearer names and smaller functions over explanatory comments.
- Delete or shorten verbose comments in code you touch.
- A comment that documents a real invariant, race, or rationale still fails if it includes more detail than needed to preserve that contract.
- Do not narrate code, repeat the identifier, list visible branches, mention tickets/people, or praise the implementation.
- Documentation should only document the declaration's own contract: side effects, blocking/zero-value behavior, errors, ownership, cancellation, concurrency, or surprising pre/postconditions.
- Document the caller-relevant semantics of a sentinel error, enum, status, or constant — retryability, permanence, lifecycle — as the value's own contract, phrased as what it means rather than advice: prefer "retryable only after …" over "callers should …". The consumer behavior to avoid is a separate component's policy, not the meaning of a value callers inspect.
- Comment a literal value when it encodes a non-obvious protocol, compatibility, migration, or product invariant: say why this exact value is required and what breaks if it changes, not what the assignment does. Prefer a named constant when that rationale is reusable.
- Document a contract at the narrowest declaration that depends on it — a sentinel's meaning on the sentinel or the function that returns it, a request-shape invariant at the request construction. If a comment reads as advice or sits on the wrong declaration, restate it as that declaration's contract and move it there.
- Inline comments are for local traps only. Put them above the relevant line and keep them to one short sentence when possible.
- TODOs must say what remains and why it is not done now.

## Go Doc Comments

Follow [Go doc comment conventions](https://go.dev/doc/comment), not generic prose style.

- Exported package-level declarations need doc comments; unexported declarations usually do not.
- Place doc comments immediately above the declaration, with no blank line.
- Use complete sentences. For packages, begin `Package name ...`. For commands, begin with the command name. For funcs and methods, begin with the function or method name. For types, name the type in the first sentence (`T ...`, `A T ...`, or `An T ...`).
- Keep the first sentence short; it is the synopsis shown by `go doc` and pkg.go.dev.
- Stop after one sentence unless callers need more to use the API correctly.
- Add extra paragraphs only for non-obvious contracts: concurrency safety, zero-value meaning, ownership/lifetime, blocking behavior, errors, panics, cancellation, ordering, or compatibility constraints.
- For bool-returning functions, prefer “reports whether”; do not add “or not.”
- Use `Deprecated:` on its own paragraph for deprecations.
- Prefer executable `ExampleFoo` tests over long usage prose.
- Use lists, headings, and code blocks only when the rendered public documentation genuinely needs structure.

Before finalizing Go code, re-read every added or modified comment and remove any sentence that only restates the declaration or implementation.

## Comment Verification

After any edit that adds or modifies a comment, you MUST spawn a code-reviewer subagent with the diff before declaring the task done. The subagent applies the Comments and Documentation checklist above and reports violations, including misplaced documentation where a function comment describes another declaration’s type, fields, payload shape, or consumer behavior. Fix the violations and re-spawn until the subagent reports none.

You MUST NOT skip this by self-reviewing the diff. The point of the subagent is to review without the generation bias of the Claude that wrote the comment — a self-review by the writer is a known failure mode and does not satisfy this step.

## Review focus

These bug classes have shipped here, most frequent and severe first. Check a diff against each class that applies to the files it touches. Large "mechanical" refactors deserve the same scrutiny: #370 and the sing-box 1.13.19 migration (#612) each caused several silent regressions.

1. **Server and outbound reconciliation** (`backend/radiance.go` `updateServers`, `vpn/tunnel.go` `updateOutbounds`/`removeDuplicates`). The server manager, the selector and urltest groups, and the datacap match bounds drift apart. A cached config evicted every server, a demoted manual pin stayed selected with no traffic, and one missing tag failed the whole refresh (#661, #651, #606, #405).
   - Trace each path through all three: cold start, cached config, fresh config, connected vs disconnected, manual pin, user servers.
   - Check that the selected tag is reconciled when it disappears, and that one tag's error can't abort the batch.
2. **Lifecycle ordering and locking** (`vpn/`, `backend/`). There were deadlocks when the tunnel failed mid-connect and lost updates from concurrent outbound read-modify-write. Settings were saved after unlocking, and bursts of connects stacked full sing-box bring-ups (#166, #588, #594, #490).
   - Check that shared state is mutated and persisted under one lock.
   - Check that close and teardown run after in-flight work finishes.
3. **Unbounded blocking on the start and IPC path.** iOS kills the tunnel if `startTunnel` exceeds about 7.5s, and Android's JNI start can't be cancelled. An inline rule-set fetch with no timeout hung `BoxService.Start` permanently (#594, #410).
   - Check that any network call, lock wait, or rebuild reachable from `LocalBackend.Start`, `Connect`, or an IPC handler has a deadline.
   - Check which context it uses: tunnel bring-up must not inherit a request's cancellation (`context.WithoutCancel`).
4. **sing-box integration** (`vpn/clash.go`, any box built outside the main tunnel). `HistoryStorage()` returning nil crashed every smart-routing connect once `libbox.NewServiceWithContext` was replaced by `sbox.New` (#639). The offline-test box was built with `Route == nil` and probed through the live TUN. Plain `encoding/json` on `option.Outbound` dropped typed options (#390).
   - Check for interface methods that return nil.
   - Check for services that must be registered with `service.ContextWithPtr`.
   - Check that outbound JSON goes through sing's `json` package with the box context.
5. **Route rules** (`vpn/boxoptions*.go`). One wrong rule fails every connection. The IPv6 fallback reject lacked `NoDrop`, so sing-box escalated it to a silent drop and IPv6 connections stalled instead of falling back to IPv4; a rule detour named `ai-domains` didn't match the `sr-ai-domains` outbound, and catch-all ordering changes were reverted (#627, #376, #189).
   - Check that every rule's outbound tag exists, and that the rule's order relative to the catch-all reject is right.
   - Check that a reject meant to make clients fail over at once (`rejectIPv6Rule`) sets `NoDrop`. The catch-all and high-memory rejects leave it unset, which keeps sing-box's drop-under-flood behaviour; don't add it there.
6. **Events and IPC delivery** (`events/`, `ipc/`). In-process `events.Subscribe` doesn't cross the iOS/Android process boundary. SSE subscribers missed the current status, and Emit didn't preserve per-subscriber order (#422, #447, #610).
   - Check for the snapshot-then-stream race and for per-subscriber ordering.
   - Check which process emits and which subscribes.
7. **Persisted state clobbered or moved** (`common/settings`, `account/`). A path change moved `settings.json` and users lost Pro on upgrade. A partial `/user-data` payload overwrote the whole blob with zero values (#463, #650, #511).
   - Check for whole-struct writes built from partial data, and for changes to file paths or settings keys.
   - Check that the lock is held across mutate+save.
8. **Retry loops without backoff or a terminal case.** These include a datacap SSE tight loop, `cap_exhausted` retried as transient, and a fronting crawler that exhausted Windows ephemeral ports host-wide (#394, #598, #632). Check every retry and poll path for backoff, a terminal error, and its behaviour when every dial fails instantly.
9. **Credential and PII leakage.** `pro_token`, proxy passwords, and UUIDs were logged, and a dev-only header shipped in every client request (#660, #456). Check new log and error strings that include options, URLs, tokens, or bodies, and any new header sourced from settings.
10. **Per-cycle leaks.** Observers were allocated on every connect, a closer channel was never released on timeout, and a UPnP mapping leaked (#564, #508, #608). Anything allocated in a connect, status, or poll callback needs a matching release.

Also scrutinize `cmd/lanternd/*_windows.go` and the wintun code. Two changes there were reverted, and the pipe ACL and authentication rules are security boundaries (#667).

## Contracts a diff can silently break

- **getlantern/lantern** calls radiance through gomobile/FFI. `LocalBackend.Start` runs inside iOS `startTunnel`, a hung JNI call wedges Android's connect gate, and native callers supply the data dir and (on mobile) the device ID.
- **IPC** is h2c with no version negotiation: a mixed-version system-extension swap broke every call. Clients rely on its status codes (for example, a connect while one is already running returns 200 for `ErrConnectInProgress`, not an error) and on SSE snapshot semantics.
- **`sing-box` is replaced by `getlantern/sing-box-minimal`** in `go.mod`, and bumping it changes registration behaviour. `getlantern/lantern-box` group semantics (MutableSelector failover, URL-test history) and `getlantern/common`'s smart-routing tags must match what radiance builds. Run `go mod tidy` on every bump.
- **lantern-cloud** reads request headers, honours non-selectable outbound flags, and defines the datacap SSE terminal states.
