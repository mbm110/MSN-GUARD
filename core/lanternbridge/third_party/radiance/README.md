[![Go](https://github.com/getlantern/radiance/actions/workflows/go.yml/badge.svg)](https://github.com/getlantern/radiance/actions/workflows/go.yml)

# Radiance
Radiance is the backend core of the [Lantern client](https://github.com/getlantern/lantern) that integrates [sing-box](https://github.com/SagerNet/sing-box/) and the [Outline SDK ](https://github.com/Jigsaw-Code/outline-sdk)in addition to Lantern's own protocols and techniques.

See [Lantern client](https://github.com/getlantern/lantern) for build instructions.

What's the "core" idea behind a lantern? _Light_, or synonymously, _radiance_.

## What's it do?
`radiance` runs a TUN device on the user's device via [sing-tun](https://github.com/SagerNet/sing-tun/) and integrates all sing-box protocols (shadowsocks, hysteria2, vmess, anytls, etc) in addition to a proxyless dialer from the Outline SDK and [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/). Radiance also integrates [application layer Geneva](https://www.youtube.com/watch?v=b9F696-oax0), compatibility with [WATER](https://github.com/refraction-networking/water-rs)/WASM-based transports, and a continuous stream of new Lantern protocols and approaches to stayin unblocked.

## Interoperability
Interoperability is at the core of Lantern and Radiance. Lantern is designed to interoperate with everything from Outline servers to sing-box servers to servers running Lantern's own sing-box extensions. You can similarly run Lantern servers to interoperate with any of those clients. The addition of WATER means that Lantern can deliver new protocols written in any WASM-compatible language at runtime without client-side updates.

## Environment Variables
Configuration can be controlled by setting environment variables or creating a `.env` file in the same directory as the compiled executable or project root directory if running the souce directly. The order of precedence for setting these is as follows:

1.  Environment variables (highest precedence)
2.  `.env` file (lowest precedence)

Available variables:

| Variable                        | Description                                                                                                                                                                                                                                                |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `RADIANCE_LOG_LEVEL`            | Log level: `trace`, `debug`, `info`, `warn`, `error`, `fatal`.                                                                                                                                                                                             |
| `RADIANCE_LOG_PATH`             | Absolute path to the log file.                                                                                                                                                                                                                             |
| `RADIANCE_DATA_PATH`            | Absolute path to the data directory.                                                                                                                                                                                                                       |
| `RADIANCE_DISABLE_FETCH_CONFIG` | If `true`, disables fetching the remote config.                                                                                                                                                                                                            |
| `RADIANCE_DISABLE_STDOUT_LOG`   | Disable printing `radiance` logs to STDOUT. Logs are still written to the log file.                                                                                                                                                                        |
| `RADIANCE_COUNTRY`              | Simulate running from another country (fetches a config as if running from X country). Example: `RADIANCE_COUNTRY=cn`.                                                                                                                                     |
| `RADIANCE_USE_SOCKS_PROXY`      | If `true`, replace the TUN with a SOCKS proxy for inbound connections.                                                                                                                                                                                     |
| `RADIANCE_SOCKS_ADDRESS`        | Address (`host:port`) for the SOCKS proxy to use for inbound connections.                                                                                                                                                                                  |
| `RADIANCE_ENV`                  | `prod` (default) or `dev`. `dev` enables additional debugging output, such as the sing-box config actually in use.                                                                                                                                         |
| `RADIANCE_VERSION`              | Overrides the application version at runtime. Takes precedence over the version set at build time via ldflags. Example: `RADIANCE_VERSION=9.1.1`.                                                                                                          |
| `RADIANCE_FEATURE_OVERRIDES`    | Comma-separated list of feature flags to force-enable on the server side. If set, the value is sent as the `X-Lantern-Feature-Override` header on config requests in any environment; recommended for testing only. Example: `RADIANCE_FEATURE_OVERRIDES=bandit_assignment`. |


## Architecture

Radiance is structured around a `LocalBackend` pattern that ties together all core functionality: configuration, servers, VPN connection, account management, issue reporting, and telemetry. The `LocalBackend` is the central coordinator and should be the primary interface for interacting with Radiance programmatically.

In addition to being the core of the [Lantern client](https://github.com/getlantern/lantern), radiance also provides a standalone daemon and CLI:

- **`lanternd`** — the VPN daemon that runs the `LocalBackend` and exposes an IPC server. It can run in the foreground or be installed as a system service.
- **`lantern`** — a CLI client that communicates with the daemon over IPC.

### Building CLI & Daemon

```sh
make build-daemon
make build-cli
```
Or using [just](https://github.com/casey/just)
```sh
just build-daemon
just build-cli
```

Both binaries are output to `bin/`. You can also run the daemon directly with `make run-daemon`.

To install into `$GOBIN` instead:

```sh
make install   # or: just install
```

> [!note]
> `make install` only compiles the `lanternd` and `lantern` binaries into `$GOBIN`. To register `lanternd` as a system service, run `lanternd install` (see below).

### Running

```sh
# Start the daemon
lanternd run --data-path /path/to/dir --log-path /path/to/dir

# Install/uninstall as a system service
lanternd install --data-path /path/to/dir --log-path /path/to/dir
lanternd uninstall

# CLI (requires a running daemon)
lantern connect [--tag <server-tag>]
lantern disconnect
lantern status
...
```
Use `--help` to see full list of commands and usage.

If `--data-path` and `--log-path` are omitted, `lanternd run` and `lanternd install` use platform-specific defaults:

| Platform | `--data-path`                          | `--log-path`            |
| -------- | -------------------------------------- | ----------------------- |
| Linux    | `/var/lib/lantern`                     | `/var/log/lantern`      |
| macOS    | `/Library/Application Support/Lantern` | `/Library/Logs/Lantern` |
| Windows  | `%ProgramData%\Lantern`                | `%ProgramData%\Lantern` |

## Packages

Use `common.Init` to setup directories and configure loggers.
> [!note]
> This isn't necessary if `NewLocalBackend` was called as it will call `Init` for you.

### `backend`

The `backend` package provides `LocalBackend`, the main entry point for all Radiance functionality. Create one with `NewLocalBackend(ctx, opts)` and call `Start()` to begin fetching configuration and serving requests. `LocalBackend` owns and coordinates the `VPNClient`, `ServerManager`, `ConfigHandler`, `AccountClient`, `IssueReporter`, and telemetry.

### `vpn`

The `vpn` package provides `VPNClient`, which manages the lifecycle of the VPN tunnel.

```go
client := vpn.NewVPNClient(dataPath, logger, platformIfce)
err := client.Connect(boxOptions)
```

`Connect` can be called without disconnecting first, allowing you to seamlessly switch between servers. Once connected, you can query status or view `Connections`. To stop the VPN, call `Disconnect`.

> [!note]
> In most cases, you should use the `LocalBackend` methods (`ConnectVPN`, `DisconnectVPN`, `RestartVPN`, `VPNStatus`) rather than using `VPNClient` directly.

This package also includes split tunneling capabilities via the `SplitTunnel` type, allowing you to include or exclude specific applications, domains, or IP addresses from the VPN tunnel.

### `servers`

The `servers` package manages all VPN server configurations, separating them into two groups: `lantern` (official Lantern servers fetched from the config) and `user` (user-provided servers).

The `Manager` allows you to `AddServers` and `RemoveServers` configurations. You can retrieve the config for a specific server with `GetServerByTag` or use `Servers` to retrieve all configs.

> [!caution]
> While you can get a new `Manager` instance with `NewManager`, it is recommended to use the `LocalBackend`'s server methods (`Servers`, `AddServers`, `RemoveServers`, `GetServerByTag`). These use the shared manager instance. `NewManager` can be useful for retrieving server information if you don't have access to the shared instance, but the new instance should not be kept as it won't stay in sync.

A key feature of this package is the ability to add private servers from a server manager via an access token using `AddPrivateServer`. This process uses Trust-on-first-use (TOFU) to securely add the server. Once a private server is added, you can invite other users with `InviteToPrivateServer` and revoke access with `RevokePrivateServerInvite`.

### `ipc`

The `ipc` package provides the communication layer between the `lantern` CLI and the `lanternd` daemon. The `ipc.Server` exposes an HTTP API backed by the `LocalBackend`, and the `ipc.Client` provides a typed Go client for calling it. All communication happens over a local socket.

### `account`

The `account` package handles user authentication (email/password and OAuth), signup, email verification, account recovery, device management, and subscription operations. It communicates with the Lantern account server and caches authentication state locally.

### `config`

The `config` package fetches proxy configuration from the Lantern API on a polling interval and emits `NewConfigEvent` events when the configuration changes. The `LocalBackend` subscribes to these events to update server configurations automatically.

### `events`

A generic pub-sub event system used throughout Radiance for decoupled communication between components (config changes, VPN status updates, log entries, etc.).

