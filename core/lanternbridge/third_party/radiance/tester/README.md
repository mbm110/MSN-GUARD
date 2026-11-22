# Radiance/Lantern-box tester

This is a simple tester for the Radiance library.
It receives all it's arguments via environment variables.

`FETCH_TIMEOUT_SECONDS` defaults to 20 and accepts 1–600. A process deadline also
bounds connection startup. Only HTTPS URLs and redirects are accepted.

The image uses the `novpn` build tag and a local SOCKS listener, without TUN privileges.
Set `RADIANCE_ENV` to `staging` or `production`. For a pinned track, set `STICKY=true`,
provide `config.json` in `DATA`, and set `TARGET_TAG` to the assigned outbound or
endpoint tag. Configuration fetching is disabled. `DIRECT=true` measures the
container's network without starting the client.

`fetch.json` contains curl's HTTP status, exit code, total and first-byte timings;
the response body is in `output.txt`. An HTTP error from the origin still proves
reachability. `connection.txt` is `connecting` until the tunnel connects, then
`connected`. A stopped tester with `connecting` and no fetch metadata failed to
establish the tunnel. Missing both files indicates a tester or configuration
failure. Old result artifacts are cleared before each run.

## Environment variables

- `DEVICE_ID`: The device id to use.
- `USER_ID`: The user id to use.
- `TOKEN`: The token to use.
- `RUN_ID`: The run id to use. It is the `run_id` attribute of the tester's root span.
- `TARGET_URL`: The target url to use. This is the url that will be pinged .
- `DATA`: The path to use for config files and for logs. This is the path where the output will be written to (config.json, etc). You can place custom config there to use it instead of fetching. (together with `STICKY=true` env var, see below)

All of these are required.

## Traces

The tester reports what it did as OpenTelemetry spans under the service
`radiance-tester`: `tester.run` for the whole run (`tester.run_id`, `tester.mode`,
`tester.sticky`, `tester.target_tag`, `url.full`), `tester.connect` around the
tunnel bring-up (with radiance's own `connect` and `tunnel.*` spans below it)
and `tester.fetch` for the curl fetch (`http.response.status_code`,
`tester.curl_exit_code`, `tester.curl_error`, `tester.total_ms`,
`tester.first_byte_ms`, `network.peer.address`). The keys are
`github.com/getlantern/semconv`'s, and URLs are recorded without credentials.
Exporting is off unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set:

- `OTEL_EXPORTER_OTLP_ENDPOINT`: the OTLP/gRPC collector, as `host:port` or a URL,
  e.g. `ingest.us.signoz.cloud:443`.
- `OTEL_EXPORTER_OTLP_HEADERS` (optional): comma-separated `key=value` pairs sent with
  every export, for collectors that need them, e.g. `signoz-ingestion-key=...`.
- `TRACEPARENT` (optional): a W3C trace context; the tester's spans then join that trace
  instead of starting one. The pinger sets it to the span that started the container.

Every span is kept; the parent's sampling decision, when there is one, is honoured.
The run's spans are flushed before the process exits, within a few seconds of its deadline.

## CLI usage

Build with `go build -tags novpn,with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api -o tester-bin ./tester`.
The default local SOCKS listener is `127.0.0.1:1080`; set
`RADIANCE_SOCKS_ADDRESS` to use a different address. Each invocation uses a fresh
client state directory below `DATA`, so retained server assignments cannot affect
either pinned targets or normal configuration fetching.

```bash
RADIANCE_ENV=staging DEVICE_ID=1234 USER_ID=123 TOKEN=1234 RUN_ID=1234 TARGET_URL=https://example.com DATA=./mydir ./tester-bin
```

The tester will start Radiance tunnel, fetch the config & proxies and try to reach the target URL via the tunnel.
Upon success, it will write the output of that request to the `output.txt`.

## Docker usage

On each new push to the repository, a new image of the tester is built and pushed to the registry.
It's tagged as `us-docker.pkg.dev/lantern-cloud/containers/radiance-tester:RADIANCE_HASH`


```bash
docker run --rm -v ./mydir:/output \
    -e RADIANCE_ENV=staging \
    -e DEVICE_ID=1234 \
    -e USER_ID=1234 \
    -e TOKEN=1234 \
    -e RUN_ID=1234 \
    -e TARGET_URL=https://example.com \
    -e DATA=/output \
   us-docker.pkg.dev/lantern-cloud/containers/radiance-tester
```

## Passing custom settings

If you want to use a custom config instead of fetching, you can place it in the output directory and it will be used instead of fetching it from the server.
In order for tester to pick it up instead of using the fetched config, set `STICKY=true` and `TARGET_TAG` to the configured outbound or endpoint tag
