# Kindling transport tester

Tests individual [kindling](../../kindling) transports (proxyless, fronted, amp, DNS tunnel).
It receives all its arguments via environment variables and uses the kindling HTTP client directly

## Environment variables

### Required

- `DEVICE_ID`: The device ID to use.
- `USER_ID`: The user ID to use.
- `TOKEN`: The auth token to use.
- `RUN_ID`: The run ID. Added to traces as `pinger-id` — useful for looking up a specific run.
- `TARGET_URL`: The URL that will be fetched through kindling.
- `DATA`: Directory for config files, logs, and output artefacts (`output.txt`, `timing.txt`, `success`).

- `TRANSPORT`: The kindling transport to test. One of: `smart`, `domainfront`, `amp`, `soar`. `soar` is the DNS tunnel; it needs a build carrying a Soar server (see `kindling/soar`).

## CLI usage

```bash
DEVICE_ID=1234 USER_ID=123 TOKEN=mytoken RUN_ID=run1 TARGET_URL=https://example.com DATA=./mydir \
    TRANSPORT=smart \
    ./kindling-tester
```

Replace `smart` with the transport you want to test (`domainfront`, `amp`, `soar`).

Upon success the tester writes:
- `DATA/success` — empty marker file
- `DATA/output.txt` — response body
- `DATA/timing.txt` — timing breakdown (connect + fetch latency)

## Docker usage

A separate image is built per transport. Each image bakes `TRANSPORT` in at build time via `ENV TRANSPORT=${TRANSPORT}`.

### Building

```bash
docker build --build-arg TRANSPORT=smart       -t radiance-kindling-tester:smart       -f ./docker/Dockerfile.kindling-tester .
docker build --build-arg TRANSPORT=domainfront -t radiance-kindling-tester:domainfront -f ./docker/Dockerfile.kindling-tester .
docker build --build-arg TRANSPORT=amp         -t radiance-kindling-tester:amp         -f ./docker/Dockerfile.kindling-tester .
docker build --build-arg TRANSPORT=soar --build-arg SOAR_ZONE="$SOAR_ZONE" --build-arg SOAR_PUBLIC_KEY="$SOAR_PUBLIC_KEY" \
                                                -t radiance-kindling-tester:soar        -f ./docker/Dockerfile.kindling-tester .
```

### Running

```bash
docker run --rm -v ./mydir:/output \
    -e DEVICE_ID=1234 \
    -e USER_ID=1234 \
    -e TOKEN=mytoken \
    -e RUN_ID=run1 \
    -e TARGET_URL=https://example.com \
    -e DATA=/output \
    radiance-kindling-tester:smart
```

Swap the image tag to test a different transport; no other flags need to change.
