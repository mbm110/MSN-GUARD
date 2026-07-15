# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| Earlier versions | No |

## Reporting a vulnerability

Please report vulnerabilities privately through [GitHub Security Advisories](https://github.com/ZethRise/Aethery/security/advisories/new).

Include:

- affected Aethery version and device ABI;
- Android version and device/emulator model;
- impact and realistic attack scenario;
- minimal reproduction steps or a proof of concept;
- whether the issue belongs to Aethery's Android layer or the [Aether core](https://github.com/CluvexStudio/Aether).

Do **not** include private keys, real provisioning identities, personal traffic captures, access tokens, or unredacted scan logs.

We will acknowledge a valid report, assess impact, and coordinate disclosure before publishing details. Please avoid public issues until a fix or mitigation is available.

## Scope

Aethery owns Android UI, JNI, VPN/TUN integration, packaging, and release workflow behavior. Route discovery, protocol behavior, and tunnel implementation may belong to Aether; reports affecting that core may be transferred or reproduced upstream with your consent.
