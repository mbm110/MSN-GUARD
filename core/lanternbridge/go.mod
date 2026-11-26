module github.com/mbm110/msn-guard/lanternbridge

go 1.26.10

// Radiance pins sing-tun to a gVisor fork that provides WritePacketDirect.
// Replace directives in a dependency's go.mod do not propagate into this
// sidecar module, so keep the upstream compatibility pin at the root.
replace github.com/sagernet/sing-box => github.com/getlantern/sing-box-minimal v1.14.2-lantern.3

replace github.com/sagernet/sing-shadowsocks => github.com/getlantern/sing-shadowsocks v0.2.8-lantern.3

replace github.com/tetratelabs/wazero => github.com/getlantern/wazero v1.11.0-water.1

replace github.com/refraction-networking/water => github.com/getlantern/water v0.7.1-alpha.0.20260309190745-bd547c14b4aa

// Upstream Radiance and lantern-box v0.0.243 both force sagernet/gvisor
// (the getlantern/gvisor target no longer resolves): that tag carries the
// WritePacketDirect API and the new udp.NewForwarder signature that
// sing-tun needs, and semver would never select it on its own.
replace github.com/sagernet/gvisor => github.com/sagernet/gvisor v0.0.0-20260727.0-sing-box-mod.1

// Upstream Radiance added this replace with the Proxyless/outline work
// (lantern-box v0.0.243 era); a replace in a dependency does not propagate,
// so mirror it at the root like the other pins.
replace golang.getoutline.org/sdk/x => github.com/getlantern/outline-sdk/x v0.3.0-lantern.2

require github.com/getlantern/radiance v0.0.0-20261121161923-0c920c73b969

// MSN fork of the pinned Radiance (upstream 0c920c73b969), vendored at
// third_party/radiance with a single delta: on Android the TUN stack is
// ALWAYS gvisor. Upstream's kernel check picks the "system" stack on
// >= 5.10 kernels; that stack terminates app TCP through a local listener
// inside the ENGINE process, which does not survive MSN's split-process
// architecture (the engine is a sidecar fed by an SCM_RIGHTS dup of the
// app's TUN fd — field-verified on 3.4.5-3.4.7: with the system stack,
// apps' UDP and DNS flow through the fd while no app TCP connection ever
// reaches the router). gvisor is pure userspace on the same fd — the path
// that already works — and is what upstream itself uses on the < 5.10
// Android majority. A directory replace needs no go.sum entry and no
// network resolution; revert to the upstream pin by deleting this replace.
// See wrapper reference lantern-android-wrapper.md before re-bumping.
replace github.com/getlantern/radiance => ./third_party/radiance
