module github.com/mbm110/msn-guard/lanternbridge

go 1.26.10

// Radiance pins sing-tun to a gVisor fork that provides WritePacketDirect.
// Replace directives in a dependency's go.mod do not propagate into this
// sidecar module, so keep the upstream compatibility pin at the root.
replace github.com/sagernet/sing-box => github.com/getlantern/sing-box-minimal v1.14.2-lantern.3

replace github.com/sagernet/sing-shadowsocks => github.com/getlantern/sing-shadowsocks v0.2.8-lantern.3

replace github.com/tetratelabs/wazero => github.com/getlantern/wazero v1.11.0-water.1

replace github.com/refraction-networking/water => github.com/getlantern/water v0.7.1-alpha.0.20260309190745-bd547c14b4aa

// Upstream Radiance and lantern-box v0.0.240 both force sagernet/gvisor
// (the getlantern/gvisor target no longer resolves): that tag carries the
// WritePacketDirect API and the new udp.NewForwarder signature that
// sing-tun needs, and semver would never select it on its own.
replace github.com/sagernet/gvisor => github.com/sagernet/gvisor v0.0.0-20260727.0-sing-box-mod.1

// Upstream Radiance added this replace with the Proxyless/outline work
// (lantern-box v0.0.240 era); a replace in a dependency does not propagate,
// so mirror it at the root like the other pins.
replace golang.getoutline.org/sdk/x => github.com/getlantern/outline-sdk/x v0.3.0-lantern.1

require github.com/getlantern/radiance v0.0.0-20261121161923-0c920c73b969
