module github.com/mbm110/msn-guard/lanternbridge

go 1.26.10

// Radiance pins sing-tun to a gVisor fork that provides WritePacketDirect.
// Replace directives in a dependency's go.mod do not propagate into this
// sidecar module, so keep the upstream compatibility pin at the root.
replace github.com/sagernet/sing-box => github.com/getlantern/sing-box-minimal v1.14.2-lantern.3

replace github.com/tetratelabs/wazero => github.com/getlantern/wazero v1.11.0-water.1

replace github.com/refraction-networking/water => github.com/getlantern/water v0.7.1-alpha.0.20260309190745-bd547c14b4aa

replace github.com/sagernet/gvisor => github.com/sagernet/gvisor v0.0.0-20260727.0-sing-box-mod.1

require github.com/getlantern/radiance v0.0.0-20261114050550-0f837799e530
