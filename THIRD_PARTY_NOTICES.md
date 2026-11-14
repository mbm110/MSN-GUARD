# Third-party notices

## Lantern / Radiance

- Project: https://github.com/getlantern/radiance
- Pinned source revision: `0f837799e530773ac50e175d9924314e6964d764`
- License: GNU General Public License, version 3 (GPL-3.0)
- License text: [licenses/RADIANCE-GPL-3.0.txt](licenses/RADIANCE-GPL-3.0.txt)
- Go module pin: `github.com/getlantern/radiance v0.0.0-20261114050550-0f837799e530`

The Android bridge is built with Radiance's `novpn` build tag. This removes
Radiance's TUN inbound and exposes a loopback-only mixed HTTP/SOCKS listener;
MSN-GUARD remains the sole owner of Android's VpnService and device TUN.

## Go mobile binding

- Project: https://github.com/golang/mobile
- Pinned tool version: `v0.0.0-20260908204917-8b95e45f8d3e`
- License: BSD 3-Clause (see the upstream project for the complete notice).

## Dependency compliance

Radiance brings its own transitive Go dependencies. Their versions are pinned
by the Radiance module metadata and are resolved by
`core/lanternbridge/build-android.sh`. Each dependency retains its own license
and copyright notices; before distributing a release APK, generate and review
a complete dependency-license inventory and include any notices required by
those licenses.

MSN-GUARD is distributed under AGPL-3.0. Adding a GPL-3.0 component does not
make copyleft obligations disappear merely because it is packaged as a
separate AAR. Review combined-work compatibility, corresponding-source
availability, and all notices before publishing a release.
