# MSN-GUARD Android design contract

## Intent

MSN-GUARD should feel like a calm, trustworthy dark Android system tool. The home screen is a
single-purpose connection console: the connection state is visible at a glance, the main
action is physically obvious, and live connection facts (exit IP, country, data, duration)
are readable without scrolling.

This is MSN-GUARD's own visual system. Any third-party app is an interaction reference only;
do not copy its code, wording, logo, or branding.

## Foundations

- **Platform:** native Android views, platform typography, and Android system bars.
- **Canvas:** `#101411`
- **Surface:** `#171C18`
- **Surface variant:** `#222A24`
- **Ink:** `#E8F1EA`
- **Muted text:** `#B9C6BB`
- **Divider:** `#3B473E`
- **Idle / primary:** `#A4D8BB`
- **Connected:** `#67D89C`
- **Connection error:** `#FFB4AB`
- **Typography:** Roboto / Android system sans. Use a compact hierarchy: app name 22sp,
  status 20sp, supporting labels 14sp, metadata 12sp.

## Home screen

- Keep the top of the screen quiet: no logo, no wordmark, no decorative cards. The brand
  lives on the launcher icon and the opening splash, not above the connect button.
- Put the circular connection control at the visual centre. It is the only large, filled
  control on the screen and has a minimum 176dp target.
- Place the selected connection status immediately below the circle.
- The app is VPN-mode only; there is no mode selector. The protocol picker is the single
  outlined, full-width control beneath the status, and it is disabled while a tunnel is active.
- Use real connection wording only: `Not connected`, `Connecting`, `Connected`, and
  `Connection failed`. Do not claim protection before the core reports it is running.
- The control uses the primary colour while idle or connecting, brighter green while connected,
  and red only after a reported connection failure.

## Motion and feedback

- A press scales the circular control to 97% for 90ms, then returns over 180ms with a
  strong ease-out. State changes redraw the ring and icon rather than moving the layout.
- Use Android's standard context-click haptic on an intentional connection tap.
- Keep motion under 300ms and restricted to transform, alpha, and the control's own drawing.
- Latency keeps its normal graph while probing. After each returned `N ms`, lift and settle the
  graph over 280ms without moving surrounding content.
- Respect Android accessibility: every interactive element has a clear content description;
  colour never carries state alone.

## Guardrails

- No copied third-party assets, names, code, screenshots, or branding.
- No gradients, neon, oversized text, fake statistics, or nested-card dashboards.
- No extra UI libraries for this first screen. Add Jetpack Compose or Material dependencies
  only when the app grows enough screens to justify that migration.
