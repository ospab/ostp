# OSTP desktop: design

This describes the look the app already has. It is not a redesign; new UI keeps to it.

## Colours

- Night `#080808`: window background.
- Surface `#111111`: power button, dialogs. Cards are white at 4% over Night.
- Text `#f0f0f0`; muted text `#8c8c8c`; placeholders and idle icons `#5c5c5c`.
- White `#ffffff`: the one accent (primary button, selected tab, toggle thumb).
- Green `#2ee66d`: only "connected" and success.
- Red `#ff5f5f` for errors and destructive actions; amber `#f0b840` for warnings.

## Type

- Inter (or the system UI font when it is not installed) for all text. No web fonts are loaded:
  the app must not contact a third party and must render offline.
- JetBrains Mono (or Consolas) for addresses, keys, logs and numbers that change.

## Layout

One narrow column, at most 460 px wide, one screen at a time: home (the power button and the
state), settings, more settings, servers, network check. Rows with a border instead of boxes in
boxes. Dialogs for choices and confirmations, toasts for results.

## Principles

1. The screen says what is true. The button shows "connected" only after the core reports it.
2. A button names its action ("Delete profile", not "OK"). One action has one name everywhere.
3. No decoration: no glows, gradients, grids, blur, entrance animations or all-caps labels.
   Motion only where something is in progress (the blinking button while connecting, spinners).
