# Browser Process Isolation and Capture Quality

This repair separates a managed browser failure from ordinary page behavior and
prevents frozen-application libraries from leaking into system executables.

## Root cause

PyInstaller starts the frozen Worker with a private extraction directory in
`LD_LIBRARY_PATH`. A child process inherits that environment unless the caller
overrides it. The failed Chrome process therefore mapped common libraries from a
`/tmp/_MEI...` directory and terminated with `SIGSEGV`; kernel evidence did not
show an out-of-memory kill.

TrafficTracer now restores `LD_LIBRARY_PATH_ORIG` for external processes and
removes any remaining bundle paths from `LD_LIBRARY_PATH` and `LD_PRELOAD`.
Chrome, tshark/dumpcap, Mihomo, and analysis subprocesses all use this sanitized
environment. Display, desktop bus, locale, proxy, and normal executable-path
variables remain available.

## Browser lifecycle evidence

Every new Session records `browser_lifecycle` in `raw/capture-context.json`.
It includes the managed PID, expected or unexpected exit status, exit code, and
signal when applicable. Chrome stderr is written to
`raw/chrome-stderr.log` and compacted to its final 64 KiB after browser
quiescence; the context records its retained size and whether truncation was
required.

An exit during the capture window raises `BROWSER_PROCESS_EXITED`. An unexpected
DevTools WebSocket loss raises `CDP_CONNECTION_LOST`, fails pending commands
immediately, and cannot silently degrade into a navigation timeout. The Worker
checks browser health again immediately before marking `Browser.close` as an
expected shutdown.

When the default bounded retry option is enabled, either classified condition
may consume the target's single automatic retry. The failed attempt and its
Session remain in `batch-manifest.json`; the replacement uses a new Job, cold
profile, Chrome process, and Session. Resume preserves the consumed budget.

## Page outcome semantics

A completed top-level HTTP 2xx document response is sufficient page-load
evidence for an SPA or long-lived page even when `Page.loadEventFired` never
arrives. The analysis retains `load_event_observed` and
`completion_evidence`, so this relaxation is explicit rather than inferred.

Main-document transport failures are separated into TLS certificate, DNS,
timeout, connectivity, and generic network classes. DNS, timeout, and
connectivity failures remain eligible for one bounded retry. Deterministic TLS
certificate failures are preserved as `MAIN_DOCUMENT_TLS_ERROR` and are not
automatically retried.

## Verification boundary

The source regression suite passed 719 tests. The coordinated desktop changes
passed the focused 22-test TrafficTracer UI suite, TypeScript type checking,
Rust formatting, and compilation of the affected Rust command module. A small
installed-package capture should still precede another full 64-target matrix;
the acceptance sample must show no `_MEI` libraries in Chrome, expected browser
lifecycle evidence for successful Sessions, and a fresh retry Session under an
injected browser/CDP failure.
