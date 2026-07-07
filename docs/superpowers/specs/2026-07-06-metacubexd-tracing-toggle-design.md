# metacubexd Tracing Toggle Design Spec

## Overview

Add a connection tracing control to metacubexd's Sidebar, so users can enable/disable mihomo-TrafficTracer's trace output from the dashboard GUI — no curl commands needed.

## Architecture

```
┌──────────────────────────────────────┐
│  metacubexd Sidebar (:9099/ui)       │
│                                      │
│  nav items (overview, proxies, ...)  │
│  ─────────────────────────────────── │
│  Mode Switcher (rule/direct/global)  │
│  ─────────────────────────────────── │
│  ★ Tracing Toggle  ← NEW             │
│    [enabled|disabled] status badge   │
│    output file path (when enabled)   │
│    [Enable]/[Disable] button         │
└──────────────────────────────────────┘
         │ GET /experimental/tracing
         │ PATCH /experimental/tracing
         ▼
┌──────────────────────────────────────┐
│  mihomo REST API (:9099)             │
│  /experimental/tracing               │
└──────────────────────────────────────┘
```

## Files

| Action | File | Purpose |
|--------|------|---------|
| Create | `composables/useTracing.ts` | API hooks for tracing GET/PATCH |
| Create | `components/TracingToggle.vue` | Sidebar UI component |
| Modify | `components/Sidebar.vue` | Insert TracingToggle after mode switcher |

## API Contract

### GET /experimental/tracing

```json
{ "enabled": true, "output": "/tmp/mihomo-trace.jsonl" }
```
```json
{ "enabled": false }
```

### PATCH /experimental/tracing

Request:
```json
{ "enabled": true, "output": "/tmp/trace.jsonl" }
```
```json
{ "enabled": false }
```

Response: same as GET.

## UI States

### Disabled state
```
┌──────────────────────────────────┐
│  📝 Tracing                 OFF  │
│  [ Enable Tracing ]              │
└──────────────────────────────────┘
```

### Enabled state
```
┌──────────────────────────────────┐
│  📝 Tracing                  ON  │
│  output: /tmp/trace.jsonl        │
│  [ Disable Tracing ]             │
└──────────────────────────────────┘
```

### Loading state
```
┌──────────────────────────────────┐
│  📝 Tracing               ...    │
│  [  ...  ]                       │
└──────────────────────────────────┘
```

### Error state
```
┌──────────────────────────────────┐
│  📝 Tracing              error   │
│  Unable to reach API             │
│  [ Retry ]                       │
└──────────────────────────────────┘
```

## Non-Requirements

- No output file path editing (use default or detect from API)
- No trace log viewer
- No historical trace management
- No i18n translations (use English for now)
