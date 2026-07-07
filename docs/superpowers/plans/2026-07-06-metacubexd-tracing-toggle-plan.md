# metacubexd Tracing Toggle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a connection tracing on/off toggle to the metacubexd Sidebar, controlling mihomo-TrafficTracer's `/experimental/tracing` API.

**Architecture:** One new Vue composable (`useTracing`) wraps TanStack Query to GET/PATCH the tracing endpoint. One new component (`TracingToggle`) renders the UI. The Sidebar imports and places the component after the existing mode switcher.

**Tech Stack:** Nuxt 3, Vue 3 Composition API, TypeScript, TanStack Vue Query, @tabler/icons-vue, ky HTTP client

## Global Constraints

- All files under `packages/ui/` in the metacubexd repo at `/data/ytluo/projects/metacubexd/`
- Follow existing patterns: `useQueries.ts` for API hooks, `components/` for Vue SFC
- Use `createRequest()` from `~/composables/useQueries` for API calls
- Use `@tabler/icons-vue` for icons
- Component must handle loading, error, enabled, disabled states
- No i18n for now (use English strings directly)
- No tests for UI components (follow existing codebase convention — no component tests exist)

---

### Task 1: Create useTracing composable

**Files:**
- Create: `packages/ui/composables/useTracing.ts`

**Interfaces:**
- Produces: `useTracingQuery()` → TanStack Query result with `{ enabled: boolean, output?: string }`, `useTracingMutation()` → TanStack Mutation with `mutate({ enabled: boolean, output?: string })`

- [ ] **Step 1: Create `packages/ui/composables/useTracing.ts`**

```typescript
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { useEndpointScopedKey } from './useQueries'
import { useRequest } from './useApi'

const tracingKeys = {
  tracing: ['tracing'] as const,
}

interface TracingStatus {
  enabled: boolean
  output?: string
}

function createRequest() {
  return useRequest()
}

export function useTracingQuery() {
  return useQuery({
    queryKey: useEndpointScopedKey(tracingKeys.tracing),
    queryFn: async (): Promise<TracingStatus> => {
      const request = createRequest()
      const data = await request.get('experimental/tracing').json<TracingStatus>()
      return data
    },
    refetchInterval: 10_000,
  })
}

export function useTracingMutation() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (body: { enabled: boolean; output?: string }) => {
      const request = createRequest()
      return await request
        .patch('experimental/tracing', { json: body })
        .json<TracingStatus>()
    },
    onSuccess: () => {
      const key = useEndpointScopedKey(tracingKeys.tracing)
      queryClient.invalidateQueries({ queryKey: key.value ?? tracingKeys.tracing })
    },
  })
}
```

- [ ] **Step 2: Build and verify no TS errors**

```bash
cd /data/ytluo/projects/metacubexd && pnpm --filter @metacubexd/ui build:mock 2>&1 | tail -5
```

Expected: build succeeds (may warn about unused composable until Task 3)

- [ ] **Step 3: Commit**

```bash
cd /data/ytluo/projects/metacubexd
git add packages/ui/composables/useTracing.ts
git commit -m "feat: add useTracing composable for /experimental/tracing API"
```

---

### Task 2: Create TracingToggle component

**Files:**
- Create: `packages/ui/components/TracingToggle.vue`

**Interfaces:**
- Consumes: `useTracingQuery`, `useTracingMutation` (from Task 1)
- Produces: Vue SFC component imported by Sidebar (Task 3)

- [ ] **Step 1: Create `packages/ui/components/TracingToggle.vue`**

```vue
<script setup lang="ts">
import { IconFileDescription } from '@tabler/icons-vue'
import { useTracingQuery, useTracingMutation } from '~/composables/useTracing'

const { data: tracing, isLoading, isError, refetch } = useTracingQuery()
const mutation = useTracingMutation()

const isEnabled = computed(() => tracing.value?.enabled ?? false)
const outputPath = computed(() => tracing.value?.output ?? '')

function toggle() {
  mutation.mutate({ enabled: !isEnabled.value })
}
</script>

<template>
  <div class="flex flex-col gap-1.5 border-t border-base-300 pt-3">
    <!-- Header row -->
    <div class="flex items-center gap-2 text-xs text-base-content/60">
      <IconFileDescription :size="14" />
      <span>Tracing</span>
      <span
        v-if="!isLoading && !isError"
        class="ml-auto rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
        :class="
          isEnabled
            ? 'bg-success/15 text-success'
            : 'bg-base-300 text-base-content/50'
        "
      >
        {{ isEnabled ? 'ON' : 'OFF' }}
      </span>
      <span v-else-if="isLoading" class="ml-auto animate-pulse text-xs">
        ...
      </span>
      <span v-else class="ml-auto text-xs text-error">error</span>
    </div>

    <!-- Output path (when enabled) -->
    <p
      v-if="isEnabled && outputPath && !isLoading"
      class="truncate text-[11px] text-base-content/40"
    >
      {{ outputPath }}
    </p>

    <!-- Toggle button -->
    <button
      v-if="!isError"
      class="btn btn-xs w-full"
      :class="mutation.isPending ? 'btn-disabled' : ''"
      :disabled="isLoading || mutation.isPending"
      @click="toggle"
    >
      {{ mutation.isPending ? '...' : isEnabled ? 'Disable Tracing' : 'Enable Tracing' }}
    </button>

    <!-- Retry -->
    <button
      v-else
      class="btn btn-xs btn-ghost w-full text-error"
      @click="refetch()"
    >
      Retry
    </button>
  </div>
</template>
```

- [ ] **Step 2: Build and verify**

```bash
cd /data/ytluo/projects/metacubexd && pnpm --filter @metacubexd/ui build:mock 2>&1 | tail -5
```

Expected: build succeeds

- [ ] **Step 3: Commit**

```bash
cd /data/ytluo/projects/metacubexd
git add packages/ui/components/TracingToggle.vue
git commit -m "feat: add TracingToggle component for sidebar"
```

---

### Task 3: Integrate TracingToggle into Sidebar

**Files:**
- Modify: `packages/ui/components/Sidebar.vue` — import and place TracingToggle

**Interfaces:**
- Consumes: `TracingToggle` component (from Task 2)
- Produces: visible tracing control in sidebar

- [ ] **Step 1: Add import to Sidebar.vue**

In the `<script setup>` section, add after the existing icon imports:

```typescript
import TracingToggle from '~/components/TracingToggle.vue'
```

- [ ] **Step 2: Place TracingToggle in template**

In the `<template>` section, find the expanded sidebar mode switcher section ending around line 333 (the `</div>` after the mode selector buttons). Insert `<TracingToggle />` on a new line between lines 333-334, so it sits between the mode switcher and the collapsed mode switcher section:

```vue
            </div>
          </div>

          <!-- Tracing Toggle -->
          <TracingToggle />

          <!-- Running mode switcher (collapsed desktop) -->
          <div
```

- [ ] **Step 3: Full build and verify**

```bash
cd /data/ytluo/projects/metacubexd && pnpm --filter @metacubexd/ui build:mock 2>&1 | tail -10
```

Expected: build succeeds, no TypeScript or template errors

- [ ] **Step 4: Test in dev mode**

```bash
cd /data/ytluo/projects/metacubexd && pnpm dev:ui &
sleep 5
curl -s http://localhost:3000 | head -1
# Expected: HTML output (SPA)
kill %1
```

- [ ] **Step 5: Commit**

```bash
cd /data/ytluo/projects/metacubexd
git add packages/ui/components/Sidebar.vue
git commit -m "feat: add TracingToggle to sidebar"
```
