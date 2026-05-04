# Targeted device passthrough

Status: design + implementation under `dominik/device-passthrough`.
Tracks `dotto-nexus#74`.

## Why

`agent-sandbox` has historically offered a single boolean for `/dev`
visibility:

| `BIND_DEV_PTS` | bwrap behavior          | What's visible inside the sandbox       |
| -------------- | ----------------------- | --------------------------------------- |
| `false` (def.) | `--dev /dev`            | Minimal devtmpfs only — no GPU, no pty  |
| `true`         | `--dev-bind /dev /dev`  | Entire host `/dev` — GPU works, but pty |

The "true" half opens `/dev/pts`, which on kernels < 6.2 lets a sandboxed
process inject keystrokes into the user's other terminals via `TIOCSTI`.
Fred Hutch's gizmo cluster runs `5.4.0-228-generic`, so the toggle is a
GPU-vs-TIOCSTI dilemma. (`GPU_PASSTHROUGH=auto`, the recent libcuda
discoverability fix, is library-side only — it doesn't bind device nodes.)

The fix is a **targeted** mechanism: expose only the device nodes the
workload needs.

## Three components

### A — `DEVICES` (user list)

`~/.config/agent-sandbox/sandbox.conf`:

```bash
# Device nodes to expose inside the sandbox. Glob patterns are expanded
# against the host /dev at sandbox spawn time. Defaults (NVIDIA + DRI)
# are pre-set in sandbox-lib.sh; user config can append (DEVICES+=) or
# replace (DEVICES=).
DEVICES=(
    /dev/nvidia*
    /dev/nvidia-uvm
    /dev/nvidia-uvm-tools
    /dev/nvidia-modeset
    /dev/nvidiactl
)
```

Each resolved device is bound into the sandbox via
`bwrap --dev-bind PATH PATH` (read-write, the same shape `--dev-bind /dev
/dev` used to take, just narrowed to single nodes).

Glob expansion is host-relative — on a node without GPUs the NVIDIA
defaults expand to nothing and are silently dropped. No spurious errors
on CPU-only hardware.

### B — `DEVICES_DEFAULTS` in the script

Shipped defaults live in `sandbox-lib.sh` (alongside other config
defaults). The user template's `DEVICES=(...)` mirrors the defaults
verbatim so editing it is straightforward; conf.d additions
(`DEVICES+=(...)`) layer cleanly on top.

```bash
# In sandbox-lib.sh:
DEVICES=(
    /dev/nvidia*
    /dev/nvidia-uvm
    /dev/nvidia-uvm-tools
    /dev/nvidia-modeset
    /dev/nvidiactl
)
```

### C — `DEVICES_BLACKLIST` (admin enforced)

Admin baseline at the install path that the user cannot edit
(`/app/lib/agent-sandbox/sandbox.conf` when an admin install is in place,
falls back to `sandbox-admin.conf` shipped with the source tree):

```bash
DEVICES_BLACKLIST=(
    /dev/mem
    /dev/kmem
    /dev/port
    /dev/pts          # TIOCSTI risk on kernel < 6.2
    /dev/sd*          # raw block devices
    /dev/nvme*
    /dev/loop*
)
```

Without an admin install, `sandbox-lib.sh` ships safe defaults so the
blacklist is never empty.

Enforcement layering mirrors `BLOCKED_FILES` and friends:

1. `sandbox-lib.sh` defaults → `_load_untrusted_config` user.conf →
   `_enforce_admin_policy` → `_load_untrusted_config` conf.d/*.conf →
   `_enforce_admin_policy` again.
2. `DEVICES_BLACKLIST` is in `_ENFORCED_ARRAYS`: user/conf.d can
   **add** entries but cannot **remove** admin-set ones — same model as
   `BLOCKED_FILES`.
3. After resolution, every `DEVICES` entry is glob-matched against
   every `DEVICES_BLACKLIST` glob. Hits are dropped and logged to stderr
   ("agent-sandbox: device /dev/pts is blacklisted, skipping").

## Resolution algorithm

```text
_resolve_devices()
    DEVICES_RESOLVED=()
    for entry in DEVICES:
        for path in shopt-nullglob expansion of entry against host /dev:
            blacklisted = false
            for bad_glob in DEVICES_BLACKLIST:
                if path matches bad_glob:        # bash case glob
                    log "device $path blacklisted, skipping"
                    blacklisted = true
                    break
            if not blacklisted and path is a device or symlink-to-device:
                DEVICES_RESOLVED+=(path)
```

Notes:
- `shopt -s nullglob` — globs that match nothing (e.g. `/dev/nvidia*` on
  a CPU-only node) drop silently.
- Both literal paths (`/dev/nvidia0`) and globs (`/dev/nvidia*`) are
  blacklist-checked against the **resolved** path, so
  `DEVICES_BLACKLIST=(/dev/nvidia*)` correctly drops every NVIDIA node.
- `case "$path" in $glob)` is the matcher — same idiom
  `_is_blocked_by_pattern` already uses for env-var globs.

## Wiring into `backends/bwrap.sh`

Replace the existing `BIND_DEV_PTS` branch:

```bash
# Before:
if _is_true "${BIND_DEV_PTS:-false}"; then
    BWRAP_ARGS+=(--dev-bind /dev /dev)
else
    BWRAP_ARGS+=(--dev /dev)
fi

# After:
BWRAP_ARGS+=(--dev /dev)            # always start with minimal devtmpfs
_resolve_devices                    # populate DEVICES_RESOLVED
for _devnode in "${DEVICES_RESOLVED[@]}"; do
    BWRAP_ARGS+=(--dev-bind "$_devnode" "$_devnode")
done
```

## `BIND_DEV_PTS` — deprecated alias

Existing configs that say `BIND_DEV_PTS=true` get a kernel-aware shim:

```bash
if _is_true "${BIND_DEV_PTS:-false}"; then
    if _kernel_at_least 5 4; then
        echo "agent-sandbox: BIND_DEV_PTS=true is a no-op on kernel >= 5.4 ..." >&2
    else
        echo "agent-sandbox: BIND_DEV_PTS is deprecated; use DEVICES+=(/dev/pts) instead." >&2
        DEVICES+=(/dev/pts)
    fi
fi
```

The shim splits on the kernel because the right answer differs:

* **Kernel < 5.4** — bwrap's user-namespace devpts ships with
  `ptmxmode=000` (the unprivileged-userns mount honours the host
  devpts default), so tmux/script/expect cannot allocate a pty inside
  the sandbox. The historical workaround was to bind the host
  `/dev/pts`, which has `ptmxmode=666`. The shim preserves that on
  pre-5.4 kernels by appending `/dev/pts` to `DEVICES`.
* **Kernel >= 5.4** — bwrap auto-mounts a working user-ns devpts.
  Binding the host `/dev/pts` on top shadows the working mount with
  the host's `ptmxmode=000` and silently breaks pty allocation
  (tmux exits with "create session failed"; `script(1)` with
  "failed to create pseudo-terminal: Permission denied"). On these
  kernels the shim emits a "no-op, drop the line" notice and
  declines to append `/dev/pts`.

Explicit `DEVICES+=(/dev/pts)` is also flagged on kernel >= 5.4 with
a stderr warning at every spawn. The entry is preserved (we do not
override explicit user intent), but the user is told why their tmux
is broken. The default `DEVICES_BLACKLIST` masks this for fresh
installs; the trap fires only when both `BIND_DEV_PTS=true` migration
configs **and** a user-overridden `DEVICES_BLACKLIST` are in play.

The blacklist still applies in either branch — admins who want to
refuse pty exposure cluster-wide add `/dev/pts` to
`DEVICES_BLACKLIST` and the legacy toggle becomes a logged no-op
regardless of kernel version.

This is a **behavior change** for users who relied on `BIND_DEV_PTS=true`
to expose more than pty (e.g. `/dev/snd`, `/dev/nvidia*`). The migration
path is to add the specific nodes to `DEVICES+=(...)`. NVIDIA users get
the right answer for free because the defaults already cover them.

## Testing

Targets in `test.sh` (config-aware, like the `S02_credentials` suite):

| ID  | Scope                                                            |
| --- | ---------------------------------------------------------------- |
| D01 | NVIDIA defaults: when host has `/dev/nvidia0`, sandbox sees them |
| D02 | `DEVICES+=(/dev/snd)` exposes `/dev/snd/*` if present            |
| D03 | `DEVICES=()` clears all (user-side reset)                        |
| D04 | `DEVICES_BLACKLIST` enforcement: user `DEVICES+=(/dev/pts)` is dropped |
| D05 | Glob `*` against missing host nodes → silent no-op (no error)    |
| D06 | Deprecated `BIND_DEV_PTS=true` → `/dev/pts` appears, deprecation warning |
| D07 | Backend skip: landlock/firejail emit a warning if `DEVICES` set  |

## Out of scope for this PR

- DRM/render device defaults (`/dev/dri/*`) — punt until a Vulkan/ROCm
  user files an issue. Trivially added to `DEVICES_DEFAULTS` later.
- Per-agent device profiles (`agents/<name>/config.conf` adding to
  `DEVICES`) — current arch already supports this if anyone needs it;
  no explicit wiring here.
- AMD/Intel GPU passthrough — same shape, just different node names.
  Documented in the migration note, not enforced.
