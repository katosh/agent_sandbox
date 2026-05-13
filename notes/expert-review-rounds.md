# Expert review rounds — network-filter v1.1 hostname-removal + docs reorg

Process per dotto-nexus#117 comment 4436219447: spawn an in-process
expert pool, collect issues, apply fixes, repeat until convergence
(cap 3 rounds).

## Reviewer pool (5)
- **doc-clarity**: clarity, structure, idiomatic technical writing, cross-link integrity
- **security**: threat-model accuracy, completeness, honesty about enforcement scope
- **hpc-operator**: practical usability for a shared-cluster operator
- **ux-onboarding**: discoverability, new-user persona walkthroughs
- **consistency**: cross-document contradictions, stale claims, drift-prone duplication

## Round 1 — output

### Consolidated MUST findings (applied this round)

| Source | Finding | Fix applied |
|---|---|---|
| security | `_NETWORK_BLOCKLIST_DEFAULTS=()` empty → upgrader with stale sandbox.conf gets ZERO enforcement; doc claim of "universal port floor" is false at the runtime | Moved 12 universally-enforceable ports into `_NETWORK_BLOCKLIST_DEFAULTS` (mail 24/25/465/587/2525, DoT 853, r-services 23/79/113/512/513/514). sandbox.conf NETWORK_BLOCKLIST now thin (commented-out site-specific examples only) |
| security | `*` deny-all rationale was wrong mechanism ("would break DNS through pasta's proxy" — pasta's resolver is userland, doesn't egress) | Rewrote: "pasta's `-T` exclusion syntax has no exclude-all form short of an explicit allow-list" |
| security | Admin entry `10.0.0.0/8:443` silently widens to universal port-443 closure → breaks pip/git/HTTPS | Generator now emits UNCONDITIONAL `WARNING:` for any non-universal CIDR:port (not gated behind `NETWORK_FILTER_VERBOSE`). Docs updated with explicit "Footgun warning" callout on the admin example |
| security | "Fully closed by port-class closure" overstates — non-standard SMTP ports (26, 2526) bypass | Softened CHANGELOG / reference doc language; ports beyond the floor are not closed |
| consistency | `tools/pasta/README.md` whole file still claims nft is required | Full rewrite — drops every nft reference; describes `-T/-U` mechanism |
| consistency | `sandbox.conf` modes block (lines 121-129) still says "v1.0 ships the config surface but the bwrap+pasta+nftables integration is v1.1 work" | Rewrote: pasta-only design, no nftables, enforcement live by default |
| consistency | `sandbox.conf` hostname-removal note says "nftables filters L3/L4" | Replaced with "pasta's port-exclusion layer" |
| consistency | `docs/admin/hardening.md` Section 4 opens "current sandbox shares the host network stack ... unrestricted outbound" | Added "What's in-baseline (v1.1)" paragraph naming the in-tree filter as the v1.1 baseline + framing Options A/B/C as additive layers |
| doc-clarity | Two stacked Modes tables in network-filter.md (lines 44-67) | Merged into one |
| doc-clarity | Stale "nft" / "nftables" references at network-filter.md:186, 392, 478-479 | All replaced with "pasta's port-exclusion layer" |
| doc-clarity | configure.md column header "Enforced at netfilter?" | Renamed to "Enforced?"; rows reordered enforced-first |
| ux-onboarding | `docs/index.md` doesn't mention the network filter at all (silent enforcement flip) | Added a "[Network filter]" bullet under "Where to go from here" with the upgrade note + Known Limitations link |
| ux-onboarding | configure.md pattern table — unenforced rows visually identical to enforced rows | Reordered enforced-first; relabeled column to "Enforced?"; "Notes" column makes the no-op semantic explicit; cross-link to Known Limitations on the widen-cell |
| ux-onboarding | CHANGELOG enforcement-flip buried mid-entry | Lifted to a `### ⚠ Behaviour change` sub-header immediately under the v1.1 entry title |

### Deferred SHOULD findings (will not address in this PR)

- security: `--map-host-loopback` future-proofing — "empty loopback is defense-in-depth only" — needs code re-architecture; tracked separately.
- security: prior-art citations for Anthropic sandbox-runtime / OpenAI Codex CLI — sourced from public statements; no linkable code yet.
- hpc-operator: startup banner naming the v1.0→v1.1 silent flip — code change, defer.
- hpc-operator: tested managed-proxy `sandbox.conf` snippet — out of v1.1 scope (explicitly named as v1.2 work).
- ux-onboarding: site-specific CIDR placeholder `<your-campus-cidr>` was already applied (sandbox.conf).
- consistency: `docs/troubleshooting.md` no network-filter content — defer to a docs-only follow-up; CHANGELOG carries the upgrade note.

### Disagreements / nits judged moot
- doc-clarity NIT on em-dash anchor `#mitigation--managed-egress-proxy-with-sni-allowlist`: MkDocs/material renders the em-dash differently across versions; cross-link relies on the section's auto-id and currently resolves. Verify on the live docs site if it breaks.
- security NIT on "L4-and-up" vs. "L6/L7" taxonomy: replaced with "above L4 (TLS handshake / application)".

## Round 2 — output

_(filled in after round-2 expert pool)_

## Convergence note

_(filled in at end)_
