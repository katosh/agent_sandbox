#!/bin/sh
# tools/mail-block/mail-block-stub.sh — universal mailer-binary stub
#
# When NETWORK_MAIL_BLOCK is active, the sandbox launcher bind-mounts
# this script over every canonical mailer path that exists on the host
# (sendmail, mail, mailx, mutt, msmtp, …) and prepends a symlink farm
# of the same names to PATH. Any invocation of a mailer name therefore
# lands here.
#
# Behaviour: print a deterrent message to stderr addressed to the agent
# that just exec'd a mailer, then exit with EX_NOPERM (sysexits.h 77 —
# "permission denied at a higher level"). Output a sanitized record of
# the invocation so the agent can reason about what triggered the
# stub, without giving an attacker a control channel into the
# enclosing terminal (no raw argv echo — ANSI / OSC-8 / CR / NUL bytes
# in argv could otherwise rewrite the agent's screen or smuggle
# clickable URLs into logs).
#
# POSIX sh on purpose: the stub is invoked at every mailer exec; we
# avoid bash startup cost and avoid pulling bash in as a hard runtime
# dependency for the layer. No external commands beyond what
# coreutils-or-busybox guarantees.

set -u

# Canonical name we were invoked under. $0 is whichever path bash /
# the kernel followed — for a bind-mount that's `/usr/bin/sendmail`,
# for a PATH-prefix symlink that's `/run/agent-sandbox/mail-block/mail`
# (or the bare name if the shell did PATH lookup). basename collapses
# both to the leaf; sanitize the result to printable ASCII (defensive
# against a hostile $0 — argv[0] is caller-controlled).
_MB_NAME="$(basename -- "$0" 2>/dev/null || echo mailer)"
_MB_NAME="$(printf '%s' "$_MB_NAME" | LC_ALL=C tr -cd '[:graph:]' | cut -c1-64)"
[ -z "$_MB_NAME" ] && _MB_NAME="mailer"

# Argv count, not contents. Echoing the args invites terminal-control
# injection (a crafted arg containing \e[2J\e[H or OSC-8 hyperlinks
# rewrites the agent's terminal view). The count alone tells the agent
# whether this was a probe (zero args, `mail --help`) or a real send
# attempt (many args), which is enough signal without the surface.
_MB_ARGC=$#

cat >&2 <<EOF
agent-sandbox: outbound mail is disabled in this configuration.

This is a configured boundary, not a transient fault. Every known
mailer on this system — sendmail, mail, mailx, mutt, msmtp, ssmtp,
s-nail, swaks, the postfix admin tools, exim, dma, qmail — has been
shimmed by this stub. Retrying with another binary, another
invocation, or another path will produce the same result. The
companion network filter additionally blocks SMTP ports at the
namespace edge, so application-level dialers (smtplib, curl smtp://,
nc) also fail.

Agents: do not retry. This rule is enforced, not advisory; persistence
escalates the incident. If the user asked for mail behaviour, escalate
the policy to the user and propose an out-of-band channel — a written
report, a PR comment, a chat message. Do not attempt to bypass.

  Invoked as: ${_MB_NAME} (${_MB_ARGC} args; contents suppressed)
  Exit code:  77 (EX_NOPERM — sysexits.h)
  Config:     NETWORK_MAIL_BLOCK=on; see
              docs/reference/network-filter.md#outbound-mail-policy
EOF

exit 77
