# Makefile — install agent-sandbox to a standard Unix prefix
#
# Usage:
#   make install                         # → ~/.local/lib/agent-sandbox/ + ~/.local/bin/agent-sandbox
#   make install PREFIX=/usr/local       # system-wide (needs sudo)
#   make install DESTDIR=./pkg PREFIX=/usr # for distro packagers
#   make uninstall
#
# The install layout:
#   $(PREFIX)/bin/agent-sandbox            Wrapper script (entry point)
#   $(PREFIX)/lib/agent-sandbox/           Full runtime tree
#   $(PREFIX)/share/doc/agent-sandbox/     Documentation

PREFIX   ?= $(HOME)/.local
LIBDIR   := $(PREFIX)/lib/agent-sandbox
BINDIR   := $(PREFIX)/bin
DOCDIR   := $(PREFIX)/share/doc/agent-sandbox
CONFDIR  ?= $(HOME)/.config/agent-sandbox
FORCE    ?= 0

INSTALL  := install
SHA256   := $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo "shasum -a 256")
SRC_DIR  := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

VERSION  := $(shell cat $(SRC_DIR)/VERSION 2>/dev/null || echo 0.0.0)

# ── File lists ──────────────────────────────────────────────────

CORE_SCRIPTS := sandbox-exec.sh sandbox-lib.sh sandbox-tmux.conf VERSION

# Deprecated but still referenced by some setups
COMPAT_SCRIPTS := sbatch-sandbox.sh srun-sandbox.sh

TEST_SCRIPTS := test.sh test-admin.sh

BACKEND_FILES := backends/bwrap.sh \
                 backends/firejail.sh \
                 backends/landlock.sh \
                 backends/landlock-sandbox.py \
                 backends/generate-seccomp.py

DOCS := README.md CHANGELOG.md CHAPERON.md ADMIN_HARDENING.md \
        ADMIN_INSTALL.md APPTAINER_COMPARISON.md SECURITY.md LICENSE

# Agents, chaperon, bin, conf.d are copied as directory trees
# (dynamic contents, easier to handle with cp -r)

.PHONY: all install install-lib install-bin install-conf install-docs uninstall clean check version

all:
	@echo "agent-sandbox $(VERSION)"
	@echo ""
	@echo "Targets:"
	@echo "  make install          Install to PREFIX=$(PREFIX)"
	@echo "  make install-conf     Deploy sandbox.conf + agent templates (preserves edits)"
	@echo "  make uninstall        Remove installed files"
	@echo "  make check            Run the test suite"
	@echo "  make version          Print version"

version:
	@echo $(VERSION)

# ── install ─────────────────────────────────────────────────────

install: install-lib install-bin install-docs
	@echo ""
	@echo "Installed agent-sandbox $(VERSION) to $(DESTDIR)$(PREFIX)"
	@echo "  Binary:  $(DESTDIR)$(BINDIR)/agent-sandbox"
	@echo "  Library: $(DESTDIR)$(LIBDIR)/"
	@echo "  Docs:    $(DESTDIR)$(DOCDIR)/"
	@echo ""
	@echo "Next steps:"
	@echo "  make install-conf     Create sandbox.conf + deploy agent templates"
	@echo "  agent-sandbox -- claude"
	@# Hint: if lmod has a bubblewrap module, mention SANDBOX_MODULES.
	@# Source lmod init with `[ -f ] && .` to avoid sh fatal error on missing file.
	@_mod=$$(sh -c 'for f in /etc/profile.d/lmod.sh /usr/share/lmod/lmod/init/sh /app/lmod/lmod/init/sh; do [ -f "$$f" ] && . "$$f" && break; done; module spider bubblewrap 2>&1' 2>/dev/null | grep -oE 'bubblewrap/[^ ]+' | sort -V | tail -1); \
	if [ -n "$$_mod" ]; then \
		echo ""; \
		if command -v bwrap >/dev/null 2>&1; then \
			echo "  Note: bubblewrap also available via lmod: $$_mod"; \
		else \
			echo "  Tip: bubblewrap available via lmod: $$_mod"; \
		fi; \
		echo "  To use it, add to sandbox.conf:  SANDBOX_MODULES=(\"$$_mod\")"; \
	fi

install-lib:
	@# Core scripts
	$(INSTALL) -d $(DESTDIR)$(LIBDIR)
	$(INSTALL) -m 755 $(addprefix $(SRC_DIR)/,sandbox-exec.sh) $(DESTDIR)$(LIBDIR)/
	$(INSTALL) -m 644 $(addprefix $(SRC_DIR)/,sandbox-lib.sh sandbox-tmux.conf VERSION) $(DESTDIR)$(LIBDIR)/
	@# Compat wrappers
	$(INSTALL) -m 755 $(addprefix $(SRC_DIR)/,$(COMPAT_SCRIPTS)) $(DESTDIR)$(LIBDIR)/ 2>/dev/null || true
	@# Tests
	$(INSTALL) -m 755 $(addprefix $(SRC_DIR)/,$(TEST_SCRIPTS)) $(DESTDIR)$(LIBDIR)/
	@# Backends
	$(INSTALL) -d $(DESTDIR)$(LIBDIR)/backends
	$(INSTALL) -m 644 $(addprefix $(SRC_DIR)/,$(BACKEND_FILES)) $(DESTDIR)$(LIBDIR)/backends/
	chmod +x $(DESTDIR)$(LIBDIR)/backends/landlock-sandbox.py
	chmod +x $(DESTDIR)$(LIBDIR)/backends/generate-seccomp.py
	@# bin/ (PATH-shadowing stubs + utilities)
	$(INSTALL) -d $(DESTDIR)$(LIBDIR)/bin
	for f in $(SRC_DIR)/bin/*; do $(INSTALL) -m 755 "$$f" $(DESTDIR)$(LIBDIR)/bin/; done
	@# Agents
	@for agent_dir in $(SRC_DIR)/agents/*/; do \
		agent=$$(basename "$$agent_dir"); \
		$(INSTALL) -d $(DESTDIR)$(LIBDIR)/agents/$$agent; \
		for f in $$agent_dir*; do \
			[ -f "$$f" ] && $(INSTALL) -m 644 "$$f" $(DESTDIR)$(LIBDIR)/agents/$$agent/; \
		done; \
		chmod +x $(DESTDIR)$(LIBDIR)/agents/$$agent/overlay.sh 2>/dev/null || true; \
	done
	@# Top-level agent docs
	@for f in $(SRC_DIR)/agents/*.md; do \
		[ -f "$$f" ] && $(INSTALL) -m 644 "$$f" $(DESTDIR)$(LIBDIR)/agents/; \
	done
	@# Chaperon
	$(INSTALL) -d $(DESTDIR)$(LIBDIR)/chaperon/handlers
	$(INSTALL) -d $(DESTDIR)$(LIBDIR)/chaperon/stubs
	$(INSTALL) -m 755 $(SRC_DIR)/chaperon/chaperon.sh $(DESTDIR)$(LIBDIR)/chaperon/
	$(INSTALL) -m 644 $(SRC_DIR)/chaperon/protocol.sh $(DESTDIR)$(LIBDIR)/chaperon/
	$(INSTALL) -m 644 $(SRC_DIR)/chaperon/logging.sh $(DESTDIR)$(LIBDIR)/chaperon/
	@# Handler scripts (executable) and shared library (sourced, not executable)
	for f in $(SRC_DIR)/chaperon/handlers/*.sh; do \
		case "$$f" in *_handler_lib.sh) $(INSTALL) -m 644 "$$f" $(DESTDIR)$(LIBDIR)/chaperon/handlers/ ;; \
		*) $(INSTALL) -m 755 "$$f" $(DESTDIR)$(LIBDIR)/chaperon/handlers/ ;; esac; done
	@# Stub scripts (executable) and shared library (sourced, not executable)
	for f in $(SRC_DIR)/chaperon/stubs/*; do \
		case "$$f" in *_stub_lib.sh) $(INSTALL) -m 644 "$$f" $(DESTDIR)$(LIBDIR)/chaperon/stubs/ ;; \
		*) $(INSTALL) -m 755 "$$f" $(DESTDIR)$(LIBDIR)/chaperon/stubs/ ;; esac; done
	@# Config templates.
	@# sandbox.conf.template: always used as the source for user auto-init,
	@#   even if an admin replaces sandbox.conf with the admin skeleton.
	@# sandbox.conf: default config (admin may replace with sandbox-admin.conf).
	@# sandbox-admin.conf: minimal enforcement skeleton for admin installs.
	$(INSTALL) -m 644 $(SRC_DIR)/sandbox.conf $(DESTDIR)$(LIBDIR)/sandbox.conf
	$(INSTALL) -m 644 $(SRC_DIR)/sandbox.conf $(DESTDIR)$(LIBDIR)/sandbox.conf.template
	$(INSTALL) -m 644 $(SRC_DIR)/sandbox-admin.conf $(DESTDIR)$(LIBDIR)/sandbox-admin.conf
	@# Example config overrides
	$(INSTALL) -d $(DESTDIR)$(LIBDIR)/conf.d
	for f in $(SRC_DIR)/conf.d/*.conf; do [ -f "$$f" ] && $(INSTALL) -m 644 "$$f" $(DESTDIR)$(LIBDIR)/conf.d/; done || true

install-bin:
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	@printf '#!/bin/sh\n# agent-sandbox — kernel-enforced isolation for AI coding agents\nexec "$(LIBDIR)/sandbox-exec.sh" "$$@"\n' > $(DESTDIR)$(BINDIR)/agent-sandbox
	chmod 755 $(DESTDIR)$(BINDIR)/agent-sandbox

install-conf:
	@# User config — never overwrites an existing sandbox.conf
	$(INSTALL) -d $(CONFDIR)
	$(INSTALL) -d $(CONFDIR)/conf.d
	@if [ -f "$(CONFDIR)/sandbox.conf" ]; then \
		echo "sandbox.conf already exists — not overwriting"; \
		echo "  Review new options: diff $(CONFDIR)/sandbox.conf $(SRC_DIR)/sandbox.conf"; \
	else \
		$(INSTALL) -m 644 $(SRC_DIR)/sandbox.conf $(CONFDIR)/sandbox.conf; \
		echo "Created $(CONFDIR)/sandbox.conf — edit to customize permissions"; \
	fi
	@# Copy example conf.d files (don't overwrite)
	@for f in $(SRC_DIR)/conf.d/*.conf; do \
		name=$$(basename "$$f"); \
		if [ ! -f "$(CONFDIR)/conf.d/$$name" ]; then \
			$(INSTALL) -m 644 "$$f" "$(CONFDIR)/conf.d/$$name"; \
		fi; \
	done || true
	@# Deploy agent template files (agent.md, settings.json).
	@# Overwrites unmodified copies; preserves user edits (via .origin-sha256).
	@# Use FORCE=1 to overwrite regardless: make install-conf FORCE=1
	@for agent_dir in $(SRC_DIR)/agents/*/; do \
		agent=$$(basename "$$agent_dir"); \
		for f in $$agent_dir/agent.md $$agent_dir/settings.json; do \
			[ -f "$$f" ] || continue; \
			fname=$$(basename "$$f"); \
			dest="$(CONFDIR)/agents/$$agent/$$fname"; \
			sha_file="$(CONFDIR)/agents/$$agent/.$$fname.origin-sha256"; \
			src_sha=$$($(SHA256) "$$f" | cut -d' ' -f1); \
			$(INSTALL) -d "$(CONFDIR)/agents/$$agent"; \
			if [ "$(FORCE)" = "1" ] || [ ! -f "$$dest" ]; then \
				$(INSTALL) -m 644 "$$f" "$$dest"; \
				echo "$$src_sha" > "$$sha_file"; \
				echo "  Deployed agents/$$agent/$$fname"; \
			elif [ -f "$$sha_file" ]; then \
				dest_sha=$$($(SHA256) "$$dest" | cut -d' ' -f1); \
				origin_sha=$$(cat "$$sha_file"); \
				if [ "$$dest_sha" = "$$origin_sha" ]; then \
					$(INSTALL) -m 644 "$$f" "$$dest"; \
					echo "$$src_sha" > "$$sha_file"; \
					echo "  Updated agents/$$agent/$$fname"; \
				else \
					echo "  Skipped agents/$$agent/$$fname (user modified)"; \
				fi; \
			else \
				echo "  Skipped agents/$$agent/$$fname (user file, no origin hash)"; \
			fi; \
		done; \
	done

install-docs:
	$(INSTALL) -d $(DESTDIR)$(DOCDIR)
	$(INSTALL) -m 644 $(addprefix $(SRC_DIR)/,$(DOCS)) $(DESTDIR)$(DOCDIR)/

# ── uninstall ───────────────────────────────────────────────────

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/agent-sandbox
	rm -rf $(DESTDIR)$(LIBDIR)
	rm -rf $(DESTDIR)$(DOCDIR)
	@echo "Removed agent-sandbox from $(DESTDIR)$(PREFIX)"
	@echo "User config preserved: $(CONFDIR)/sandbox.conf"

# ── check ───────────────────────────────────────────────────────

check:
	@bash $(SRC_DIR)/test.sh --quick

clean:
	@echo "Nothing to build — agent-sandbox is pure shell scripts."
