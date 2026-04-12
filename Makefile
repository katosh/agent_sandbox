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

INSTALL  := install
SRC_DIR  := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

VERSION  := $(shell cat $(SRC_DIR)/VERSION 2>/dev/null || echo 0.0.0)

# ── File lists ──────────────────────────────────────────────────

CORE_SCRIPTS := sandbox-exec.sh sandbox-lib.sh sandbox-tmux.conf VERSION

# Deprecated but still referenced by some setups
COMPAT_SCRIPTS := sbatch-sandbox.sh srun-sandbox.sh

TEST_SCRIPTS := test.sh test-admin.sh test-lab.sh

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
	@echo "  make install-conf     Create default sandbox.conf (won't overwrite)"
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
	@echo "  make install-conf     Create ~/.config/agent-sandbox/sandbox.conf"
	@echo "  agent-sandbox -- claude"

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
	for f in $(SRC_DIR)/chaperon/handlers/*.sh; do $(INSTALL) -m 644 "$$f" $(DESTDIR)$(LIBDIR)/chaperon/handlers/; done
	chmod +x $(DESTDIR)$(LIBDIR)/chaperon/handlers/*.sh
	chmod -x $(DESTDIR)$(LIBDIR)/chaperon/handlers/_handler_lib.sh
	for f in $(SRC_DIR)/chaperon/stubs/*; do $(INSTALL) -m 755 "$$f" $(DESTDIR)$(LIBDIR)/chaperon/stubs/; done
	chmod -x $(DESTDIR)$(LIBDIR)/chaperon/stubs/_stub_lib.sh
	@# Default config template (for users to copy)
	$(INSTALL) -m 644 $(SRC_DIR)/sandbox.conf $(DESTDIR)$(LIBDIR)/sandbox.conf
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
