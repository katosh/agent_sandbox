# Homebrew formula for agent-sandbox
#
# To publish:
#   1. Create a repo at github.com/katosh/homebrew-tools
#   2. Place this file at Formula/agent-sandbox.rb in that repo
#   3. Tag a release in the main repo: git tag -a v0.1.0 -m "Initial release" && git push --tags
#   4. Compute the sha256: curl -sL https://github.com/katosh/agent_sandbox/archive/refs/tags/v0.1.0.tar.gz | shasum -a 256
#   5. Replace PLACEHOLDER_SHA256 below with the actual hash
#
# Users install with:
#   brew tap katosh/tools
#   brew install agent-sandbox

class AgentSandbox < Formula
  desc "Kernel-enforced filesystem isolation for AI coding agents on Linux"
  homepage "https://github.com/katosh/agent_sandbox"
  url "https://github.com/katosh/agent_sandbox/releases/download/v0.5.0/agent-sandbox-0.5.0.tar.gz"
  sha256 "8238c393fb15feb0a0df1389a427a6cca1aa81f100e34ed7b797589fd8e8404e"
  license "MIT"

  depends_on :linux

  # NOTE: bubblewrap is intentionally NOT a dependency here.
  # On Ubuntu 24.04+, AppArmor restricts unprivileged user namespaces and
  # requires an AppArmor profile tied to the specific bwrap binary path.
  # A Homebrew-installed bwrap (~/.linuxbrew/bin/bwrap) would shadow a
  # working system bwrap (/usr/bin/bwrap) that already has the profile,
  # breaking what was already working.  The sandbox auto-detects the best
  # available backend (bwrap → firejail → landlock) at runtime.

  def install
    system "make", "install", "PREFIX=#{prefix}"
  end

  def caveats
    <<~EOS
      The sandbox needs at least one isolation backend.  It auto-detects
      the best available at runtime (bwrap > firejail > landlock).

      If you don't have one yet, the recommended option is bubblewrap:
        brew install bubblewrap

      Note: on Ubuntu 24.04+, a Homebrew-installed bwrap may need an
      AppArmor profile.  If bwrap fails, a system-installed bwrap
      (apt/dnf) with the profile is the simplest fix — see:
        #{share}/doc/agent-sandbox/README.md  (Troubleshooting section)

      Configure the sandbox:
        agent-sandbox bash -c 'echo sandbox works'   # auto-creates config dir
        cp #{lib}/agent-sandbox/sandbox.conf ~/.config/agent-sandbox/sandbox.conf
        $EDITOR ~/.config/agent-sandbox/sandbox.conf

      Quick start:
        cd /path/to/your/project
        agent-sandbox claude       # Claude Code, sandboxed
        agent-sandbox bash         # interactive shell
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/agent-sandbox --version")
  end
end
