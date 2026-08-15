# Homebrew formula for TravelShield
class Travelshield < Formula
  desc "Single-key TUI to toggle TPM2 LUKS auto-unlock — arm your disk for the road"
  homepage "https://github.com/Okazakee/homebrew-travelshield"
  url "https://github.com/Okazakee/homebrew-travelshield/archive/refs/tags/v2.0.4.tar.gz"
  sha256 "46e5283350b2ccd5726ab5c3a4d2f3b1aaeb56432e2012dd91e25aac17569371"

  license "Unlicense"

  depends_on "jq"

  head "https://github.com/Okazakee/homebrew-travelshield.git", branch: "main"

  def install
    bin.install "travelshield.sh" => "travelshield"
  end

  def caveats
    <<~EOS
      TravelShield requires a TPM2 LUKS unlock backend:
        - systemd-cryptenroll (built into systemd >= 248) — recommended
        - clevis-luks + tpm2-tools

      Optional: tpm2-tools for PCR7 fingerprint verification.
        Arch/CachyOS:  sudo pacman -S tpm2-tools
        Debian/Ubuntu: sudo apt install tpm2-tools
        Fedora/RHEL:   sudo dnf install tpm2-tools

      After toggling travel mode, rebuild your initramfs before rebooting.
      Run with: sudo travelshield
    EOS
  end

  test do
    assert_match "TravelShield", shell_output("#{bin}/travelshield --version")
  end
end
