# Homebrew formula for TravelShield
class Travelshield < Formula
  desc "Single-key TUI to toggle TPM2 LUKS auto-unlock — arm your disk for the road"
  homepage "https://github.com/Okazakee/homebrew-travelshield"
  url "https://github.com/Okazakee/homebrew-travelshield/archive/refs/tags/v2.0.1.tar.gz"
  sha256 "83c8be8722795ed28b5f0ac7367248487400c3548fa19e08990fbb0e99ac9d7c"

  license "Unlicense"

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
    output = shell_output("#{bin}/travelshield 2>&1", 1)
    assert_match "TravelShield", output
  end
end
