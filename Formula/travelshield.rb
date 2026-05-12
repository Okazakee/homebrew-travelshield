# Homebrew formula for TravelShield
class Travelshield < Formula
  desc "Single-key TUI to toggle TPM2 LUKS auto-unlock — arm your disk for the road"
  homepage "https://github.com/Okazakee/homebrew-travelshield"
  url "https://github.com/Okazakee/homebrew-travelshield/archive/refs/tags/v2.0.0.tar.gz"
  sha256 "16c2d458bf77ce99c1bc62b173e508791240e86a4e6afa4e01a4ab8e3b2d8f13"

  head "https://github.com/Okazakee/homebrew-travelshield.git", branch: "main"
  license "Unlicense"

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
    system "#{bin}/travelshield", "--help" rescue false
  end
end
