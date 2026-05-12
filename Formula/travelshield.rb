# Homebrew formula for TravelShield
class Travelshield < Formula
  desc "Arm your disk encryption for the road — toggle TPM2 LUKS auto-unlock on/off with one command"
  homepage "https://github.com/Okazakee/homebrew-travelshield"
  url "https://github.com/Okazakee/homebrew-travelshield/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "e68006813c2835b772deac9fefb5e94a94be27c6d62fc3b41b1ece7427ca85a9"
  license "Unlicense"

  def install
    bin.install "travelshield.sh" => "travelshield"
  end

  def caveats
    <<~EOS
      System dependencies required (install before use):

        Debian/Ubuntu:  sudo apt install tpm2-tools cryptsetup-bin
        Fedora/RHEL:    sudo dnf install tpm2-tools cryptsetup
        Arch:           sudo pacman -S tpm2-tools cryptsetup

      Additionally, one of these TPM2 LUKS unlock backends is required:
        - systemd-cryptenroll (built into systemd >= 248)
        - clevis-luks + tpm2-tools

      If the travelshield command is not found, add Homebrew to your PATH:
        echo 'eval "$(#{HOMEBREW_PREFIX}/bin/brew shellenv)"' >> ~/.bashrc

      After toggling travel mode, rebuild your initramfs before rebooting.
      Run with: sudo travelshield
    EOS
  end

  test do
    system "#{bin}/travelshield", "--help" rescue false
  end
end
