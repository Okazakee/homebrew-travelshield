# Homebrew formula for TravelShield
class Travelshield < Formula
  desc "Arm your disk encryption for the road — toggle TPM2 LUKS auto-unlock on/off with one command"
  homepage "https://github.com/Okazakee/homebrew-travelshield"
  url "https://github.com/Okazakee/homebrew-travelshield/archive/refs/tags/v1.1.0.tar.gz"
  sha256 "fea9babf3aafe746b0d48a10404f4954c2d9fb87690355f4cd6a3589928ab791"
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
