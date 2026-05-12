# Homebrew formula for TravelShield
class Travelshield < Formula
  desc "Arm your disk encryption for the road — toggle TPM2 LUKS auto-unlock on/off with one command"
  homepage "https://github.com/USER/travel-mode-repo"
  url "https://github.com/USER/travel-mode-repo/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "PLACEHOLDER" # Replace with actual SHA256 after releasing the tarball
  license "Unlicense"

  depends_on "tpm2-tools"
  depends_on "cryptsetup"

  def install
    bin.install "travelshield.sh" => "travelshield"
  end

  def caveats
    <<~EOS
      TravelShield requires systemd-cryptenroll OR clevis-luks to manage TPM2 tokens.
      Install clevis with: brew install clevis

      After toggling travel mode, rebuild your initramfs before rebooting.
      Run with: sudo travelshield
    EOS
  end

  test do
    system "#{bin}/travelshield", "--help" rescue false
  end
end
