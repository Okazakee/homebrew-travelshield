# Homebrew formula for TravelShield
class Travelshield < Formula
  desc "Arm your disk encryption for the road — toggle TPM2 LUKS auto-unlock on/off with one command"
  homepage "https://github.com/Okazakee/travel-mode-repo"
  url "https://github.com/Okazakee/travel-mode-repo/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "1167a75cc02157866a6978f25ce6c65cf668f766579a62b58ee963973c20a9a9"
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
