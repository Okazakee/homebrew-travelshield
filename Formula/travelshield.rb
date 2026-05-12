# Homebrew formula for TravelShield
class Travelshield < Formula
  desc "Arm your disk encryption for the road — toggle TPM2 LUKS auto-unlock on/off with one command"
  homepage "https://github.com/Okazakee/homebrew-travelshield"
  url "https://github.com/Okazakee/homebrew-travelshield/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "e68006813c2835b772deac9fefb5e94a94be27c6d62fc3b41b1ece7427ca85a9"
  license "Unlicense"

  depends_on "tpm2-tools"
  depends_on "cryptsetup"

  def install
    bin.install "travelshield.sh" => "travelshield"
  end

  def post_install
    brew_bin = HOMEBREW_PREFIX/"bin"
    local_bin = Pathname("/usr/local/bin")

    if local_bin.writable? && !(local_bin/"travelshield").exist?
      local_bin.mkpath
      FileUtils.ln_s brew_bin/"travelshield", local_bin/"travelshield"
    end
  rescue
    nil
  end

  def caveats
    <<~EOS
      TravelShield requires systemd-cryptenroll OR clevis-luks to manage TPM2 tokens.
      Install clevis with: brew install clevis

      If the command is not found after install, add Homebrew to your PATH:
        echo 'eval "$(#{HOMEBREW_PREFIX}/bin/brew shellenv)"' >> ~/.bashrc

      After toggling travel mode, rebuild your initramfs before rebooting.
      Run with: sudo travelshield
    EOS
  end

  test do
    system "#{bin}/travelshield", "--help" rescue false
  end
end
