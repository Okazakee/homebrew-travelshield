```
╔═══════════════════════════════════════════╗
║  :: TravelShield ::                      ║
║  TPM2 LUKS Travel Mode Toggle            ║
╚═══════════════════════════════════════════╝
```

# TravelShield – TPM2 LUKS Travel Mode Toggle

**Arm your disk encryption for the road. One command to lock it down.**

TravelShield detects whether TPM2 auto-unlock is active on your LUKS-encrypted root
filesystem and lets you toggle **Travel Mode** on or off with a single keystroke.

| Travel Mode ON | Travel Mode OFF |
|---|---|
| TPM slot wiped | TPM slot enrolled |
| Passphrase required | Auto-unlock via TPM2 |
| Safe for border crossings | Convenient at home |

## Why TravelShield?

Crossing a border? Attending a conference? Leaving your laptop unattended? With the
TPM slot active, anyone who powers on your machine gets straight to the desktop.
TravelShield lets you temporarily **disable TPM auto-unlock** so only your LUKS
passphrase can decrypt the disk. When you're back home, re-enable it with the same tool.

- PCR7 fingerprinting detects stale bindings (e.g. after a BIOS update) and warns you
- Works with both `systemd-cryptenroll` (systemd ≥ 248) and `clevis-luks` + `tpm2-tools`
- Remembers to tell you to rebuild your initramfs after changes

## Quick Start

```bash
sudo ./travelshield.sh
```

The script auto-detects your toolchain, locates your root LUKS device, verifies your
TPM2 chip is present, and drops you into the menu:

```
╔══════════════════════════════════════╗
║  TravelShield – TPM2 LUKS Travel Mode  ║
╚══════════════════════════════════════╝

  1) Toggle travel mode
  2) Re‑enroll TPM binding (fix broken binding)
  3) Show detailed status
  4) Exit
```

## Requirements

- Linux host with TPM 2.0 (`/dev/tpm0`)
- LUKS-encrypted root filesystem
- One of:
  - `systemd-cryptenroll` (systemd 248+)
  - `clevis-luks` + `tpm2-tools`
- `cryptsetup`, `findmnt`, `blkid` (standard on most distros)

## Install

### Direct download

```bash
curl -O https://raw.githubusercontent.com/Okazakee/homebrew-travelshield/main/travelshield.sh
chmod +x travelshield.sh
sudo ./travelshield.sh
```

### Homebrew (Linuxbrew)

```bash
brew tap Okazakee/travelshield
brew install travelshield
```

## How It Works

1. **Detects** whether you have `systemd-cryptenroll` or `clevis-luks` installed.
2. **Locates** the LUKS device backing your `/` mount via `/etc/crypttab` and `findmnt`.
3. **Verifies** TPM2 chip presence and that the raw block device isn't directly mounted.
4. **Checks** for an existing TPM token slot on the LUKS header.
5. **Compares** the current PCR7 hash against a stored fingerprint to detect stale bindings.
6. **Toggles** the TPM slot on or off depending on your choice.
7. **Suggests** the correct `initramfs` rebuild command for your distro.

State is stored in `/var/lib/travelshield/pcr7.sha256`.

## License

This is free and unencumbered software released into the public domain. See [LICENSE](LICENSE).

---

Built with care for the paranoid. [Contribute](https://github.com/Okazakee/homebrew-travelshield) or [report issues](https://github.com/Okazakee/homebrew-travelshield/issues).
