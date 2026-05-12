```
╔══════════════════════════════════════╗
║  :: TravelShield ::                 ║
║  TPM2 LUKS Travel Mode Manager      ║
╚══════════════════════════════════════╝
```

# TravelShield – TPM2 LUKS Travel Mode Manager

**Arm your disk encryption for the road. One keystroke to lock it down.**

TravelShield detects whether TPM2 auto-unlock is active on your LUKS-encrypted root
filesystem and lets you toggle **Travel Mode** on or off instantly — no Enter key required.

| Travel Mode ON | Travel Mode OFF |
|---|---|
| `[ARMED]` — TPM slot wiped | `[DISARMED]` — TPM slot enrolled |
| Passphrase required at boot | Auto-unlock via TPM2 |
| Safe for border crossings | Convenient at home |

## Why TravelShield?

Crossing a border? Attending a conference? Leaving your laptop unattended? With the
TPM slot active, anyone who powers on your machine gets straight to the desktop.
TravelShield lets you temporarily **disable TPM auto-unlock** so only your LUKS
passphrase can decrypt the disk. When you're back home, re-enable it with the same tool.

- **Single-key navigation** — tap `T`/`R`/`S`/`Q`, no Enter needed
- **Colored status** — green `[DISARMED]` or red `[ARMED]` at a glance
- **PCR7 fingerprinting** — detects stale bindings after BIOS/firmware updates
- **Distro-agnostic** — works on Arch, Debian, Fedora, openSUSE, Void, Alpine, and more
- **Dual backend** — `systemd-cryptenroll` or `clevis-luks` + `tpm2-tools`
- **Initramfs reminder** — detects mkinitcpio, dracut, or update-initramfs and tells you what to run

## Quick Start

```bash
sudo travelshield
```

The script auto-detects your backend, locates your root LUKS device, and drops you
into the menu:

```
╔══════════════════════════════════════╗
║  TravelShield   TPM2 LUKS Manager   ║
╠══════════════════════════════════════╣
║  Device : luks-abc123               ║
║  Status : ARMED — passphrase req.   ║
║  Backend: systemd-cryptenroll       ║
╠══════════════════════════════════════╣
║  [T] Toggle travel mode             ║
║  [R] Re‑enroll TPM binding          ║
║  [S] Show detailed status           ║
║  [Q] Quit                           ║
╚══════════════════════════════════════╝
> 
```

## Requirements

- Linux host with TPM 2.0 (`/dev/tpm0` or `/dev/tpmrm0`)
- LUKS-encrypted root filesystem
- One of:
  - `systemd-cryptenroll` (built into systemd ≥ 248)
  - `clevis-luks` + `tpm2-tools`
- Standard util-linux tools: `lsblk`, `findmnt`, `blkid`, `cryptsetup` (pre-installed on all distros)

## Install

### Homebrew (Linuxbrew)

```bash
brew tap Okazakee/travelshield
brew install travelshield
```

### Direct download

```bash
curl -O https://raw.githubusercontent.com/Okazakee/homebrew-travelshield/main/travelshield.sh
chmod +x travelshield.sh
sudo ./travelshield.sh
```

## How It Works

1. **Detects** your TPM2 backend — `systemd-cryptenroll` or `clevis-luks`.
2. **Locates** the LUKS device backing your `/` mount via `lsblk` and `findmnt` (no sudo, distro-agnostic).
3. **Verifies** TPM2 chip presence (`/dev/tpm0` or `/dev/tpmrm0`).
4. **Checks** for an existing TPM token slot on the LUKS header.
5. **Compares** the current PCR7 hash against a stored fingerprint to detect stale bindings.
6. **Toggles** the TPM slot on or off with a single keypress.
7. **Suggests** the correct `initramfs` rebuild command for your distro.

State is stored in `/var/lib/travelshield/pcr7.sha256`.

## License

This is free and unencumbered software released into the public domain. See [LICENSE](LICENSE).

---

Built with care for the paranoid. [Contribute](https://github.com/Okazakee/homebrew-travelshield) or [report issues](https://github.com/Okazakee/homebrew-travelshield/issues).
