# 🛡️ TravelShield

> **TPM2 LUKS Travel Mode Manager** — Arm your disk encryption for the road. One keystroke to lock it down.

TravelShield detects whether TPM2 auto-unlock is active on your LUKS-encrypted root filesystem and lets you toggle **Travel Mode** on or off instantly — no Enter key required.

**Single-key navigation** • **PCR7 fingerprinting** • **Distro-agnostic** • **systemd-cryptenroll & clevis-luks**

---

## Why TravelShield?

TPM2 auto-unlock is convenient at home: you power on and the disk decrypts silently. But when you travel, that same convenience becomes a liability.

**Crossing a border?** Attending a conference? Leaving your laptop in a hotel room?

With the TPM slot active, anyone who powers on your machine gets straight to the desktop. TravelShield lets you temporarily **disable TPM auto-unlock** so only your LUKS passphrase can decrypt the disk. When you're back in a safe place, re-enable it with the same tool.

[Background reading: Unlocking LUKS2 volumes with TPM2, FIDO2, PKCS#11 security hardware on systemd ≥ 248](https://0pointer.net/blog/unlocking-luks2-volumes-with-tpm2-fido2-pkcs11-security-hardware-on-systemd-248.html)

---

## Travel Mode States

### 🔴 [ARMED] — ON
- TPM slot wiped
- Passphrase required at boot
- Safe for border crossings, transit, shared spaces

### 🟢 [DISARMED] — OFF
- TPM slot enrolled
- Auto-unlock via TPM2
- Convenient at home or in a trusted environment

---

## Quick Start

```bash
sudo travelshield
```

The script auto-detects your backend, locates your root LUKS device, and drops you into an interactive menu:

```
╔══════════════════════════════════════════════╗
║  TravelShield   TPM2 LUKS Manager            ║
╠══════════════════════════════════════════════╣
║  Device : luks-abc123                        ║
║  Status : ARMED — passphrase required        ║
║  Backend: systemd-cryptenroll                ║
╠══════════════════════════════════════════════╣
║  [T] Toggle travel mode                      ║
║  [R] Re-enroll TPM binding                   ║
║  [S] Show detailed status                    ║
║  [Q] Quit                                    ║
╚══════════════════════════════════════════════╝
> 
```

---

## Installation

### 📦 Homebrew (Linuxbrew)
```bash
brew tap Okazakee/travelshield
brew install travelshield
```

### 📥 Direct Download
```bash
curl -O https://raw.githubusercontent.com/Okazakee/homebrew-travelshield/main/travelshield.sh
chmod +x travelshield.sh
sudo ./travelshield.sh
```

---

## Requirements

- Linux host with TPM 2.0 (`/dev/tpm0` or `/dev/tpmrm0`)
- LUKS-encrypted root filesystem
- One of:
  - `systemd-cryptenroll` (built into systemd ≥ 248)
  - `clevis-luks` + `tpm2-tools`
- Standard util-linux tools: `lsblk`, `findmnt`, `blkid`, `cryptsetup` (pre-installed on all distros)

---

## Technical Features

**systemd-cryptenroll**
Primary backend. Uses built-in systemd ≥ 248 support to enroll or wipe TPM2 tokens on LUKS2 headers.

**clevis-luks**
Fallback backend. Supports Clevis TPM2 policy bindings for distros not on systemd 248+.

**PCR7 Fingerprinting**
Stores a SHA-256 hash of PCR7 after enrollment. Detects stale bindings after BIOS or firmware updates.

**Initramfs Reminder**
Auto-detects mkinitcpio, dracut, or update-initramfs and tells you exactly what to run before rebooting.

**Distro-Agnostic Discovery**
Locates your root LUKS device via lsblk, findmnt, and blkid — no hardcoded paths, works across Arch, Debian, Fedora, Void, Alpine, and more.

**Single-Key TUI**
No Enter key needed. Tap T, R, S, or Q. Colored status output gives instant clarity on system state.

---

## How It Works

1. **Detects** your TPM2 backend — `systemd-cryptenroll` or `clevis-luks`.
2. **Locates** the LUKS device backing your `/` mount via `lsblk` and `findmnt` (no sudo, distro-agnostic).
3. **Verifies** TPM2 chip presence (`/dev/tpm0` or `/dev/tpmrm0`).
4. **Checks** for an existing TPM token slot on the LUKS header.
5. **Compares** the current PCR7 hash against a stored fingerprint to detect stale bindings.
6. **Toggles** the TPM slot on or off with a single keypress.
7. **Suggests** the correct `initramfs` rebuild command for your distro.

State is stored in `/var/lib/travelshield/pcr7.sha256`.

---

## License

Built with care for the paranoid. Released into the public domain under [The Unlicense](https://unlicense.org/).

**Source & Issues:** [github.com/Okazakee/homebrew-travelshield](https://github.com/Okazakee/homebrew-travelshield)
