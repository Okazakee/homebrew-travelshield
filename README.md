# TravelShield

TPM2 LUKS travel mode manager. Toggles TPM auto-unlock on LUKS-encrypted root filesystems so your passphrase is required at boot while traveling.

**systemd-cryptenroll** • **clevis-luks** • **PCR7 fingerprinting** • **Distro-agnostic**

---

## Why

TPM2 auto-unlock is convenient at home. When traveling, that same convenience is a liability. Anyone who powers on your machine gets straight to the desktop.

TravelShield lets you temporarily wipe the TPM slot so only your LUKS passphrase can decrypt the disk. Re-enroll it when you are back.

[Background reading: Unlocking LUKS2 volumes with TPM2, FIDO2, PKCS#11 security hardware on systemd >= 248](https://0pointer.net/blog/unlocking-luks2-volumes-with-tpm2-fido2-pkcs11-security-hardware-on-systemd-248.html)

---

## Travel Mode States

### ARMED
- TPM slot wiped
- Passphrase required at boot

### DISARMED
- TPM slot enrolled
- Auto-unlock via TPM2

---

## Quick Start

```bash
sudo travelshield
```

---

## Installation

### Homebrew (Linuxbrew)
```bash
brew tap Okazakee/travelshield
brew install travelshield
```

### Direct Download
```bash
curl -O https://raw.githubusercontent.com/Okazakee/homebrew-travelshield/main/travelshield.sh
chmod +x travelshield.sh
sudo ./travelshield.sh
```

---

## Requirements

- Linux host with TPM 2.0 (`/dev/tpm0` or `/dev/tpmrm0`)
- LUKS-encrypted root filesystem
- `systemd-cryptenroll` (built into systemd >= 248) or `clevis-luks` + `tpm2-tools`
- Standard util-linux tools: `lsblk`, `findmnt`, `blkid`, `cryptsetup`

---

## How It Works

1. Detects your TPM2 backend
2. Locates the LUKS root device via `lsblk` and `findmnt`
3. Checks for an existing TPM token slot on the LUKS header
4. Compares current PCR7 hash against stored fingerprint
5. Wipes or enrolls the TPM slot
6. Suggests the correct initramfs rebuild command for your distro

State is stored in `/var/lib/travelshield/pcr7.sha256`.

---

## License

Released under [The Unlicense](https://unlicense.org/).

**Source & Issues:** [github.com/Okazakee/homebrew-travelshield](https://github.com/Okazakee/homebrew-travelshield)
