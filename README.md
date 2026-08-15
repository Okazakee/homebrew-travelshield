# TravelShield

TPM2 LUKS travel mode manager. Toggles TPM auto-unlock on LUKS-encrypted root filesystems so your passphrase is required at boot while traveling.

**systemd-cryptenroll** • **clevis-luks** • **PCR7-sealed bindings** • **Distro-agnostic**

---

## Why

TPM2 auto-unlock is convenient at home. When traveling, that same convenience is a liability. Anyone who powers on your machine gets straight to the desktop.

TravelShield lets you temporarily remove the TPM bindings so only your LUKS passphrase can decrypt the disk. Re-enroll them when you are back.

[Background reading: Unlocking LUKS2 volumes with TPM2, FIDO2, PKCS#11 security hardware on systemd >= 248](https://0pointer.net/blog/unlocking-luks2-volumes-with-tpm2-fido2-pkcs11-security-hardware-on-systemd-248.html)

---

## Travel Mode States

TravelShield inspects the actual LUKS2 header (tokens + keyslots) and reports one of:

### ARMED
- A fresh header inspection verified that **no supported TPM2 auto-unlock binding remains** — no `systemd-tpm2` token and no top-level Clevis `tpm2` binding.
- If a non-TPM automatic unlocker is still configured (e.g. a Clevis `tang` binding), the UI says `ARMED (TPM)` and warns that a passphrase may still not be required.
- ARMED is **never** derived from a PCR state, a missing cache file, a command failure, or an attempted removal.

### DISARMED
- At least one supported TPM2 auto-unlock binding is present and active.

### STALE
- A TPM binding is present, but the stored PCR7 diagnostic differs from the current value (e.g. after a firmware/BIOS update).
- The binding is **still present** and may still auto-unlock — STALE is never treated as "token absent". Re-enroll to restore a matching binding.

### UNKNOWN
- The header cannot be inspected or classified safely (inspection failure, LUKS1 volume, missing `jq`, ambiguous/composite Clevis policies, inconsistent token/keyslot metadata).
- TravelShield refuses to toggle and never reports ARMED from an unknown state.

### ERROR
- The last destructive or enrollment operation failed or was only partially applied. The residual state is shown; ARMED is never reported after a failed operation.

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
- LUKS2-encrypted root filesystem (LUKS1 is not supported — state is reported as UNKNOWN)
- `systemd-cryptenroll` (built into systemd >= 248) or `clevis-luks` + `tpm2-tools`
- `jq` (required to parse LUKS2 header metadata)
- Standard util-linux tools: `lsblk`, `findmnt`, `blkid`, `cryptsetup`

---

## How It Works

1. Locates the LUKS root device via `lsblk` and `findmnt`
2. Inspects the LUKS2 header JSON metadata (`cryptsetup luksDump --dump-json-metadata`)
3. Enumerates **all** supported TPM2 auto-unlock mechanisms — `systemd-tpm2` tokens and Clevis `tpm2` bindings — independently of which backend binary is installed
4. Cross-checks Clevis bindings with `clevis luks list` (slot-oriented, no substring matching)
5. Classifies ARMED / DISARMED / STALE / UNKNOWN / ERROR from the actual header
6. Arming removes **every** supported TPM binding (all systemd slots, every Clevis tpm2 slot) and re-inspects the header before reporting ARMED
7. Enrollment seals the new binding to **PCR7 (sha256 bank)** — never an empty Clevis policy
8. Suggests the correct initramfs rebuild command for your distro

---

## Security Model

### Clevis bindings are sealed to PCR7
Since v2.0.3, Clevis enrollment uses an explicit TPM policy:

```json
{"pcr_bank":"sha256","pcr_ids":"7"}
```

The TPM policy — not the fingerprint file — is the cryptographic control. The stored PCR7 fingerprint in `/var/lib/travelshield/pcr7-<uuid>.sha256` is a **diagnostic only**: it never authorizes state, and a mismatch never makes a binding "disappear".

### PCR7 and Secure Boot
PCR7 is associated with Secure Boot state, policy and certificates. It does **not** uniquely identify one particular signed boot image — multiple Secure Boot-approved images can have compatible/related measured states depending on platform behavior. Do not over-rely on PCR7 as a tamper guarantee.

### v2.0.2 Clevis bindings are insecure
Versions <= 2.0.2 bound Clevis with an empty `{}` config, which creates **no PCR policy at all** — the binding was unsealed to a plain TPM key. If you enrolled with an old version:

- Re-enroll with v2.0.3 (`R` in the TUI) to replace the old binding with a PCR7-sealed one.
- Or arm travel mode (`T`) to remove it.
- TravelShield detects legacy `{}` bindings and warns; it never treats them as PCR7-bound.

### Recovery safety
Before removing TPM bindings, TravelShield checks that at least one LUKS keyslot **not referenced by any token** survives, and refuses removal if none does. A surviving keyslot is **structural evidence only** — TravelShield cannot prove you know its passphrase or recovery secret. Verify your recovery material before arming. After the check, a typed confirmation (`ARM`) is required.

### Unmanaged automatic unlockers
Non-TPM automatic unlockers (Clevis `tang`, `sss` without TPM, other token types) are reported but never removed. If one is present, TravelShield does not claim "passphrase required".

---

## License

Released under [The Unlicense](https://unlicense.org/).

**Source & Issues:** [github.com/Okazakee/homebrew-travelshield](https://github.com/Okazakee/homebrew-travelshield)
