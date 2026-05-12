#!/usr/bin/env bash
# =============================================================================
# TravelShield - TPM2 LUKS Travel Mode Manager
# Single-key TUI with PCR fingerprinting — distro-agnostic
# =============================================================================
# Source: https://github.com/Okazakee/homebrew-travelshield

set -euo pipefail

# ── Colors (printf for portability) ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

print_info()    { printf "${BLUE}  ▶${NC} %s\n" "$1"; }
print_success() { printf "${GREEN}  ✔${NC} %s\n" "$1"; }
print_warning() { printf "${YELLOW}  ⚡${NC} %s\n" "$1"; }
print_error()   { printf "${RED}  ✘${NC} %s\n" "$1" >&2; }

# ── Single-key input (no Enter required) ──
read_key()     { read -n 1 -r -s -- "$@"; }
wait_any_key() { printf "\n${CYAN}  Press any key to continue...${NC}"; read -n 1 -r -s; echo; }

# ── Global state ──
TOOLCHAIN=""          # "systemd" or "clevis"
CHECK_TPM_FN=""
ENABLE_FN=""
DISABLE_FN=""
LUKS_DEVICE=""
RAW_LUKS_DEVICE=""
STATE_DIR="/var/lib/travelshield"
PCR_FILE="${STATE_DIR}/pcr7.sha256"

# ─────────────────────────────
# TPM / tool detection
# ─────────────────────────────
detect_toolchain() {
    if command -v systemd-cryptenroll &>/dev/null; then
        echo "systemd"
    elif command -v clevis &>/dev/null && command -v tpm2_createprimary &>/dev/null; then
        echo "clevis"
    else
        echo "none"
    fi
}

# ─────────────────────────────
# LUKS device discovery
# ─────────────────────────────
detect_luks_device() {
    local mapped
    mapped=$(lsblk -rno NAME,TYPE 2>/dev/null | awk '$2=="crypt"{print "/dev/mapper/"$1; exit}')
    if [[ -n "$mapped" ]]; then
        echo "$mapped"
        return
    fi

    local root_src
    root_src=$(findmnt -n -o SOURCE / 2>/dev/null)
    if [[ -n "$root_src" ]]; then
        if [[ "$root_src" == /dev/mapper/* ]] || [[ "$root_src" == /dev/dm-* ]]; then
            echo "$root_src"
            return
        fi
    fi

    local dev
    dev=$(blkid -t TYPE=crypto_LUKS -o device 2>/dev/null | head -1)
    if [[ -n "$dev" ]]; then
        echo "$dev"
        return
    fi

    echo ""
}

# ─────────────────────────────
# PCR helpers
# ─────────────────────────────
get_current_pcr7() {
    command -v tpm2_pcrread &>/dev/null || { echo "n/a"; return; }
    tpm2_pcrread sha256:7 2>/dev/null | awk '{print $2}'
}

store_pcr_fingerprint() {
    if command -v tpm2_pcrread &>/dev/null; then
        sudo mkdir -p "$STATE_DIR"
        get_current_pcr7 | sudo tee "$PCR_FILE" >/dev/null 2>&1
    fi
}

clear_pcr_fingerprint() {
    sudo rm -f "$PCR_FILE" 2>/dev/null || true
}

# ─────────────────────────────
# systemd-cryptenroll
# ─────────────────────────────
check_tpm_systemd() {
    if sudo cryptsetup luksDump "$RAW_LUKS_DEVICE" 2>/dev/null | grep -q "systemd-tpm2"; then
        local current stored
        current=$(get_current_pcr7)
        if stored=$(sudo cat "$PCR_FILE" 2>/dev/null) && [[ -n "$stored" ]]; then
            if [[ "$current" != "$stored" ]]; then
                print_warning "PCR7 mismatch — token may be stale (firmware update?)"
                return 1
            fi
        fi
        return 0
    fi
    return 1
}

enable_systemd() {
    printf "\n${BOLD}Enrolling TPM2 token...${NC}\n"
    sudo systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 "$RAW_LUKS_DEVICE"
    store_pcr_fingerprint
}

disable_systemd() {
    printf "\n${BOLD}Wiping TPM2 token...${NC}\n"
    sudo systemd-cryptenroll --wipe-slot=tpm2 "$RAW_LUKS_DEVICE"
    clear_pcr_fingerprint
}

# ─────────────────────────────
# Clevis
# ─────────────────────────────
check_tpm_clevis() {
    if sudo cryptsetup luksDump "$RAW_LUKS_DEVICE" 2>/dev/null | grep -q "clevis"; then
        local current stored
        current=$(get_current_pcr7)
        if stored=$(sudo cat "$PCR_FILE" 2>/dev/null) && [[ -n "$stored" ]]; then
            if [[ "$current" != "$stored" ]]; then
                print_warning "PCR7 mismatch — token may be stale"
                return 1
            fi
        fi
        return 0
    fi
    return 1
}

enable_clevis() {
    printf "\n${BOLD}Binding Clevis TPM2 policy...${NC}\n"
    sudo clevis luks bind -d "$RAW_LUKS_DEVICE" tpm2 '{}'
    store_pcr_fingerprint
}

disable_clevis() {
    printf "\n${BOLD}Unbinding Clevis policy...${NC}\n"
    local slot
    slot=$(sudo clevis luks list -d "$RAW_LUKS_DEVICE" 2>/dev/null | awk -F: '/tpm2/{print $1; exit}')
    if [[ -z "$slot" ]]; then
        print_error "No Clevis tpm2 slot found."
        exit 1
    fi
    sudo clevis luks unbind -d "$RAW_LUKS_DEVICE" -s "$slot"
    clear_pcr_fingerprint
}

# ─────────────────────────────
# Initramfs reminder
# ─────────────────────────────
suggest_initramfs() {
    echo
    print_info "Rebuild your initramfs before rebooting:"
    if command -v mkinitcpio &>/dev/null; then
        print_info "  sudo mkinitcpio -P"
    elif command -v dracut &>/dev/null; then
        print_info "  sudo dracut --force"
    elif command -v update-initramfs &>/dev/null; then
        print_info "  sudo update-initramfs -u -k all"
    else
        print_warning "No initramfs tool detected — rebuild manually."
    fi
}

# ─────────────────────────────
# Detailed status view
# ─────────────────────────────
show_detailed_status() {
    clear
    printf "${BLUE}╔══════════════════════════════════════════╗${NC}\n"
    printf "${BLUE}║${NC}  ${YELLOW}TravelShield${NC} — Detailed Status           ${BLUE}║${NC}\n"
    printf "${BLUE}╚══════════════════════════════════════════╝${NC}\n"
    echo
    printf "  LUKS device     : ${YELLOW}%s${NC}\n" "$LUKS_DEVICE"
    printf "  Raw device      : ${YELLOW}%s${NC}\n" "$RAW_LUKS_DEVICE"
    printf "  Backend         : ${CYAN}%s${NC}\n" "$TOOLCHAIN"
    printf "  PCR7 current    : ${CYAN}%s${NC}\n" "$(get_current_pcr7)"
    if [[ -f "$PCR_FILE" ]]; then
        printf "  PCR7 stored     : ${CYAN}%s${NC}\n" "$(sudo cat "$PCR_FILE" 2>/dev/null || echo 'unreadable')"
    else
        printf "  PCR7 stored     : ${YELLOW}none${NC}\n"
    fi
    echo
    if sudo cryptsetup isLuks "$RAW_LUKS_DEVICE" 2>/dev/null; then
        printf "${BOLD}  LUKS header slots/tokens:${NC}\n"
        local dump
        dump=$(sudo cryptsetup luksDump "$RAW_LUKS_DEVICE" 2>/dev/null)
        if echo "$dump" | grep -qE "(systemd-tpm2|clevis)"; then
            echo "$dump" | grep -E "^\s+(Key Slot|Token|tpm2|clevis)" || true
        else
            echo "  No TPM-related slots or tokens found."
        fi
    fi
    wait_any_key
}

# ─────────────────────────────
# Toggle handler
# ─────────────────────────────
toggle_travel_mode() {
    clear
    printf "${BLUE}╔══════════════════════════════════════════╗${NC}\n"
    printf "${BLUE}║${NC}  ${YELLOW}TravelShield${NC} — Toggle Travel Mode        ${BLUE}║${NC}\n"
    printf "${BLUE}╚══════════════════════════════════════════╝${NC}\n"
    echo

    if $CHECK_TPM_FN; then
        printf "  Current: ${GREEN}[DISARMED]${NC} — TPM auto-unlock active\n\n"
        printf "  ${BOLD}Enable travel mode?${NC}\n"
        printf "  This will ${RED}wipe the TPM slot${NC} — passphrase required at boot.\n\n"
        printf "  ${CYAN}[Y]${NC} Yes, arm travel mode   ${CYAN}[N]${NC} No, go back\n"
        read_key key
        if [[ "${key,,}" == "y" ]]; then
            $DISABLE_FN
            print_success "Travel mode ${RED}ARMED${NC} — passphrase required at next boot."
            suggest_initramfs
        else
            print_info "Cancelled."
        fi
    else
        printf "  Current: ${RED}[ARMED]${NC} — passphrase required at boot\n\n"
        printf "  ${BOLD}Disable travel mode?${NC}\n"
        printf "  This will ${GREEN}enroll a TPM2 token${NC} — auto-unlock at boot.\n\n"
        printf "  ${CYAN}[Y]${NC} Yes, disarm travel mode   ${CYAN}[N]${NC} No, go back\n"
        read_key key
        if [[ "${key,,}" == "y" ]]; then
            $ENABLE_FN
            print_success "Travel mode ${GREEN}DISARMED${NC} — TPM auto-unlock enabled."
            suggest_initramfs
        else
            print_info "Cancelled."
        fi
    fi
    wait_any_key
}

# ─────────────────────────────
# Re-enroll handler
# ─────────────────────────────
reenroll_binding() {
    clear
    printf "${BLUE}╔══════════════════════════════════════════╗${NC}\n"
    printf "${BLUE}║${NC}  ${YELLOW}TravelShield${NC} — Re‑enroll TPM Binding      ${BLUE}║${NC}\n"
    printf "${BLUE}╚══════════════════════════════════════════╝${NC}\n"
    echo
    printf "  This will ${YELLOW}remove and re-add${NC} the TPM binding.\n"
    printf "  Use this after a BIOS update or when the token is stale.\n\n"
    printf "  ${CYAN}[Y]${NC} Re‑enroll now   ${CYAN}[N]${NC} Go back\n"
    read_key key
    if [[ "${key,,}" != "y" ]]; then
        print_info "Cancelled."
        wait_any_key
        return
    fi

    echo
    if $CHECK_TPM_FN; then
        $DISABLE_FN
        sleep 1
    fi
    $ENABLE_FN
    suggest_initramfs
    wait_any_key
}

# ─────────────────────────────
# Main TUI menu
# ─────────────────────────────
show_menu() {
    while true; do
        local status_label status_color
        if $CHECK_TPM_FN; then
            status_label="DISARMED — TPM auto-unlock active"
            status_color="${GREEN}"
        else
            status_label="ARMED — passphrase required"
            status_color="${RED}"
        fi

        clear
        printf "${BLUE}╔══════════════════════════════════════╗${NC}\n"
        printf "${BLUE}║${NC}  ${YELLOW}TravelShield${NC}   TPM2 LUKS Manager     ${BLUE}║${NC}\n"
        printf "${BLUE}╠══════════════════════════════════════╣${NC}\n"
        printf "${BLUE}║${NC}  Device : ${CYAN}%-25s${NC} ${BLUE}║${NC}\n" "$(basename "$LUKS_DEVICE")"
        printf "${BLUE}║${NC}  Status : %s%-31s${NC} ${BLUE}║${NC}\n" "$status_color" "$status_label"
        printf "${BLUE}║${NC}  Backend: ${CYAN}%-25s${NC} ${BLUE}║${NC}\n" "$TOOLCHAIN"
        printf "${BLUE}╠══════════════════════════════════════╣${NC}\n"
        printf "${BLUE}║${NC}  ${CYAN}[T]${NC} Toggle travel mode              ${BLUE}║${NC}\n"
        printf "${BLUE}║${NC}  ${CYAN}[R]${NC} Re‑enroll TPM binding          ${BLUE}║${NC}\n"
        printf "${BLUE}║${NC}  ${CYAN}[S]${NC} Show detailed status           ${BLUE}║${NC}\n"
        printf "${BLUE}║${NC}  ${CYAN}[Q]${NC} Quit                           ${BLUE}║${NC}\n"
        printf "${BLUE}╚══════════════════════════════════════╝${NC}\n"
        printf "  ${CYAN}>${NC} "
        read_key key
        echo

        case "${key,,}" in
            t) toggle_travel_mode ;;
            r) reenroll_binding ;;
            s) show_detailed_status ;;
            q) echo; print_info "Goodbye."; exit 0 ;;
            *) ;;  # ignore invalid key, redraw menu
        esac
    done
}

# ─────────────────────────────
# Main entry point
# ─────────────────────────────
main() {
    clear
    printf "${BLUE}╔══════════════════════════════════════╗${NC}\n"
    printf "${BLUE}║${NC}  ${YELLOW}TravelShield${NC} — starting up...        ${BLUE}║${NC}\n"
    printf "${BLUE}╚══════════════════════════════════════╝${NC}\n\n"

    # ── Detect toolchain ──
    TOOLCHAIN=$(detect_toolchain)
    case "$TOOLCHAIN" in
        systemd)
            print_success "Backend: systemd-cryptenroll"
            CHECK_TPM_FN="check_tpm_systemd"
            ENABLE_FN="enable_systemd"
            DISABLE_FN="disable_systemd"
            ;;
        clevis)
            print_success "Backend: clevis + tpm2-tools"
            CHECK_TPM_FN="check_tpm_clevis"
            ENABLE_FN="enable_clevis"
            DISABLE_FN="disable_clevis"
            ;;
        none)
            print_error "No supported TPM2 backend found."
            echo
            print_info "Install one of:"
            print_info "  • systemd-cryptenroll (built into systemd ≥ 248)"
            print_info "  • clevis-luks + tpm2-tools"
            exit 1
            ;;
    esac

    # ── TPM device check ──
    if ! [[ -e /dev/tpm0 ]] && ! [[ -e /dev/tpmrm0 ]]; then
        print_error "No TPM2 device detected (/dev/tpm0 or /dev/tpmrm0)."
        exit 1
    fi
    if command -v tpm2_getcap &>/dev/null && ! sudo tpm2_getcap properties-fixed &>/dev/null 2>&1; then
        print_warning "tpm2_getcap failed — device node exists, continuing anyway."
    fi

    # ── Find LUKS device ──
    LUKS_DEVICE=$(detect_luks_device)
    if [[ -z "$LUKS_DEVICE" ]]; then
        print_error "No LUKS-encrypted root device found."
        exit 1
    fi

    # ── Resolve raw device ──
    if [[ "$LUKS_DEVICE" == /dev/mapper/* ]]; then
        RAW_LUKS_DEVICE=$(sudo cryptsetup status "$LUKS_DEVICE" 2>/dev/null | awk '/device:/ {print $2}')
        if [[ -z "$RAW_LUKS_DEVICE" ]]; then
            print_error "Could not resolve underlying device for $LUKS_DEVICE"
            exit 1
        fi
    else
        RAW_LUKS_DEVICE="$LUKS_DEVICE"
    fi

    # ── Safety checks ──
    if findmnt -n "$RAW_LUKS_DEVICE" &>/dev/null; then
        print_error "Raw device $RAW_LUKS_DEVICE is mounted — unmount first."
        exit 1
    fi

    if ! sudo cryptsetup isLuks "$RAW_LUKS_DEVICE" 2>/dev/null; then
        print_error "$RAW_LUKS_DEVICE is not a LUKS device."
        exit 1
    fi

    print_success "Device: $LUKS_DEVICE"
    sleep 0.5
    show_menu
}

main "$@"
