#!/usr/bin/env bash
# =============================================================================
# TravelShield - TPM2 LUKS Travel Mode Manager
# Enhanced version with PCR fingerprinting and TUI menu
# =============================================================================
# Source: https://github.com/Okazakee/travelshield

set -euo pipefail

# ── Colors (using printf for portability) ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_info()    { printf "${BLUE}[INFO]${NC} %s\n" "$1"; }
print_success() { printf "${GREEN}[SUCCESS]${NC} %s\n" "$1"; }
print_warning() { printf "${YELLOW}[WARNING]${NC} %s\n" "$1"; }
print_error()   { printf "${RED}[ERROR]${NC} %s\n" "$1" >&2; }
print_prompt()  { printf "${CYAN}%s${NC} " "$1"; }

# ── Global state ──
INIT_SYSTEM=""       # "systemd" or "clevis"
CHECK_TPM_FN=""
ENABLE_FN=""
DISABLE_FN=""
LUKS_DEVICE=""
RAW_LUKS_DEVICE=""
STATE_DIR="/var/lib/travelshield"
PCR_FILE="${STATE_DIR}/pcr7.sha256"

# ── Early sudo credential caching ──
sudo -v 2>/dev/null || true

# ─────────────────────────────
# TPM / tool detection
# ─────────────────────────────
detect_tpm_toolchain() {
    if command -v systemd-cryptenroll &>/dev/null; then
        echo "systemd"
    elif command -v clevis &>/dev/null && command -v tpm2_createprimary &>/dev/null; then
        echo "clevis"
    else
        echo "none"
    fi
}

# ─────────────────────────────
# LUKS device discovery (focus on root)
# ─────────────────────────────
detect_luks_device() {
    # 1. /etc/crypttab entry with mountpoint /
    if [[ -f /etc/crypttab ]]; then
        while read -r mapper device _; do
            [[ "$device" =~ ^/dev ]] || continue
            local mp
            mp=$(findmnt -nr -o TARGET "/dev/mapper/$mapper" 2>/dev/null | head -1)
            if [[ "$mp" == "/" ]]; then
                echo "/dev/mapper/$mapper"
                return
            fi
        done < /etc/crypttab
    fi

    # 2. Work backwards from root mount
    local root_src
    root_src=$(findmnt -n -o SOURCE / 2>/dev/null)
    if [[ -n "$root_src" ]]; then
        # If it's a dm-crypt device (mapper or dm-X)
        if [[ "$root_src" == /dev/mapper/* ]] || [[ "$root_src" == /dev/dm-* ]]; then
            echo "$root_src"
            return
        fi
    fi

    # 3. fallback: blkid scan for crypto_LUKS (avoid if possible)
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
    tpm2_pcrread sha256:7 2>/dev/null | awk '{print $2}'
}

store_pcr_fingerprint() {
    sudo mkdir -p "$STATE_DIR"
    get_current_pcr7 | sudo tee "$PCR_FILE" >/dev/null
    print_success "PCR7 fingerprint stored."
}

clear_pcr_fingerprint() {
    sudo rm -f "$PCR_FILE"
}

# ─────────────────────────────
# systemd‑cryptenroll functions
# ─────────────────────────────
check_tpm_status_systemd() {
    if sudo cryptsetup luksDump "$RAW_LUKS_DEVICE" 2>/dev/null | grep -q "systemd-tpm2"; then
        # Token slot present – check fingerprint
        local current_pcr stored_pcr
        current_pcr=$(get_current_pcr7)
        if ! stored_pcr=$(sudo cat "$PCR_FILE" 2>/dev/null); then
            print_warning "No stored PCR fingerprint – assuming token valid."
            return 0
        fi
        if [[ "$current_pcr" == "$stored_pcr" ]]; then
            return 0
        else
            print_warning "PCR7 mismatch! Token likely stale (e.g., firmware update)."
            return 1
        fi
    else
        return 1
    fi
}

enable_auto_unlock_systemd() {
    print_info "Enrolling TPM2 token with systemd-cryptenroll..."
    sudo systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 "$RAW_LUKS_DEVICE"
    store_pcr_fingerprint
    print_success "Travel mode OFF – auto-unlock enabled."
}

disable_auto_unlock_systemd() {
    print_info "Wiping TPM2 token with systemd-cryptenroll..."
    sudo systemd-cryptenroll --wipe-slot=tpm2 "$RAW_LUKS_DEVICE"
    clear_pcr_fingerprint
    print_success "Travel mode ON – passphrase required."
}

# ─────────────────────────────
# Clevis functions
# ─────────────────────────────
check_tpm_status_clevis() {
    if sudo cryptsetup luksDump "$RAW_LUKS_DEVICE" 2>/dev/null | grep -q "clevis"; then
        local current_pcr stored_pcr
        current_pcr=$(get_current_pcr7)
        if ! stored_pcr=$(sudo cat "$PCR_FILE" 2>/dev/null); then
            print_warning "No stored PCR fingerprint – assuming token valid."
            return 0
        fi
        if [[ "$current_pcr" == "$stored_pcr" ]]; then
            return 0
        else
            print_warning "PCR7 mismatch! Token likely stale."
            return 1
        fi
    else
        return 1
    fi
}

enable_auto_unlock_clevis() {
    print_info "Binding Clevis TPM2 policy..."
    sudo clevis luks bind -d "$RAW_LUKS_DEVICE" tpm2 '{}'
    store_pcr_fingerprint
    print_success "Travel mode OFF – auto-unlock enabled."
}

disable_auto_unlock_clevis() {
    print_info "Unbinding Clevis policy..."
    local slot
    slot=$(sudo clevis luks list -d "$RAW_LUKS_DEVICE" 2>/dev/null | awk -F: '/tpm2/{print $1; exit}')
    if [[ -z "$slot" ]]; then
        print_error "No Clevis tpm2 slot found."
        exit 1
    fi
    sudo clevis luks unbind -d "$RAW_LUKS_DEVICE" -s "$slot"
    clear_pcr_fingerprint
    print_success "Travel mode ON – passphrase required."
}

# ─────────────────────────────
# Initramfs suggestion
# ─────────────────────────────
suggest_initramfs_rebuild() {
    echo
    print_info "Remember to rebuild your initramfs for changes to take effect:"
    if command -v dracut &>/dev/null; then
        print_info "  sudo dracut --force"
    elif command -v mkinitcpio &>/dev/null; then
        print_info "  sudo mkinitcpio -P"
    elif command -v update-initramfs &>/dev/null; then
        print_info "  sudo update-initramfs -u -k all"
    else
        print_warning "Could not detect initramfs tool. Please rebuild manually."
    fi
}

# ─────────────────────────────
# Detailed status
# ─────────────────────────────
show_detailed_status() {
    echo
    echo "LUKS device      : $LUKS_DEVICE"
    echo "Raw device       : $RAW_LUKS_DEVICE"
    echo "Toolchain        : $INIT_SYSTEM"
    echo "PCR7 current     : $(get_current_pcr7)"
    if [[ -f "$PCR_FILE" ]]; then
        echo "PCR7 stored      : $(sudo cat "$PCR_FILE")"
    else
        echo "PCR7 stored      : none"
    fi
    if sudo cryptsetup isLuks "$RAW_LUKS_DEVICE" 2>/dev/null; then
        sudo cryptsetup luksDump "$RAW_LUKS_DEVICE" 2>/dev/null | grep -E "^\s+(Key Slot|Token|tpm2|clevis)" || echo "No relevant slots/tokens visible."
    fi
    echo
    read -rp "Press Enter to return to menu..."
}

# ─────────────────────────────
# Toggle logic
# ─────────────────────────────
toggle_travel_mode() {
    if $CHECK_TPM_FN; then
        printf "\nCurrent state: ${GREEN}Travel mode OFF${NC} (auto-unlock should work)\n"
        read -rp "Enable travel mode (disable auto-unlock)? (y/N): " choice
        if [[ "$choice" == y || "$choice" == Y ]]; then
            $DISABLE_FN
            suggest_initramfs_rebuild
        else
            print_info "No changes made."
        fi
    else
        printf "\nCurrent state: ${RED}Travel mode ON${NC} (passphrase required)\n"
        read -rp "Disable travel mode (enable auto-unlock)? (y/N): " choice
        if [[ "$choice" == y || "$choice" == Y ]]; then
            $ENABLE_FN
            suggest_initramfs_rebuild
        else
            print_info "No changes made."
        fi
    fi
}

# ─────────────────────────────
# Re‑enroll binding
# ─────────────────────────────
reenroll_binding() {
    print_info "Re‑enrolling TPM binding..."
    if $CHECK_TPM_FN; then
        $DISABLE_FN
        sleep 1
    fi
    $ENABLE_FN
    suggest_initramfs_rebuild
}

# ─────────────────────────────
# TUI menu
# ─────────────────────────────
show_menu() {
    while true; do
        # Determine status line
        local status_line
        if $CHECK_TPM_FN; then
            status_line="Travel mode OFF (auto-unlock expected)"
        else
            status_line="Travel mode ON (passphrase required)"
        fi

        clear
        printf "${BLUE}╔══════════════════════════════════════╗${NC}\n"
        printf "${BLUE}║${NC}  ${YELLOW}TravelShield${NC} – TPM2 LUKS Travel Mode  ${BLUE}║${NC}\n"
        printf "${BLUE}╚══════════════════════════════════════╝${NC}\n"
        printf "  LUKS device : ${YELLOW}%s${NC}\n" "$LUKS_DEVICE"
        printf "  Status      : %s\n" "$status_line"
        printf "  Tooling     : ${YELLOW}%s${NC}\n" "$INIT_SYSTEM"
        echo
        echo "1) Toggle travel mode"
        echo "2) Re‑enroll TPM binding (fix broken binding)"
        echo "3) Show detailed status"
        echo "4) Exit"
        echo
        read -rp "Choose an option [1-4]: " opt
        case "$opt" in
            1) toggle_travel_mode ;;
            2) reenroll_binding ;;
            3) show_detailed_status ;;
            4) exit 0 ;;
            *) print_error "Invalid option."; sleep 1 ;;
        esac
        echo
        read -rp "Press Enter to continue..."
    done
}

# ─────────────────────────────
# Main entry point
# ─────────────────────────────
main() {
    print_info "TravelShield – TPM2 LUKS Travel Mode Manager"
    echo

    # Detect toolchain
    INIT_SYSTEM=$(detect_tpm_toolchain)
    case "$INIT_SYSTEM" in
        systemd)
            print_success "Detected systemd-cryptenroll"
            CHECK_TPM_FN="check_tpm_status_systemd"
            ENABLE_FN="enable_auto_unlock_systemd"
            DISABLE_FN="disable_auto_unlock_systemd"
            ;;
        clevis)
            print_success "Detected clevis + tpm2-tools"
            CHECK_TPM_FN="check_tpm_status_clevis"
            ENABLE_FN="enable_auto_unlock_clevis"
            DISABLE_FN="disable_auto_unlock_clevis"
            ;;
        none)
            print_error "No supported TPM2 management tools found."
            print_info "Install systemd-cryptenroll or clevis-luks + tpm2-tools."
            exit 1
            ;;
    esac

    # Check TPM presence
    if ! [[ -e /dev/tpm0 ]] || ! sudo tpm2_getcap properties-fixed &>/dev/null; then
        print_error "No TPM2 device detected or accessible."
        exit 1
    fi

    # Find LUKS device
    LUKS_DEVICE=$(detect_luks_device)
    if [[ -z "$LUKS_DEVICE" ]]; then
        print_error "No LUKS device found for the root filesystem."
        exit 1
    fi

    # Resolve raw device if it's a mapper
    if [[ "$LUKS_DEVICE" == /dev/mapper/* ]]; then
        RAW_LUKS_DEVICE=$(sudo cryptsetup status "$LUKS_DEVICE" 2>/dev/null | awk '/device:/ {print $2}')
        if [[ -z "$RAW_LUKS_DEVICE" ]]; then
            print_error "Could not resolve underlying device for $LUKS_DEVICE"
            exit 1
        fi
    else
        RAW_LUKS_DEVICE="$LUKS_DEVICE"
    fi

    # Safety: ensure RAW_LUKS_DEVICE is not mounted directly
    if findmnt -n "$RAW_LUKS_DEVICE" &>/dev/null; then
        print_error "Raw device $RAW_LUKS_DEVICE is mounted. Unmount it first."
        exit 1
    fi

    # Verify it's LUKS
    if ! sudo cryptsetup isLuks "$RAW_LUKS_DEVICE" 2>/dev/null; then
        print_error "$RAW_LUKS_DEVICE is not a LUKS device."
        exit 1
    fi

    print_info "Using LUKS device: $LUKS_DEVICE"
    print_info "Underlying device: $RAW_LUKS_DEVICE"
    echo

    # Launch menu
    show_menu
}

main "$@"
