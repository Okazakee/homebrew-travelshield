#!/usr/bin/env bash
# =============================================================================
# TravelShield - TPM2 LUKS Travel Mode Manager
# Single-key TUI with strict ARMED/DISARMED/STALE/UNKNOWN/ERROR semantics
# =============================================================================
# Source: https://github.com/Okazakee/homebrew-travelshield
#
# State semantics (v2.0.3):
#   ARMED    A fresh LUKS2 header inspection proved that no supported TPM2
#            auto-unlock binding remains (no systemd-tpm2 token, no top-level
#            Clevis tpm2 binding).  ARMED is NEVER derived from a PCR state,
#            a missing cache file, a command failure, or an attempted removal.
#   DISARMED At least one supported TPM2 auto-unlock binding is present.
#   STALE    Binding(s) present, but the PCR7 diagnostic differs from the
#            stored per-volume fingerprint.  The binding is STILL PRESENT.
#   UNKNOWN  The header cannot be inspected or classified safely.
#   ERROR    The last destructive/enrollment operation failed or was partial.
#
# The stored PCR7 fingerprint is a DIAGNOSTIC ONLY.  It never authorizes
# state.  The cryptographic policy lives in the Clevis/systemd binding.

set -euo pipefail

VERSION="2.0.3"

# ── Colors (printf for portability) ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

print_info()    { printf "${BLUE}  [i]${NC} %s\n" "$1"; }
print_success() { printf "${GREEN}  [+]${NC} %s\n" "$1"; }
print_warning() { printf "${YELLOW}  [!]${NC} %s\n" "$1"; }
print_error()   { printf "${RED}  [x]${NC} %s\n" "$1" >&2; }

# Clear the screen; never fatal (clear exits 1 without a TTY, which would
# abort the whole TUI under set -e).
cls() { clear 2>/dev/null || printf '\033[2J\033[H'; }

# ── Single-key input (no Enter required) ──
read_key()     { read -n 1 -r -s -- "$@" || true; }
wait_any_key() { printf "\n${CYAN}  Press any key to continue...${NC}"; read -n 1 -r -s || true; echo; }

# ── Box drawing helpers (fixed inner width = 44) ──
BOX_W=44

# Strip ANSI escape patterns (literal \033[...m) to compute visible length
_strip_ansi() { printf '%s' "$1" | sed 's/\\033\[[0-9;]*m//g'; }

# Print a bordered row.  Text is left-aligned, padded to BOX_W.
_box_row() {
    local text="${1:-}" visible pad
    visible=$(_strip_ansi "$text")
    pad=$(( BOX_W - ${#visible} ))
    [[ $pad -lt 0 ]] && pad=0
    printf "${BLUE}║${NC} %b%*s${BLUE}║${NC}\n" "$text" "$pad" ""
}

# ── Global state ──
ENROLL_BACKEND=""         # "systemd" or "clevis" — enrollment preference only
LUKS_DEVICE=""
RAW_LUKS_DEVICE=""
STATE_DIR="${TS_STATE_DIR:-/var/lib/travelshield}"

# Inventory (populated by collect_luks_inventory)
INV_UUID=""
INV_LUKS_VERSION=""
INV_ERROR=""              # non-empty => inspection failed -> UNKNOWN
INV_JSON_RAW=""           # raw LUKS2 JSON metadata (for deep verification)
declare -A INV_KEYS_TYPE=()   # keyslot id -> type
declare -A INV_TOK_TYPE=()    # token id -> type
declare -A INV_TOK_KEYS=()    # token id -> "keyslot ids" (space-joined)
declare -A KEYS_TOKENS=()     # keyslot id -> "token ids" (reverse map)
declare -A CLEVIS_TOK_KEYS=() # clevis token id -> "keyslot ids"
INV_SYSTEMD_TOKENS=()         # token ids
INV_SYSTEMD_KEYS=()           # unique keyslot ids of systemd tokens
INV_CLEVIS_TPM2=()            # "slot|pin|policy" records
INV_CLEVIS_KEYS=()            # unique keyslot ids of clevis tpm2 bindings
INV_UNMANAGED=()              # "mechanism|detail" (non-TPM auto unlockers)
INV_AMBIGUOUS=()              # reasons blocking safe classification
INV_SURVIVORS=()              # keyslot ids referenced by no token
INV_TARGET_KEYS=()            # keyslot ids targeted for removal

# PCR diagnostic state
PCR_CURRENT=""
PCR_STORED=""
PCR_STATUS="unavailable"   # match | mismatch | unavailable
LAST_OP_ERROR=""           # set by failed operations; shown by the UI

# ─────────────────────────────
# Capability detection
# ─────────────────────────────
have() { command -v "$1" &>/dev/null; }

detect_enroll_backend() {
    if have systemd-cryptenroll; then
        echo "systemd"
    elif have clevis; then
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
# PCR7 diagnostics (never authorize state)
# ─────────────────────────────
# Parse the PCR 7 record from `tpm2_pcrread sha256:7` output:
#   sha256:
#     7 : 0x<64 hex chars>
# Sets PCR_CURRENT to the validated digest, or empty if unavailable.
get_current_pcr7() {
    PCR_CURRENT=""
    have tpm2_pcrread || return 0
    local out digest
    out=$(tpm2_pcrread sha256:7 2>/dev/null) || return 0
    digest=$(printf '%s\n' "$out" | sed -n 's/^[[:space:]]*7[[:space:]]*:[[:space:]]*0x\([0-9a-fA-F]\{64\}\).*/\1/p' | head -1)
    [[ -n "$digest" ]] || return 0
    PCR_CURRENT="$digest"
}

pcr_file() {
    [[ -n "$INV_UUID" ]] || return 1
    echo "${STATE_DIR}/pcr7-${INV_UUID}.sha256"
}

read_pcr_diagnostic() {
    PCR_CURRENT=""
    PCR_STORED=""
    PCR_STATUS="unavailable"
    local f
    f=$(pcr_file) || return 0
    get_current_pcr7
    if [[ -f "$f" ]]; then
        PCR_STORED=$(sudo cat "$f" 2>/dev/null || true)
    fi
    # A malformed stored value is diagnostic-unavailable, never a mismatch.
    if [[ -n "$PCR_STORED" ]] && ! printf '%s' "$PCR_STORED" | grep -qE '^[0-9a-fA-F]{64}$'; then
        PCR_STORED=""
    fi
    if [[ -n "$PCR_CURRENT" && -n "$PCR_STORED" ]]; then
        if [[ "$PCR_CURRENT" == "$PCR_STORED" ]]; then
            PCR_STATUS="match"
        else
            PCR_STATUS="mismatch"
        fi
    fi
}

store_pcr_diagnostic() {
    local f
    f=$(pcr_file) || return 0
    get_current_pcr7
    if [[ -z "$PCR_CURRENT" ]]; then
        print_warning "Could not read PCR7 — diagnostic not stored (state unaffected)."
        return 0
    fi
    if ! sudo mkdir -p "$STATE_DIR" 2>/dev/null; then
        print_warning "Could not create $STATE_DIR — diagnostic not stored."
        return 0
    fi
    if ! printf '%s\n' "$PCR_CURRENT" | sudo tee "$f" >/dev/null 2>&1; then
        print_warning "Could not write PCR7 diagnostic to $f."
    fi
}

clear_pcr_diagnostic() {
    local f
    f=$(pcr_file) || return 0
    sudo rm -f "$f" 2>/dev/null || print_warning "Could not remove $f."
}

# ─────────────────────────────
# LUKS2 header inventory (the sole authority)
# ─────────────────────────────
_reset_inventory() {
    INV_UUID=""
    INV_LUKS_VERSION=""
    INV_ERROR=""
    INV_JSON_RAW=""
    INV_KEYS_TYPE=()
    INV_TOK_TYPE=()
    INV_TOK_KEYS=()
    KEYS_TOKENS=()
    CLEVIS_TOK_KEYS=()
    INV_SYSTEMD_TOKENS=()
    INV_SYSTEMD_KEYS=()
    INV_CLEVIS_TPM2=()
    INV_CLEVIS_KEYS=()
    INV_UNMANAGED=()
    INV_AMBIGUOUS=()
    INV_SURVIVORS=()
    INV_TARGET_KEYS=()
}

_push_unique() { # name value — appends value to array $name if absent
    local -n arr=$1
    local v
    for v in "${arr[@]}"; do [[ "$v" == "$2" ]] && return 0; done
    arr+=("$2")
}

# Classify one Clevis tpm2 policy config: pcr7 | legacy | other | malformed
_classify_clevis_policy() {
    local cfg="$1"
    printf '%s' "$cfg" | jq -e '.pcr_bank == "sha256" and .pcr_ids == "7"' >/dev/null 2>&1 && { echo "pcr7"; return; }
    printf '%s' "$cfg" | jq -e '(.pcr_ids == null or .pcr_ids == "" or (has("pcr_ids") | not))' >/dev/null 2>&1 && { echo "legacy"; return; }
    printf '%s' "$cfg" | jq -e 'has("pcr_ids")' >/dev/null 2>&1 && { echo "other"; return; }
    echo "malformed"
}

collect_luks_inventory() {
    _reset_inventory
    [[ -n "$RAW_LUKS_DEVICE" ]] || { INV_ERROR="no LUKS device resolved"; return 1; }

    if ! have cryptsetup; then INV_ERROR="cryptsetup not found"; return 1; fi
    if ! have jq; then INV_ERROR="jq not found (required to parse LUKS2 metadata)"; return 1; fi

    local dump human ver
    dump=$(sudo cryptsetup luksDump --dump-json-metadata "$RAW_LUKS_DEVICE" 2>/dev/null) || {
        # Distinguish LUKS1 from a genuine failure.
        human=$(sudo cryptsetup luksDump "$RAW_LUKS_DEVICE" 2>/dev/null || true)
        ver=$(printf '%s\n' "$human" | sed -n 's/^Version:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
        if [[ "$ver" == "1" ]]; then
            INV_ERROR="LUKS1 volumes are not supported — cannot classify safely"
        else
            INV_ERROR="cryptsetup luksDump failed"
        fi
        return 1
    }

    if ! printf '%s' "$dump" | jq -e . >/dev/null 2>&1; then
        INV_ERROR="LUKS2 metadata is not valid JSON"
        return 1
    fi

    INV_LUKS_VERSION="2"
    INV_JSON_RAW="$dump"

    # The volume identity is required: an empty UUID would skip the lock,
    # show a blank identity in destructive confirmations, and make the
    # post-confirmation change guard useless.  Fail closed.
    INV_UUID=$(sudo cryptsetup luksUUID "$RAW_LUKS_DEVICE" 2>/dev/null || true)
    if [[ -z "$INV_UUID" ]]; then
        INV_ERROR="could not read the LUKS UUID"
        return 1
    fi

    # ── Structural schema validation (fail closed, never "no token") ──
    if ! printf '%s' "$dump" | jq -e '(.keyslots | type) == "object" and (.tokens | type) == "object"' >/dev/null 2>&1; then
        INV_ERROR="LUKS2 metadata has invalid keyslots/tokens structure"
        return 1
    fi

    # ── keyslots ──
    local id kt
    while IFS= read -r id; do
        [[ -n "$id" ]] || continue
        if ! [[ "$id" =~ ^[0-9]+$ ]]; then
            INV_ERROR="LUKS2 metadata contains a non-numeric keyslot id: $id"
            return 1
        fi
        kt=$(printf '%s' "$dump" | jq -r --arg i "$id" '.keyslots[$i].type // "unknown"' 2>/dev/null || echo unknown)
        INV_KEYS_TYPE["$id"]="$kt"
    done < <(printf '%s' "$dump" | jq -r '.keyslots | keys[]' 2>/dev/null || true)

    # ── tokens ──
    local tid ttype tkeys k
    while IFS= read -r tid; do
        [[ -n "$tid" ]] || continue
        ttype=$(printf '%s' "$dump" | jq -r --arg t "$tid" '.tokens[$t].type // ""' 2>/dev/null || true)
        if [[ -z "$ttype" ]]; then
            INV_AMBIGUOUS+=("token $tid is missing its type")
            continue
        fi
        # keyslots must be an array of numeric ids, or absent (then empty).
        if ! printf '%s' "$dump" | jq -e --arg t "$tid" '
              ((.tokens[$t] | has("keyslots")) | not) or (
                ((.tokens[$t].keyslots | type) == "array") and
                ([.tokens[$t].keyslots[] | ((type == "number") or (type == "string" and test("^[0-9]+$")))] | all)
              )' >/dev/null 2>&1; then
            INV_AMBIGUOUS+=("token $tid has a malformed keyslots field")
            continue
        fi
        tkeys=$(printf '%s' "$dump" | jq -r --arg t "$tid" '(.tokens[$t].keyslots // []) | map(tostring) | join(" ")' 2>/dev/null || true)
        INV_TOK_TYPE["$tid"]="$ttype"
        INV_TOK_KEYS["$tid"]="$tkeys"
        for k in $tkeys; do
            KEYS_TOKENS["$k"]+=" $tid"
            if [[ -z "${INV_KEYS_TYPE[$k]:-}" ]]; then
                INV_AMBIGUOUS+=("token $tid references missing keyslot $k")
            fi
        done

        case "$ttype" in
            systemd-tpm2)
                if [[ -z "$tkeys" ]]; then
                    INV_AMBIGUOUS+=("systemd-tpm2 token $tid has no keyslots")
                    continue
                fi
                INV_SYSTEMD_TOKENS+=("$tid")
                for k in $tkeys; do _push_unique INV_SYSTEMD_KEYS "$k"; done
                ;;
            systemd-fido2|systemd-pkcs11|systemd-recovery)
                _push_unique INV_UNMANAGED "$ttype|token $tid"
                ;;
            clevis)
                if [[ -z "$tkeys" ]]; then
                    INV_AMBIGUOUS+=("clevis token $tid has no keyslots")
                    continue
                fi
                CLEVIS_TOK_KEYS["$tid"]="$tkeys"
                ;;
            *)
                # An unrecognized token type cannot be classified.  Fail
                # closed instead of assuming it is not an unlocker.
                INV_AMBIGUOUS+=("unrecognized token type '$ttype' (token $tid)")
                ;;
        esac
    done < <(printf '%s' "$dump" | jq -r '.tokens | keys[]' 2>/dev/null || true)

    # ── Clevis list cross-check ──
    # Real Clevis LUKS2 tokens store the encrypted payload (`jwe`); the pin
    # and policy live ONLY in the decoded JWE, surfaced by `clevis luks
    # list`.  The list output is therefore the sole authority for pin and
    # policy.  Correlation is strict and bidirectional:
    #   - every header Clevis token keyslot MUST have a list record
    #     (clevis silently skips slots whose JWE it cannot decode), and
    #   - every list record slot MUST belong to a header Clevis token.
    # Any disagreement is ambiguous -> UNKNOWN.
    local -A listed_cfg=()   # slot -> config
    local -A listed_pin=()   # slot -> pin
    # Run the list whenever Clevis is available: real list output always
    # corresponds to real header tokens, so an orphan record (or a header
    # token missing from the list) is an inconsistency that must fail
    # closed rather than fall through to ARMED.
    if (( ${#CLEVIS_TOK_KEYS[@]} > 0 )) || have clevis; then
        if ! have clevis; then
            INV_ERROR="Clevis tokens present but clevis binary is not installed"
            return 1
        fi
        local list_out line slot pin cfg
        local clevis_pat="^([0-9]+): ([a-z0-9]+) '(.*)'$"
        list_out=$(sudo clevis luks list -d "$RAW_LUKS_DEVICE" 2>/dev/null) || {
            INV_ERROR="clevis luks list failed"
            return 1
        }
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            if [[ "$line" =~ $clevis_pat ]]; then
                slot="${BASH_REMATCH[1]}"
                pin="${BASH_REMATCH[2]}"
                cfg="${BASH_REMATCH[3]}"
                listed_pin["$slot"]="$pin"
                listed_cfg["$slot"]="$cfg"
            else
                INV_ERROR="unparseable clevis luks list output: $line"
                return 1
            fi
        done <<<"$list_out"
    fi

    # Bidirectional correlation between header Clevis tokens and list records.
    local -A header_clevis_keys=()
    local tid2 tkeys2 k2
    for tid2 in "${!CLEVIS_TOK_KEYS[@]}"; do
        tkeys2="${CLEVIS_TOK_KEYS[$tid2]}"
        for k2 in $tkeys2; do header_clevis_keys["$k2"]=1; done
    done
    for k2 in "${!header_clevis_keys[@]}"; do
        if [[ -z "${listed_pin[$k2]:-}" ]]; then
            INV_AMBIGUOUS+=("header clevis token references keyslot $k2 missing from clevis luks list")
        fi
    done
    for k2 in "${!listed_pin[@]}"; do
        if [[ -z "${header_clevis_keys[$k2]:-}" ]]; then
            INV_AMBIGUOUS+=("clevis luks list reports slot $k2 with no matching header token")
        fi
    done

    # Classify the (correlated) list records.
    local slot2 cfg2 pol
    for slot2 in "${!listed_pin[@]}"; do
        pin="${listed_pin[$slot2]}"
        cfg2="${listed_cfg[$slot2]:-}"
        case "$pin" in
            tpm2)
                pol=$(_classify_clevis_policy "$cfg2")
                INV_CLEVIS_TPM2+=("$slot2|tpm2|$pol")
                _push_unique INV_CLEVIS_KEYS "$slot2"
                ;;
            sss)
                # Composite policy.  A nested tpm2 pin is ambiguous and must
                # never be auto-removed (unbind would kill the whole
                # composite keyslot).
                if printf '%s' "$cfg2" | grep -q '"tpm2"'; then
                    INV_AMBIGUOUS+=("composite clevis sss policy contains tpm2 (slot $slot2)")
                else
                    _push_unique INV_UNMANAGED "clevis-sss|slot $slot2"
                fi
                ;;
            *)
                _push_unique INV_UNMANAGED "clevis-$pin|slot $slot2"
                ;;
        esac
    done

    # ── Survivor / target keyslots ──
    # Target = keyslots referenced by supported TPM bindings.
    for k2 in "${INV_SYSTEMD_KEYS[@]}"; do _push_unique INV_TARGET_KEYS "$k2"; done
    for k2 in "${INV_CLEVIS_KEYS[@]}"; do _push_unique INV_TARGET_KEYS "$k2"; done

    # A target keyslot referenced by more than one token is ambiguous:
    # removing it could silently break another mechanism (e.g. a shared
    # tpm2/tang keyslot).  Fail closed — UNKNOWN, never auto-removed.
    local krefs
    for k2 in "${INV_TARGET_KEYS[@]}"; do
        krefs=$(wc -w <<<"${KEYS_TOKENS[$k2]:-}")
        if (( krefs > 1 )); then
            INV_AMBIGUOUS+=("keyslot $k2 is referenced by multiple tokens")
        fi
    done

    # Survivor = keyslot referenced by NO token at all.
    local kid
    for kid in "${!INV_KEYS_TYPE[@]}"; do
        if [[ -z "${KEYS_TOKENS[$kid]:-}" ]]; then
            _push_unique INV_SURVIVORS "$kid"
        fi
    done

    return 0
}

# ─────────────────────────────
# State classification
# ─────────────────────────────
classify_inventory() {
    if [[ -n "$INV_ERROR" ]]; then echo "UNKNOWN"; return; fi
    if (( ${#INV_AMBIGUOUS[@]} > 0 )); then echo "UNKNOWN"; return; fi
    local tpm_count=$(( ${#INV_SYSTEMD_TOKENS[@]} + ${#INV_CLEVIS_TPM2[@]} ))
    if (( tpm_count == 0 )); then echo "ARMED"; return; fi
    read_pcr_diagnostic
    if [[ "$PCR_STATUS" == "mismatch" ]]; then echo "STALE"; else echo "DISARMED"; fi
}

# Machine-readable summary used by tests and the detailed view.
inventory_summary() {
    local state
    state=$(classify_inventory)
    printf 'state=%s uuid=%s version=%s\n' "$state" "$INV_UUID" "${INV_LUKS_VERSION:-none}"
    printf 'systemd_tokens=%s clevis_tpm2=%s target_keys=%s survivors=%s\n' \
        "${#INV_SYSTEMD_TOKENS[@]}" "${#INV_CLEVIS_TPM2[@]}" "${#INV_TARGET_KEYS[@]}" "${#INV_SURVIVORS[@]}"
    local r
    for r in "${INV_CLEVIS_TPM2[@]}"; do printf 'clevis_slot=%s\n' "$r"; done
    for r in "${INV_UNMANAGED[@]}"; do printf 'unmanaged=%s\n' "$r"; done
    for r in "${INV_AMBIGUOUS[@]}"; do printf 'ambiguous=%s\n' "$r"; done
    if [[ -n "$INV_ERROR" ]]; then printf 'error=%s\n' "$INV_ERROR"; fi
    return 0
}

# ─────────────────────────────
# Privilege handling
# ─────────────────────────────
# Validate/cache sudo credentials before any destructive confirmation so a
# mid-operation sudo prompt can never be misread as success.  Returns 0 when
# elevation is available; aborts with a message otherwise.
ensure_sudo() {
    if sudo -n true 2>/dev/null; then return 0; fi
    if sudo -v 2>/dev/null; then return 0; fi
    print_error "sudo access unavailable — cannot perform privileged operations."
    return 1
}

# ─────────────────────────────
# Advisory per-volume lock (TravelShield instances only)
# ─────────────────────────────
# The lock lives under the root-owned mode-0700 state directory, never in
# attacker-writable /tmp: as root, a predictable /tmp name could be
# pre-planted as a symlink and followed during open.  Creation failure is
# fatal (fail closed).
LOCK_FD=""
acquire_lock() {
    [[ -n "$INV_UUID" ]] || return 0
    if ! sudo install -d -m 700 "$STATE_DIR" 2>/dev/null; then
        print_error "Cannot create state directory $STATE_DIR (locking impossible)."
        exit 1
    fi
    local lock="${STATE_DIR}/travelshield-${INV_UUID}.lock"
    if ! exec {LOCK_FD}>"$lock" 2>/dev/null; then
        print_error "Cannot open lock file $lock."
        exit 1
    fi
    if ! flock -n "$LOCK_FD"; then
        print_error "Another TravelShield instance is running for this volume."
        exit 1
    fi
}

# ─────────────────────────────
# Recovery gate
# ─────────────────────────────
# Returns 0 if at least one structural survivor keyslot exists (a keyslot
# referenced by no token at all).  Prints nothing on success; prints the
# refusal reason and returns 1 otherwise.
check_recovery_survivors() {
    if (( ${#INV_SURVIVORS[@]} > 0 )); then return 0; fi
    print_error "REFUSING: no passphrase/recovery keyslot survives removal."
    print_error "Every LUKS keyslot is referenced by an automatic-unlock token;"
    print_error "removing the TPM bindings could lock you out of the disk."
    print_error "Add a passphrase keyslot (cryptsetup luksAddKey) or recovery key first."
    return 1
}

# Show the removal plan and require the user to type "ARM".
# $1 = operation label ("ARM travel mode" / "RE-ENROLL")
confirm_destructive_plan() {
    local label="$1" ack
    echo
    print_warning "About to remove ALL supported TPM2 auto-unlock bindings:"
    printf "  ${BOLD}Device${NC}       : %s\n" "$RAW_LUKS_DEVICE"
    printf "  ${BOLD}LUKS UUID${NC}    : %s\n" "$INV_UUID"
    printf "  ${BOLD}Target slots${NC} : %s\n" "${INV_TARGET_KEYS[*]:-none}"
    if (( ${#INV_SYSTEMD_TOKENS[@]} > 0 )); then
        printf "  ${BOLD}systemd-tpm2${NC}  : %s\n" "${INV_SYSTEMD_TOKENS[*]}"
    fi
    for r in "${INV_CLEVIS_TPM2[@]}"; do
        printf "  ${BOLD}Clevis tpm2${NC}   : slot %s policy %s\n" "${r%%|*}" "${r##*|}"
    done
    if (( ${#INV_SURVIVORS[@]} > 0 )); then
        printf "  ${BOLD}Survivors${NC}    : %s\n" "${INV_SURVIVORS[*]}"
    elif [[ "$label" == "RE-ENROLL" ]]; then
        printf "  ${BOLD}Survivors${NC}    : NONE — re-enrollment removal will be refused\n"
    else
        printf "  ${BOLD}Survivors${NC}    : NONE — removal refused\n"
    fi
    if (( ${#INV_UNMANAGED[@]} > 0 )); then
        print_warning "Non-TPM auto-unlock mechanisms are also present (not removed):"
        local u
        for u in "${INV_UNMANAGED[@]}"; do print_warning "  $u"; done
    fi
    echo
    print_warning "A surviving keyslot is STRUCTURAL ONLY — TravelShield cannot prove"
    print_warning "you know its passphrase/recovery secret.  Verify your recovery"
    print_warning "material before continuing."
    echo
    printf "  Type ${RED}${BOLD}ARM${NC} to confirm ${label}: "
    read -r ack || true
    if [[ "$ack" != "ARM" ]]; then
        print_info "Cancelled — no changes made."
        return 1
    fi
    # Re-collect and compare the complete plan with the confirmed one
    # (concurrent change guard).  Any difference — including new ambiguity
    # or an altered token/keyslot association — aborts before mutation.
    local before_uuid="$INV_UUID"
    local before_target="${INV_TARGET_KEYS[*]}"
    local before_surv="${INV_SURVIVORS[*]}"
    local before_sig
    before_sig=$(token_signature)
    if ! collect_luks_inventory; then
        print_error "Header changed or became uninspectable — aborting, no changes made."
        return 1
    fi
    local new_state
    new_state=$(classify_inventory)
    if [[ "$new_state" == "UNKNOWN" ]]; then
        print_error "Header became ambiguous after confirmation — aborting, no changes made."
        print_warning "Reason: ${INV_ERROR:-${INV_AMBIGUOUS[0]:-unknown}}"
        return 1
    fi
    if [[ "$INV_UUID" != "$before_uuid" \
          || "${INV_TARGET_KEYS[*]}" != "$before_target" \
          || "${INV_SURVIVORS[*]}" != "$before_surv" \
          || "$(token_signature)" != "$before_sig" ]]; then
        print_error "LUKS header changed since confirmation — aborting, no changes made."
        return 1
    fi
    return 0
}

# Sorted "tid:type:keys" signature of every token (for change detection).
token_signature() {
    local tid out=""
    local -a ids
    ids=("${!INV_TOK_TYPE[@]}")
    mapfile -t ids < <(printf '%s\n' "${ids[@]}" | sort)
    for tid in "${ids[@]}"; do
        out+="$tid:${INV_TOK_TYPE[$tid]}:${INV_TOK_KEYS[$tid]:-};"
    done
    printf '%s\n' "$out"
}

# ─────────────────────────────
# systemd-cryptenroll
# ─────────────────────────────
remove_systemd_tokens() { # removes ALL systemd-tpm2 tokens/keyslots
    sudo systemd-cryptenroll --wipe-slot=tpm2 "$RAW_LUKS_DEVICE"
}

enroll_systemd_tpm2() { # explicit PCR7 policy, sha256 bank; never unbound
    sudo systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7:sha256 "$RAW_LUKS_DEVICE"
}

# ─────────────────────────────
# Clevis
# ─────────────────────────────
remove_clevis_slot() { # $1 = slot number
    sudo clevis luks unbind -d "$RAW_LUKS_DEVICE" -s "$1"
}

enroll_clevis_tpm2() { # explicit PCR7 policy; never the legacy '{}'
    sudo clevis luks bind -d "$RAW_LUKS_DEVICE" tpm2 '{"pcr_bank":"sha256","pcr_ids":"7"}'
}

# ─────────────────────────────
# Verification helpers
# ─────────────────────────────
# Post-enrollment check: exactly one supported binding with the expected
# policy exists.  $1 = backend ("systemd" | "clevis")
verify_new_binding() {
    local backend="$1"
    collect_luks_inventory || return 1
    local state
    state=$(classify_inventory)
    if [[ "$state" == "UNKNOWN" || "$state" == "ERROR" ]]; then return 1; fi
    if [[ "$backend" == "systemd" ]]; then
        systemd_token_ok || return 1
        # A concurrent Clevis TPM2 binding must not be silently accepted.
        (( ${#INV_CLEVIS_TPM2[@]} == 0 )) || return 1
    else
        # Exactly one Clevis TPM2 binding with PCR7 policy and no systemd
        # binding: a concurrent/header-side duplicate must never be
        # reported as a verified enrollment.
        if (( ${#INV_CLEVIS_TPM2[@]} == 1 && ${#INV_SYSTEMD_TOKENS[@]} == 0 )); then
            local r
            for r in "${INV_CLEVIS_TPM2[@]}"; do
                [[ "${r##*|}" == "pcr7" ]] && return 0
            done
        fi
        return 1
    fi
    return 0
}

# Policy predicate for ONE systemd-tpm2 token id: selects exactly PCR 7
# with bank sha256 recorded (absent bank fails).
systemd_token_policy_ok() {
    [[ -n "$INV_JSON_RAW" ]] || return 1
    jq -e --arg t "$1" '
        .tokens[$t].type == "systemd-tpm2" and
        ((.tokens[$t]["tpm2-pcrs"] // []) |
           if type == "array" then map(tostring) else ([tostring]) end |
           sort == ["7"]) and
        ((.tokens[$t]["tpm2-pcr-bank"] // "") == "sha256")
    ' <<<"$INV_JSON_RAW" >/dev/null 2>&1
}

# True iff the header holds EXACTLY ONE systemd-tpm2 token selecting ONLY
# PCR 7 and recording bank sha256 — the exact policy TravelShield enrolls.
systemd_token_ok() {
    [[ -n "$INV_JSON_RAW" ]] || return 1
    jq -e '[.tokens | to_entries[] | select(.value.type == "systemd-tpm2")] | length == 1' \
        <<<"$INV_JSON_RAW" >/dev/null 2>&1 || return 1
    local tid
    tid=$(jq -r '[.tokens | to_entries[] | select(.value.type == "systemd-tpm2")][0].key' <<<"$INV_JSON_RAW" 2>/dev/null || true)
    systemd_token_policy_ok "$tid"
}

# ─────────────────────────────
# Initramfs reminder
# ─────────────────────────────
suggest_initramfs() {
    echo
    print_info "Rebuild your initramfs before rebooting:"
    if have mkinitcpio; then
        print_info "  sudo mkinitcpio -P"
    elif have dracut; then
        print_info "  sudo dracut --force"
    elif have update-initramfs; then
        print_info "  sudo update-initramfs -u -k all"
    else
        print_warning "No initramfs tool detected — rebuild manually."
    fi
}

# ─────────────────────────────
# Operations
# ─────────────────────────────
arm_travel_mode() {
    cls
    print_info "Inspecting LUKS header..."
    if ! collect_luks_inventory; then
        print_error "Cannot inspect the LUKS header: ${INV_ERROR}"
        print_error "State is UNKNOWN — no changes made."
        return
    fi
    local state
    state=$(classify_inventory)
    if [[ "$state" == "UNKNOWN" ]]; then
        print_error "State is UNKNOWN: ${INV_ERROR:-${INV_AMBIGUOUS[0]:-ambiguous}}"
        print_error "No changes made."
        return
    fi
    if (( ${#INV_SYSTEMD_TOKENS[@]} == 0 && ${#INV_CLEVIS_TPM2[@]} == 0 )); then
        print_success "Already ARMED — no supported TPM2 auto-unlock binding found."
        return
    fi

    # Capability preflight: every detected family must be removable.
    if (( ${#INV_SYSTEMD_TOKENS[@]} > 0 )) && ! have systemd-cryptenroll; then
        print_error "systemd-tpm2 token present but systemd-cryptenroll is not installed."
        print_error "Refusing to change the header — install systemd-cryptenroll first."
        return
    fi
    if (( ${#INV_CLEVIS_TPM2[@]} > 0 )) && ! have clevis; then
        print_error "Clevis tpm2 binding present but clevis is not installed."
        print_error "Refusing to change the header — install clevis first."
        return
    fi

    ensure_sudo || return
    check_recovery_survivors || return
    confirm_destructive_plan "ARM travel mode" || return

    # ── Execute removals ──
    if (( ${#INV_SYSTEMD_TOKENS[@]} > 0 )); then
        printf "\n${BOLD}Removing systemd-tpm2 token(s)...${NC}\n"
        if ! remove_systemd_tokens; then
            LAST_OP_ERROR="systemd-cryptenroll --wipe-slot=tpm2 failed"
            _report_partial_removal
            return
        fi
    fi
    local r slot
    for r in "${INV_CLEVIS_TPM2[@]}"; do
        slot="${r%%|*}"
        printf "\n${BOLD}Unbinding Clevis tpm2 slot %s...${NC}\n" "$slot"
        if ! remove_clevis_slot "$slot"; then
            LAST_OP_ERROR="clevis luks unbind slot $slot failed"
            _report_partial_removal
            return
        fi
    done

    # ── Post-operation verification (mandatory) ──
    printf "\n${BOLD}Verifying resulting state...${NC}\n"
    if ! collect_luks_inventory; then
        LAST_OP_ERROR="post-removal inspection failed: ${INV_ERROR}"
        print_error "${LAST_OP_ERROR}"
        print_error "State is UNKNOWN — do NOT trust that the disk is armed."
        return
    fi
    state=$(classify_inventory)
    if (( ${#INV_SYSTEMD_TOKENS[@]} == 0 && ${#INV_CLEVIS_TPM2[@]} == 0 )) && [[ "$state" != "UNKNOWN" ]]; then
        clear_pcr_diagnostic
        if (( ${#INV_UNMANAGED[@]} > 0 )); then
            LAST_OP_ERROR=""; print_success "Travel mode ${RED}ARMED (TPM)${NC} — no supported TPM2 auto-unlock remains."
            print_warning "Non-TPM automatic unlockers are still configured:"
            local u
            for u in "${INV_UNMANAGED[@]}"; do print_warning "  $u"; done
            print_warning "A passphrase may still NOT be required at boot."
        else
            LAST_OP_ERROR=""; print_success "Travel mode ${RED}ARMED${NC} — passphrase required at next boot."
        fi
        suggest_initramfs
    else
        LAST_OP_ERROR="${LAST_OP_ERROR:-residual TPM bindings remain after removal}"
        _report_partial_removal
    fi
}

_report_partial_removal() {
    print_error "ERROR — removal incomplete: ${LAST_OP_ERROR}"
    if collect_luks_inventory 2>/dev/null; then
        print_error "Remaining supported TPM2 bindings:"
        local r
        for r in "${INV_CLEVIS_TPM2[@]}"; do print_error "  clevis tpm2 slot ${r%%|*} (${r##*|})"; done
        for r in "${INV_SYSTEMD_TOKENS[@]}"; do print_error "  systemd-tpm2 token $r"; done
    fi
    print_error "TravelShield is NOT armed.  Fix the failure and re-run."
}

disarm_travel_mode() {
    cls
    print_info "Inspecting LUKS header..."
    if ! collect_luks_inventory; then
        print_error "Cannot inspect the LUKS header: ${INV_ERROR}"
        return
    fi
    local state
    state=$(classify_inventory)
    if [[ "$state" == "UNKNOWN" ]]; then
        print_error "State is UNKNOWN: ${INV_ERROR:-${INV_AMBIGUOUS[0]:-ambiguous}}"
        print_error "No changes made."
        return
    fi
    if (( ${#INV_SYSTEMD_TOKENS[@]} > 0 || ${#INV_CLEVIS_TPM2[@]} > 0 )); then
        print_info "TPM auto-unlock is already configured ($state)."
        print_info "Use Re-enroll TPM binding to replace it; this would only add duplicates."
        return
    fi

    local backend
    backend=$(detect_enroll_backend)
    if [[ "$backend" == "none" ]]; then
        print_error "No TPM2 enrollment backend found (systemd-cryptenroll or clevis)."
        return
    fi
    ensure_sudo || return
    echo
    printf "  Enroll TPM2 auto-unlock using ${CYAN}%s${NC}?\n" "$backend"
    printf "  Binding will be sealed to ${BOLD}PCR7 (sha256)${NC}.\n"
    printf "  ${CYAN}[Y]${NC} Enroll   ${CYAN}[N]${NC} Go back\n"
    read_key key
    [[ "${key,,}" == "y" ]] || { print_info "Cancelled."; return; }

    printf "\n${BOLD}Enrolling TPM2 token (PCR7, sha256)...${NC}\n"
    if [[ "$backend" == "systemd" ]]; then
        enroll_systemd_tpm2 || { LAST_OP_ERROR="systemd-cryptenroll enrollment failed"; print_error "${LAST_OP_ERROR}"; return; }
    else
        enroll_clevis_tpm2 || { LAST_OP_ERROR="clevis luks bind failed"; print_error "${LAST_OP_ERROR}"; return; }
    fi

    # Post-enrollment verification: the binding must exist with the policy.
    if verify_new_binding "$backend"; then
        store_pcr_diagnostic
        LAST_OP_ERROR=""; print_success "Travel mode ${GREEN}DISARMED${NC} — TPM auto-unlock enabled (PCR7-sealed)."
        suggest_initramfs
    else
        LAST_OP_ERROR="enrollment reported success but the new binding could not be verified"
        print_error "${LAST_OP_ERROR}"
        if collect_luks_inventory 2>/dev/null; then
            print_info "Actual header state: $(classify_inventory)"
        fi
    fi
}

# ─────────────────────────────
# Re-enrollment
# ─────────────────────────────
# Recovery gate for re-enrollment: refuse removal when no passphrase
# keyslot survives.  MUST run after the staged replacement is verified and
# BEFORE any old binding is deleted.  Header policy verification cannot
# prove the replacement will unseal or that the user knows an independent
# credential, so without a survivor the removal is refused outright.
reenroll_recovery_gate() {
    if (( ${#INV_SURVIVORS[@]} > 0 )); then return 0; fi
    print_error "REFUSING: no passphrase/recovery keyslot survives removal."
    print_error "Re-enrollment removal is blocked even though a replacement binding"
    print_error "was created — the replacement may not unseal, and no independent"
    print_error "credential is verifiable."
    print_error "Add a passphrase keyslot (cryptsetup luksAddKey) or a recovery key first."
    print_error "The new binding was left in place; NO old binding was removed."
    return 1
}

reenroll_binding() {
    cls
    print_info "Inspecting LUKS header..."
    if ! collect_luks_inventory; then
        print_error "Cannot inspect the LUKS header: ${INV_ERROR}"
        return
    fi
    local state
    state=$(classify_inventory)
    if [[ "$state" == "UNKNOWN" ]]; then
        print_error "State is UNKNOWN: ${INV_ERROR:-${INV_AMBIGUOUS[0]:-ambiguous}}"
        print_error "No changes made."
        return
    fi
    if (( ${#INV_SYSTEMD_TOKENS[@]} == 0 && ${#INV_CLEVIS_TPM2[@]} == 0 )); then
        print_info "No TPM binding to re-enroll — use Toggle to enroll one."
        return
    fi

    local backend
    backend=$(detect_enroll_backend)
    if [[ "$backend" == "none" ]]; then
        print_error "No TPM2 enrollment backend found (systemd-cryptenroll or clevis)."
        return
    fi

    # Capability preflight: old bindings of either family must be removable.
    if (( ${#INV_SYSTEMD_TOKENS[@]} > 0 )) && ! have systemd-cryptenroll; then
        print_error "systemd-tpm2 token present but systemd-cryptenroll is not installed."
        return
    fi
    if (( ${#INV_CLEVIS_TPM2[@]} > 0 )) && ! have clevis; then
        print_error "Clevis tpm2 binding present but clevis is not installed."
        return
    fi

    ensure_sudo || return
    confirm_destructive_plan "RE-ENROLL" || return

    # Capture the old bindings and the full token signature BEFORE any
    # mutation: the staged verification must prove the replacement is a
    # NEW token/slot (set difference) and that NOTHING else changed.
    local -a old_clevis_slots=()
    local -a old_systemd_keys=()
    local -a old_systemd_tids=()
    local r pre_sig
    for r in "${INV_CLEVIS_TPM2[@]}"; do old_clevis_slots+=("${r%%|*}"); done
    for r in "${INV_SYSTEMD_KEYS[@]}"; do old_systemd_keys+=("$r"); done
    for r in "${INV_SYSTEMD_TOKENS[@]}"; do old_systemd_tids+=("$r"); done
    pre_sig=$(token_signature)

    printf "\n${BOLD}Staged re-enrollment (%s)...${NC}\n" "$backend"

    if [[ "$backend" == "systemd" ]]; then
        # 1. Enroll the replacement binding ONLY (no wipe yet).
        if ! sudo systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7:sha256 "$RAW_LUKS_DEVICE"; then
            LAST_OP_ERROR="systemd enrollment failed (no old binding was removed)"
            print_error "${LAST_OP_ERROR}"
            return
        fi
        # 2. Exact-delta verification BEFORE removing anything: the
        #    post-enrollment inventory must be fully classifiable and equal
        #    to the pre-enrollment signature plus EXACTLY ONE new
        #    systemd-tpm2 token with the exact PCR7 policy.
        if ! collect_luks_inventory; then
            LAST_OP_ERROR="header uninspectable after systemd enrollment — old bindings NOT removed"
            print_error "${LAST_OP_ERROR}"
            return
        fi
        if [[ "$(classify_inventory)" == "UNKNOWN" ]]; then
            LAST_OP_ERROR="post-enrollment inventory is ambiguous — old bindings NOT removed"
            print_error "${LAST_OP_ERROR}"
            _report_partial_removal
            return
        fi
        local new_tid="" t3 o3 in_old
        while IFS= read -r t3; do
            [[ -n "$t3" ]] || continue
            in_old=0
            for o3 in "${old_systemd_tids[@]}"; do [[ "$t3" == "$o3" ]] && in_old=1; done
            (( in_old == 0 )) || continue
            if systemd_token_policy_ok "$t3"; then new_tid="$t3"; fi
        done < <(jq -r '[.tokens | to_entries[] | select(.value.type=="systemd-tpm2") | .key] | .[]' <<<"$INV_JSON_RAW" 2>/dev/null || true)
        local post_sig new_entry
        post_sig=$(token_signature)
        new_entry="${new_tid}:systemd-tpm2:${INV_TOK_KEYS[$new_tid]:-};"
        if [[ -z "$new_tid" ]] || [[ "$post_sig" != *"$new_entry"* ]] || [[ "${post_sig//$new_entry/}" != "$pre_sig" ]]; then
            LAST_OP_ERROR="staged systemd replacement not verified (exact delta) — old bindings NOT removed"
            print_error "${LAST_OP_ERROR}"
            _report_partial_removal
            return
        fi
        # Recovery gate: refuse removal when no passphrase keyslot survives.
        reenroll_recovery_gate || {
            LAST_OP_ERROR="re-enrollment refused: zero surviving recovery keyslots"
            _report_partial_removal
            return
        }
        # 3. Remove the OLD systemd keyslots by number (the new keyslot is
        #    strictly greater, so it is never selected).
        local ks
        for ks in "${old_systemd_keys[@]}"; do
            if ! sudo systemd-cryptenroll --wipe-slot="$ks" "$RAW_LUKS_DEVICE"; then
                LAST_OP_ERROR="wiping old systemd keyslot $ks failed"
                _report_partial_removal
                return
            fi
        done
    else
        # 1. Enroll the replacement Clevis binding ONLY.
        if ! enroll_clevis_tpm2; then
            LAST_OP_ERROR="clevis enrollment failed (no old binding was removed)"
            print_error "${LAST_OP_ERROR}"
            return
        fi
        # 2. Exact-delta verification BEFORE removing anything: fully
        #    classifiable post-enrollment inventory equal to the
        #    pre-enrollment signature plus EXACTLY ONE new clevis token
        #    whose (new) keyslot carries the PCR7 policy.
        if ! collect_luks_inventory; then
            LAST_OP_ERROR="header uninspectable after clevis enrollment — old bindings NOT removed"
            print_error "${LAST_OP_ERROR}"
            return
        fi
        if [[ "$(classify_inventory)" == "UNKNOWN" ]]; then
            LAST_OP_ERROR="post-enrollment inventory is ambiguous — old bindings NOT removed"
            print_error "${LAST_OP_ERROR}"
            _report_partial_removal
            return
        fi
        local new_tid="" r2 slot2 o2 in_old tid2 kk
        for tid2 in "${!CLEVIS_TOK_KEYS[@]}"; do
            for kk in ${CLEVIS_TOK_KEYS[$tid2]}; do
                in_old=0
                for o2 in "${old_clevis_slots[@]}"; do [[ "$kk" == "$o2" ]] && in_old=1; done
                (( in_old == 0 )) || continue
                for r2 in "${INV_CLEVIS_TPM2[@]}"; do
                    if [[ "$r2" == "$kk|tpm2|pcr7" ]]; then new_tid="$tid2"; fi
                done
            done
        done
        post_sig=$(token_signature)
        new_entry="${new_tid}:clevis:${INV_TOK_KEYS[$new_tid]:-};"
        if [[ -z "$new_tid" ]] || [[ "$post_sig" != *"$new_entry"* ]] || [[ "${post_sig//$new_entry/}" != "$pre_sig" ]]; then
            LAST_OP_ERROR="staged clevis replacement not verified (exact delta) — old bindings NOT removed"
            print_error "${LAST_OP_ERROR}"
            _report_partial_removal
            return
        fi
        # Recovery gate: refuse removal when no passphrase keyslot survives.
        reenroll_recovery_gate || {
            LAST_OP_ERROR="re-enrollment refused: zero surviving recovery keyslots"
            _report_partial_removal
            return
        }
        # 3. Remove old systemd bindings (type wipe never touches clevis).
        if (( ${#old_systemd_keys[@]} > 0 )); then
            if ! remove_systemd_tokens; then
                LAST_OP_ERROR="removing old systemd-tpm2 tokens failed"
                _report_partial_removal
                return
            fi
        fi
    fi

    # 4. Remove every OLD clevis tpm2 slot (the new one is not in this list).
    local slot
    for slot in "${old_clevis_slots[@]}"; do
        printf "\n${BOLD}Unbinding old Clevis tpm2 slot %s...${NC}\n" "$slot"
        if ! remove_clevis_slot "$slot"; then
            LAST_OP_ERROR="clevis luks unbind slot $slot failed"
            _report_partial_removal
            return
        fi
    done

    # Final verification: a fully classifiable inventory with EXACTLY one
    # new binding of the expected policy.  Ambiguity or inspection failure
    # is never announced as a verified re-enrollment.
    printf "\n${BOLD}Verifying resulting state...${NC}\n"
    if ! collect_luks_inventory; then
        LAST_OP_ERROR="re-enrollment verification failed: ${INV_ERROR}"
        print_error "${LAST_OP_ERROR}"
        return
    fi
    local final_state
    final_state=$(classify_inventory)
    local ok=0
    if [[ "$final_state" == "UNKNOWN" ]]; then
        LAST_OP_ERROR="re-enrollment verification ambiguous: ${INV_ERROR:-${INV_AMBIGUOUS[0]:-unknown}}"
        print_error "${LAST_OP_ERROR}"
        return
    fi
    if [[ "$backend" == "systemd" ]] && systemd_token_ok && (( ${#INV_CLEVIS_TPM2[@]} == 0 )); then
        ok=1
    elif [[ "$backend" == "clevis" && ${#INV_CLEVIS_TPM2[@]} -eq 1 && ${#INV_SYSTEMD_TOKENS[@]} -eq 0 ]]; then
        for r in "${INV_CLEVIS_TPM2[@]}"; do
            [[ "${r##*|}" == "pcr7" ]] && ok=1
        done
    fi
    if (( ok )); then
        store_pcr_diagnostic
        LAST_OP_ERROR=""; print_success "Re-enrolled: ${GREEN}DISARMED${NC} — single TPM2 binding (PCR7-sealed)."
        suggest_initramfs
    else
        LAST_OP_ERROR="re-enrollment incomplete — residual bindings remain"
        _report_partial_removal
    fi
}

# ─────────────────────────────
# Detailed status view
# ─────────────────────────────
show_detailed_status() {
    cls
    collect_luks_inventory || true
    local state
    state=$(classify_inventory)
    printf "${BLUE}╔%s╗${NC}\n" "$(printf '═%.0s' $(seq 1 $BOX_W))"
    _box_row "${YELLOW}TravelShield — Detailed Status${NC}"
    printf "${BLUE}╚%s╝${NC}\n" "$(printf '═%.0s' $(seq 1 $BOX_W))"
    echo
    printf "  LUKS device     : ${YELLOW}%s${NC}\n" "$LUKS_DEVICE"
    printf "  Raw device      : ${YELLOW}%s${NC}\n" "$RAW_LUKS_DEVICE"
    printf "  LUKS UUID       : ${CYAN}%s${NC}\n" "${INV_UUID:-unknown}"
    printf "  LUKS format     : ${CYAN}%s${NC}\n" "${INV_LUKS_VERSION:-unknown}"
    printf "  Backend         : ${CYAN}%s${NC}\n" "$(detect_enroll_backend)"
    echo
    printf "  State           : ${BOLD}%s${NC}\n" "$state"
    printf "  PCR7 current    : ${CYAN}%s${NC}\n" "${PCR_CURRENT:-unavailable}"
    printf "  PCR7 stored     : ${CYAN}%s${NC}\n" "${PCR_STORED:-none}"
    printf "  PCR7 diagnostic : ${CYAN}%s${NC}\n" "$PCR_STATUS"
    echo
    if [[ -n "$INV_ERROR" ]]; then
        print_error "Inspection error: $INV_ERROR"
        echo
    fi
    if [[ -n "$LAST_OP_ERROR" ]]; then
        print_error "Last operation error: $LAST_OP_ERROR"
        echo
    fi
    if (( ${#INV_AMBIGUOUS[@]} > 0 )); then
        print_warning "Ambiguous header conditions:"
        local a
        for a in "${INV_AMBIGUOUS[@]}"; do print_warning "  $a"; done
        echo
    fi
    printf "${BOLD}  Keyslots:${NC}\n"
    local kid
    if (( ${#INV_KEYS_TYPE[@]} == 0 )); then
        printf "    (none visible)\n"
    else
        for kid in "${!INV_KEYS_TYPE[@]}"; do
            printf "    %s : %s\n" "$kid" "${INV_KEYS_TYPE[$kid]}"
        done
    fi
    echo
    printf "${BOLD}  Tokens:${NC}\n"
    local tid
    if (( ${#INV_TOK_TYPE[@]} == 0 )); then
        printf "    (none)\n"
    else
        for tid in "${!INV_TOK_TYPE[@]}"; do
            printf "    %s : %s (keyslots: %s)\n" "$tid" "${INV_TOK_TYPE[$tid]}" "${INV_TOK_KEYS[$tid]:--}"
        done
    fi
    echo
    printf "${BOLD}  Clevis TPM2 bindings:${NC}\n"
    if (( ${#INV_CLEVIS_TPM2[@]} == 0 )); then
        printf "    (none)\n"
    else
        for r in "${INV_CLEVIS_TPM2[@]}"; do
            printf "    slot %s : policy %s\n" "${r%%|*}" "${r##*|}"
        done
    fi
    echo
    printf "${BOLD}  Unmanaged automatic unlockers (not removed by TravelShield):${NC}\n"
    if (( ${#INV_UNMANAGED[@]} == 0 )); then
        printf "    (none)\n"
    else
        for r in "${INV_UNMANAGED[@]}"; do printf "    %s\n" "$r"; done
    fi
    wait_any_key
}

# ─────────────────────────────
# Status text for the menu
# ─────────────────────────────
menu_status() {
    collect_luks_inventory || true
    # A failed/partial operation keeps the documented ERROR state visible
    # until a fully verified operation succeeds.
    if [[ -n "$LAST_OP_ERROR" ]]; then
        echo "ERROR — last operation incomplete"
        return
    fi
    local state
    state=$(classify_inventory)
    case "$state" in
        ARMED)
            if (( ${#INV_UNMANAGED[@]} > 0 )); then
                echo "ARMED (TPM) — non-TPM auto-unlock still configured"
            else
                echo "ARMED — passphrase required"
            fi
            ;;
        DISARMED) echo "DISARMED — TPM auto-unlock active" ;;
        STALE)    echo "STALE — TPM token present, PCR7 mismatch" ;;
        UNKNOWN)  echo "UNKNOWN — cannot inspect TPM state safely" ;;
        ERROR)    echo "ERROR — last operation incomplete" ;;
        *)        echo "UNKNOWN — cannot inspect TPM state safely" ;;
    esac
}

# ─────────────────────────────
# Toggle handler
# ─────────────────────────────
toggle_travel_mode() {
    cls
    collect_luks_inventory || true
    local state
    state=$(classify_inventory)
    case "$state" in
        DISARMED|STALE)
            printf "${BLUE}╔%s╗${NC}\n" "$(printf '═%.0s' $(seq 1 $BOX_W))"
            _box_row "${YELLOW}TravelShield — Toggle Travel Mode${NC}"
            printf "${BLUE}╚%s╝${NC}\n" "$(printf '═%.0s' $(seq 1 $BOX_W))"
            echo
            if [[ "$state" == "STALE" ]]; then
                printf "  Current: ${YELLOW}[STALE]${NC} — TPM token present, PCR7 mismatch\n\n"
                print_warning "The token still exists and may auto-unlock."
                print_warning "Re-enroll after a firmware/BIOS change, or arm travel mode."
                echo
            else
                printf "  Current: ${GREEN}[DISARMED]${NC} — TPM auto-unlock active\n\n"
            fi
            printf "  ${BOLD}Enable travel mode?${NC}\n"
            printf "  This removes ${RED}every${NC} supported TPM2 auto-unlock binding\n"
            printf "  (systemd-tpm2 and Clevis tpm2).\n"
            if (( ${#INV_UNMANAGED[@]} > 0 )); then
                print_warning "Non-TPM automatic unlockers are still configured — a passphrase"
                print_warning "may still NOT be required at boot.  See [S] Detailed Status."
            else
                printf "  Passphrase required at boot.\n"
            fi
            printf "\n  ${CYAN}[Y]${NC} Yes, arm travel mode   ${CYAN}[N]${NC} No, go back\n"
            local key
            read_key key
            if [[ "${key,,}" == "y" ]]; then
                arm_travel_mode
            else
                print_info "Cancelled."
            fi
            ;;
        ARMED)
            printf "${BLUE}╔%s╗${NC}\n" "$(printf '═%.0s' $(seq 1 $BOX_W))"
            _box_row "${YELLOW}TravelShield — Toggle Travel Mode${NC}"
            printf "${BLUE}╚%s╝${NC}\n" "$(printf '═%.0s' $(seq 1 $BOX_W))"
            echo
            if (( ${#INV_UNMANAGED[@]} > 0 )); then
                printf "  Current: ${RED}[ARMED (TPM)]${NC} — no supported TPM2 auto-unlock remains\n\n"
                print_warning "Non-TPM automatic unlockers are still configured — a passphrase"
                print_warning "may still NOT be required at boot.  See [S] Detailed Status."
                echo
            else
                printf "  Current: ${RED}[ARMED]${NC} — passphrase required at boot\n\n"
            fi
            printf "  ${BOLD}Disable travel mode?${NC}\n"
            printf "  This enrolls a TPM2 token sealed to ${BOLD}PCR7 (sha256)${NC}.\n\n"
            printf "  ${CYAN}[Y]${NC} Yes, disarm travel mode   ${CYAN}[N]${NC} No, go back\n"
            local key
            read_key key
            if [[ "${key,,}" == "y" ]]; then
                disarm_travel_mode
            else
                print_info "Cancelled."
            fi
            ;;
        UNKNOWN|ERROR)
            print_error "State is $state — TravelShield refuses to toggle."
            print_warning "Reason: ${INV_ERROR:-${INV_AMBIGUOUS[0]:-ambiguous header}}"
            print_info "Open [S] Detailed Status for the full picture, then resolve."
            ;;
    esac
    wait_any_key
}

# ─────────────────────────────
# Main TUI menu
# ─────────────────────────────
show_menu() {
    while true; do
        local status_color status_text
        status_text=$(menu_status)
        case "$status_text" in
            DISARMED*) status_color="${GREEN}" ;;
            STALE*)    status_color="${YELLOW}" ;;
            UNKNOWN*|ERROR*) status_color="${RED}" ;;
            *)         status_color="${RED}" ;;
        esac

        cls
        printf "${BLUE}╔%s╗${NC}\n" "$(printf '═%.0s' $(seq 1 $BOX_W))"
        _box_row "${YELLOW}TravelShield   TPM2 LUKS Manager${NC}"
        printf "${BLUE}╠%s╣${NC}\n" "$(printf '─%.0s' $(seq 1 $BOX_W))"

        _box_row "${CYAN}Device : $(basename "$LUKS_DEVICE")${NC}"

        local status_fmt="Status : ${status_color}${status_text}${NC}"
        _box_row "$status_fmt"

        _box_row "${CYAN}Backend: $(detect_enroll_backend)${NC}"

        printf "${BLUE}╠%s╣${NC}\n" "$(printf '─%.0s' $(seq 1 $BOX_W))"
        _box_row "${CYAN}[T] Toggle travel mode${NC}"
        _box_row "${CYAN}[R] Re-enroll TPM binding${NC}"
        _box_row "${CYAN}[S] Show detailed status${NC}"
        _box_row "${CYAN}[Q] Quit${NC}"
        printf "${BLUE}╚%s╝${NC}\n" "$(printf '═%.0s' $(seq 1 $BOX_W))"
        printf "  ${CYAN}>${NC} "
        local key
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
    case "${1:-}" in
        --version|-V) echo "TravelShield $VERSION"; exit 0 ;;
        --help|-h)
            echo "Usage: travelshield [--version|--help]"
            echo "  --version, -V   Show version"
            echo "  --help, -h      Show this help"
            echo
            echo "Run without arguments for the interactive TUI."
            exit 0
            ;;
        "") ;;
        *) echo "Unknown option: $1"; echo "Usage: travelshield [--version|--help]"; exit 1 ;;
    esac

    cls
    printf "${BLUE}╔%s╗${NC}\n" "$(printf '═%.0s' $(seq 1 $BOX_W))"
    _box_row "${YELLOW}TravelShield — starting up...${NC}"
    printf "${BLUE}╚%s╝${NC}\n" "$(printf '═%.0s' $(seq 1 $BOX_W))"
    echo

    # ── Backend detection (enrollment preference only — detection is all-family) ──
    ENROLL_BACKEND=$(detect_enroll_backend)
    case "$ENROLL_BACKEND" in
        systemd) print_success "Backend: systemd-cryptenroll" ;;
        clevis)  print_success "Backend: clevis + tpm2-tools" ;;
        none)
            print_error "No TPM2 enrollment backend found."
            echo
            print_info "Install one of:"
            print_info "  * systemd-cryptenroll (built into systemd >= 248)"
            print_info "  * clevis-luks + tpm2-tools"
            exit 1
            ;;
    esac
    if ! have jq; then
        print_error "jq is required to inspect LUKS2 metadata (jq missing)."
        print_error "Install jq (pacman: jq, apt: jq, dnf: jq) — state would be UNKNOWN otherwise."
    fi

    # ── TPM device check ──
    if ! [[ -e /dev/tpm0 ]] && ! [[ -e /dev/tpmrm0 ]]; then
        print_error "No TPM2 device detected (/dev/tpm0 or /dev/tpmrm0)."
        exit 1
    fi
    if have tpm2_getcap && ! sudo tpm2_getcap properties-fixed &>/dev/null 2>&1; then
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

    # ── Initial inventory + lock ──
    collect_luks_inventory || print_warning "Initial inspection failed: $INV_ERROR"
    acquire_lock

    print_success "Device: $LUKS_DEVICE"
    sleep 0.5
    show_menu
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
