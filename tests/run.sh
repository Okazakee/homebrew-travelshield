#!/usr/bin/env bash
# =============================================================================
# TravelShield v2.0.3 — safe regression test harness
# =============================================================================
# Run:  bash tests/run.sh
#
# SAFETY: no real LUKS volume, TPM, block device, initramfs, boot config or
# sudo privilege is touched.  All system commands are stubbed via PATH; all
# state lives in a temporary directory and a virtual LUKS header JSON file.
# The stub set even replaces tpm2_getcap so no real TPM tool ever runs.
# =============================================================================

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d /tmp/travelshield-tests.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

export TS_HEADER="$WORK/header.json"
export TS_LOG="$WORK/commands.log"
export TS_STATE_DIR="$WORK/state"
export TS_UUID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
mkdir -p "$TS_STATE_DIR"

ORIG_PATH="$PATH"
export PATH="$ROOT/tests/bin:$ORIG_PATH"

# Build a PATH dir that contains every test stub and every real tool EXCEPT
# one named tool, so the "tool missing" branches can be exercised without
# shadowing the other stubs with real binaries.
build_hide_dir() { # $1 = dir suffix, $2 = tool to hide
    local d="$WORK/hide-$1" b base
    mkdir -p "$d"
    for b in "$ROOT"/tests/bin/*; do
        base=$(basename "$b")
        [[ "$base" == "$2" ]] && continue
        ln -sf "$b" "$d/$base"
    done
    for b in /usr/bin/*; do
        base=$(basename "$b")
        [[ "$base" == "$2" ]] && continue
        [[ -e "$d/$base" ]] && continue
        ln -sf "$b" "$d/$base"
    done
}
build_hide_dir jq jq
build_hide_dir systemd-cryptenroll systemd-cryptenroll
build_hide_dir tpm2_pcrread tpm2_pcrread

# ── Harness helpers ──
PASS=0
FAIL=0
FAILED_NAMES=()

ok()   { PASS=$((PASS+1)); printf '  ok   - %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILED_NAMES+=("$1"); printf '  FAIL - %s\n' "$1"; }

check() { # name expected actual
    if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (expected [$2] got [$3])"; fi
}
check_contains() { # name needle haystack
    if [[ "$3" == *"$2"* ]]; then ok "$1"; else bad "$1 (missing [$2] in [$3])"; fi
}
check_not_contains() { # name needle haystack
    if [[ "$3" != *"$2"* ]]; then ok "$1"; else bad "$1 (unexpected [$2] in [$3])"; fi
}

# Collect into the PARENT shell (command substitution would fork a subshell
# and lose the globals).
collect_now() { collect_luks_inventory >/dev/null 2>&1 || true; }

reset_env() {
    : >"$TS_LOG"
    export TS_SYSTEMD_FAIL=0 TS_SYSTEMD_WIPE_FAIL=0 TS_SYSTEMD_NOOP=0 \
           TS_CLEVIS_FAIL_SLOT= TS_CLEVIS_CANCEL=0 TS_CLEVIS_NOOP=0 \
           TS_CLEVIS_LIST_FAIL=0 TS_CRYPTSETUP_FAIL=0 \
           TS_LUKSUUID_FAIL=0 TS_LUKS1=0 TS_SUDO_DENIED=0
    export TS_CLEVIS_LIST="$WORK/clevis.list"
    : >"$TS_CLEVIS_LIST"
    rm -rf "$TS_STATE_DIR"; mkdir -p "$TS_STATE_DIR"
}

# ── Fixtures (virtual LUKS2 headers; Clevis tokens store only `jwe`, with
#    the decoded pin/policy kept in the companion list file — mirroring the
#    real clevis model) ──
fixture_no_tokens() {
    cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"0":{"type":"luks2"},"1":{"type":"luks2"}},"tokens":{},"segments":{},"config":{}}
EOF
}
fixture_systemd_one() {
    cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"0":{"type":"luks2"},"1":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"],"tpm2-pcrs":[7],"tpm2-pcr-bank":"sha256"}},"segments":{},"config":{}}
EOF
}
fixture_systemd_multi_keyslot() {
    cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"0":{"type":"luks2"},"1":{"type":"luks2"},"2":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1","2"],"tpm2-pcrs":[7],"tpm2-pcr-bank":"sha256"}},"segments":{},"config":{}}
EOF
}
fixture_clevis_pcr7() {
    cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"0":{"type":"luks2"},"2":{"type":"luks2"}},"tokens":{"1":{"type":"clevis","keyslots":["2"],"jwe":"<jwe>"}},"segments":{},"config":{}}
EOF
    printf "%s\n" "2: tpm2 '{\"pcr_bank\":\"sha256\",\"pcr_ids\":\"7\"}'" >"$TS_CLEVIS_LIST"
}
fixture_clevis_legacy() {
    cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"0":{"type":"luks2"},"2":{"type":"luks2"}},"tokens":{"1":{"type":"clevis","keyslots":["2"],"jwe":"<jwe>"}},"segments":{},"config":{}}
EOF
    printf "%s\n" "2: tpm2 '{}'" >"$TS_CLEVIS_LIST"
}
fixture_clevis_other() {
    cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"0":{"type":"luks2"},"2":{"type":"luks2"}},"tokens":{"1":{"type":"clevis","keyslots":["2"],"jwe":"<jwe>"}},"segments":{},"config":{}}
EOF
    printf "%s\n" "2: tpm2 '{\"pcr_bank\":\"sha1\",\"pcr_ids\":\"7\"}'" >"$TS_CLEVIS_LIST"
}
fixture_clevis_multi() {
    cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"0":{"type":"luks2"},"2":{"type":"luks2"},"3":{"type":"luks2"}},"tokens":{"1":{"type":"clevis","keyslots":["2"],"jwe":"<jwe>"},"2":{"type":"clevis","keyslots":["3"],"jwe":"<jwe2>"}},"segments":{},"config":{}}
EOF
    printf "%s\n" "2: tpm2 '{\"pcr_bank\":\"sha256\",\"pcr_ids\":\"7\"}'" "3: tpm2 '{\"pcr_bank\":\"sha256\",\"pcr_ids\":\"7\"}'" >"$TS_CLEVIS_LIST"
}
fixture_mixed() {
    cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"0":{"type":"luks2"},"1":{"type":"luks2"},"2":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"],"tpm2-pcrs":[7],"tpm2-pcr-bank":"sha256"},"1":{"type":"clevis","keyslots":["2"],"jwe":"<jwe>"}},"segments":{},"config":{}}
EOF
    printf "%s\n" "2: tpm2 '{\"pcr_bank\":\"sha256\",\"pcr_ids\":\"7\"}'" >"$TS_CLEVIS_LIST"
}
fixture_malformed() {
    echo "this is not json" >"$TS_HEADER"
}
fixture_nested_sss() {
    cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"0":{"type":"luks2"},"2":{"type":"luks2"}},"tokens":{"1":{"type":"clevis","keyslots":["2"],"jwe":"<jwe>"}},"segments":{},"config":{}}
EOF
    printf "%s\n" "2: sss '{\"threshold\":1,\"pins\":{\"tpm2\":{\"pcr_bank\":\"sha256\",\"pcr_ids\":\"7\"}}}'" >"$TS_CLEVIS_LIST"
}
fixture_tang() {
    cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"0":{"type":"luks2"},"2":{"type":"luks2"}},"tokens":{"1":{"type":"clevis","keyslots":["2"],"jwe":"<jwe>"}},"segments":{},"config":{}}
EOF
    printf "%s\n" "2: tang '{\"url\":\"https://tang.example\"}'" >"$TS_CLEVIS_LIST"
}
fixture_token_missing_keyslot() {
    cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"0":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["9"],"tpm2-pcrs":[7],"tpm2-pcr-bank":"sha256"}},"segments":{},"config":{}}
EOF
}
fixture_shared_keyslot() {
    cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"0":{"type":"luks2"},"1":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"],"tpm2-pcrs":[7],"tpm2-pcr-bank":"sha256"},"1":{"type":"clevis","keyslots":["1"],"jwe":"<jwe>"}},"segments":{},"config":{}}
EOF
    printf "%s\n" "1: tpm2 '{\"pcr_bank\":\"sha256\",\"pcr_ids\":\"7\"}'" >"$TS_CLEVIS_LIST"
}
fixture_no_survivors() {
    cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"1":{"type":"luks2"},"2":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"],"tpm2-pcrs":[7],"tpm2-pcr-bank":"sha256"},"1":{"type":"clevis","keyslots":["2"],"jwe":"<jwe>"}},"segments":{},"config":{}}
EOF
    printf "%s\n" "2: tpm2 '{\"pcr_bank\":\"sha256\",\"pcr_ids\":\"7\"}'" >"$TS_CLEVIS_LIST"
}
fixture_survivor_tang_referenced() {
    cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"1":{"type":"luks2"},"2":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"],"tpm2-pcrs":[7],"tpm2-pcr-bank":"sha256"},"1":{"type":"clevis","keyslots":["2"],"jwe":"<jwe>"}},"segments":{},"config":{}}
EOF
    printf "%s\n" "2: tang '{\"url\":\"https://tang.example\"}'" >"$TS_CLEVIS_LIST"
}
# Header clevis token whose JWE cannot be decoded -> absent from list.
fixture_clevis_missing_from_list() {
    cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"0":{"type":"luks2"},"2":{"type":"luks2"}},"tokens":{"1":{"type":"clevis","keyslots":["2"],"jwe":"<jwe>"}},"segments":{},"config":{}}
EOF
    : >"$TS_CLEVIS_LIST"
}
# Orphan list record with no matching header token.
fixture_list_without_header() {
    cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"0":{"type":"luks2"}},"tokens":{},"segments":{},"config":{}}
EOF
    printf "%s\n" "2: tpm2 '{\"pcr_bank\":\"sha256\",\"pcr_ids\":\"7\"}'" >"$TS_CLEVIS_LIST"
}

write_stored_pcr() { # digest
    printf '%s\n' "$1" >"$TS_STATE_DIR/pcr7-${TS_UUID}.sha256"
}

# ── Load the script under test ──
source "$ROOT/travelshield.sh"
RAW_LUKS_DEVICE=/dev/sda
LUKS_DEVICE=/dev/mapper/tsroot

printf '== Classification ==\n'

reset_env; fixture_no_tokens; collect_now
check "no tokens -> ARMED" "ARMED" "$(classify_inventory)"

reset_env; fixture_systemd_one; collect_now
check "systemd token -> DISARMED" "DISARMED" "$(classify_inventory)"

reset_env; fixture_clevis_pcr7; collect_now
check "clevis pcr7 -> DISARMED" "DISARMED" "$(classify_inventory)"
s=$(inventory_summary)
check_contains "clevis pcr7 policy classified" "clevis_slot=2|tpm2|pcr7" "$s"

reset_env; fixture_clevis_legacy; collect_now
check "legacy {} binding -> DISARMED (never ARMED)" "DISARMED" "$(classify_inventory)"
s=$(inventory_summary)
check_contains "legacy policy classified" "|legacy" "$s"

reset_env; fixture_clevis_other; collect_now
s=$(inventory_summary)
check_contains "other policy classified" "|other" "$s"

reset_env; fixture_clevis_multi; collect_now
check "two clevis slots -> DISARMED" "DISARMED" "$(classify_inventory)"

reset_env; fixture_mixed; collect_now
check "mixed families -> DISARMED" "DISARMED" "$(classify_inventory)"

reset_env; fixture_malformed; collect_now
check "malformed JSON -> UNKNOWN" "UNKNOWN" "$(classify_inventory)"

reset_env; fixture_nested_sss; collect_now
check "nested sss+tpm2 -> UNKNOWN" "UNKNOWN" "$(classify_inventory)"
s=$(inventory_summary)
check_contains "sss ambiguity recorded" "ambiguous=" "$s"

reset_env; fixture_tang; collect_now
check "tang-only -> ARMED (TPM scope)" "ARMED" "$(classify_inventory)"
s=$(inventory_summary)
check_contains "tang recorded as unmanaged" "unmanaged=clevis-tang" "$s"

reset_env; fixture_token_missing_keyslot; collect_now
check "token->missing keyslot -> UNKNOWN" "UNKNOWN" "$(classify_inventory)"

reset_env; fixture_shared_keyslot; collect_now
check "shared target keyslot -> UNKNOWN" "UNKNOWN" "$(classify_inventory)"

reset_env; fixture_no_survivors; collect_now
s=$(inventory_summary)
check "zero survivors recorded" "survivors=0" "$(printf '%s\n' "$s" | grep -o 'survivors=[0-9]*')"

reset_env; fixture_survivor_tang_referenced; collect_now
s=$(inventory_summary)
check "tang-referenced slot not a survivor" "survivors=0" "$(printf '%s\n' "$s" | grep -o 'survivors=[0-9]*')"

reset_env; fixture_systemd_one
export TS_CRYPTSETUP_FAIL=1; collect_now
check "cryptsetup failure -> UNKNOWN" "UNKNOWN" "$(classify_inventory)"

reset_env; fixture_clevis_pcr7
export TS_CLEVIS_LIST_FAIL=1; collect_now
check "clevis list failure -> UNKNOWN" "UNKNOWN" "$(classify_inventory)"

printf '== Tool availability ==\n'

reset_env; fixture_systemd_one
PATH="$WORK/hide-jq"; collect_now
check "jq missing -> UNKNOWN" "UNKNOWN" "$(classify_inventory)"
PATH="$ROOT/tests/bin:$ORIG_PATH"

reset_env; fixture_clevis_missing_from_list; collect_now
check "clevis token missing from list -> UNKNOWN" "UNKNOWN" "$(classify_inventory)"

reset_env; fixture_list_without_header; collect_now
check "list record without header token -> UNKNOWN" "UNKNOWN" "$(classify_inventory)"

reset_env; fixture_systemd_one
export TS_LUKSUUID_FAIL=1; collect_now
check "LUKS UUID failure -> UNKNOWN" "UNKNOWN" "$(classify_inventory)"

reset_env; fixture_systemd_multi_keyslot; collect_now
check "multi-keyslot systemd token -> DISARMED" "DISARMED" "$(classify_inventory)"
s=$(inventory_summary)
check "multi-keyslot -> both slots targeted" "target_keys=2" "$(printf '%s\n' "$s" | grep -o 'target_keys=[0-9]*')"
out=$(printf 'ARM\n' | arm_travel_mode 2>&1 || true)
collect_now
check "multi-keyslot arm -> ARMED" "ARMED" "$(classify_inventory)"

reset_env; fixture_systemd_one
PATH="$WORK/hide-systemd-cryptenroll"; collect_now
check "systemd token detected without binary -> DISARMED" "DISARMED" "$(classify_inventory)"
out=$(printf 'ARM\n' | arm_travel_mode 2>&1 || true)
check_contains "missing removal tool blocks arming" "Refusing" "$out"
check_not_contains "no removal attempted" "systemd-cryptenroll --wipe" "$(cat "$TS_LOG")"
PATH="$ROOT/tests/bin:$ORIG_PATH"

printf '== PCR diagnostics ==\n'

DIG_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
DIG_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

reset_env; fixture_systemd_one
export TS_PCR="$DIG_A"
write_stored_pcr "$DIG_A"; collect_now
classify_inventory >"$WORK/state.txt" || true
check "pcr match -> DISARMED" "DISARMED" "$(cat "$WORK/state.txt")"
check "pcr status match" "match" "$PCR_STATUS"

reset_env; fixture_systemd_one
export TS_PCR="$DIG_A"
write_stored_pcr "$DIG_B"; collect_now
check "pcr mismatch -> STALE (never ARMED)" "STALE" "$(classify_inventory)"

reset_env; fixture_systemd_one
export TS_PCR="$DIG_A"; collect_now
check "missing cache -> DISARMED" "DISARMED" "$(classify_inventory)"

reset_env; fixture_systemd_one
export TS_PCR="$DIG_A"
printf 'garbage\n' >"$TS_STATE_DIR/pcr7-${TS_UUID}.sha256"
collect_now
classify_inventory >"$WORK/state.txt" || true
check "malformed cache -> STALE-free non-ARMED state" "DISARMED" "$(cat "$WORK/state.txt")"
check "malformed cache treated as unavailable" "unavailable" "$PCR_STATUS"

reset_env; fixture_systemd_one
export TS_PCR="$DIG_A"
get_current_pcr7
check "YAML 7 : 0x... parse yields digest" "$DIG_A" "$PCR_CURRENT"

PATH="$WORK/hide-tpm2_pcrread"
reset_env; fixture_systemd_one; collect_now
check "tpm2_pcrread missing -> DISARMED" "DISARMED" "$(classify_inventory)"
PATH="$ROOT/tests/bin:$ORIG_PATH"

printf '== Verification strictness ==\n'

reset_env; fixture_systemd_one; collect_now
if systemd_token_ok; then ok "systemd_token_ok accepts exact 7:sha256"; else bad "systemd_token_ok rejects exact 7:sha256"; fi

reset_env
cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"0":{"type":"luks2"},"1":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"],"tpm2-pcrs":[7]}},"segments":{},"config":{}}
EOF
collect_now
if systemd_token_ok; then bad "missing bank must fail verification"; else ok "missing bank fails verification"; fi

reset_env
cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"0":{"type":"luks2"},"1":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"],"tpm2-pcrs":[7,8],"tpm2-pcr-bank":"sha256"}},"segments":{},"config":{}}
EOF
collect_now
if systemd_token_ok; then bad "extra PCR must fail verification"; else ok "extra PCR fails verification"; fi

reset_env; fixture_systemd_one; collect_now
if verify_new_binding systemd >/dev/null 2>&1; then ok "verify_new_binding systemd accepts exact 7:sha256"; else bad "verify_new_binding systemd rejects exact 7:sha256"; fi

reset_env
cat >"$TS_HEADER" <<'EOF'
{"keyslots":{"0":{"type":"luks2"},"1":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"],"tpm2-pcrs":[7]}},"segments":{},"config":{}}
EOF
collect_now
if verify_new_binding systemd >/dev/null 2>&1; then bad "verify_new_binding systemd accepts missing bank"; else ok "verify_new_binding systemd rejects missing bank"; fi

reset_env; fixture_clevis_multi; collect_now
if verify_new_binding clevis >/dev/null 2>&1; then bad "duplicate clevis binding must fail verification"; else ok "duplicate clevis binding fails verification"; fi

reset_env; fixture_tang
out=$(printf 'n\n' | toggle_travel_mode 2>&1 || true)
check_contains "toggle labels ARMED (TPM) with unmanaged" "ARMED (TPM)" "$out"
check_not_contains "toggle makes no false passphrase claim" "passphrase required at boot" "$out"

printf '== Arming ==\n'

reset_env; fixture_systemd_one
out=$(printf 'ARM\n' | arm_travel_mode 2>&1 || true)
check_contains "arm systemd success text" "ARMED" "$out"
check_contains "arm systemd passphrase required" "passphrase required" "$out"
collect_now
check "post-arm state ARMED" "ARMED" "$(classify_inventory)"
check_contains "systemd wipe invoked" "systemd-cryptenroll --wipe-slot=tpm2 /dev/sda" "$(cat "$TS_LOG")"

reset_env; fixture_systemd_one
export TS_SYSTEMD_FAIL=1
out=$(printf 'ARM\n' | arm_travel_mode 2>&1 || true)
check_contains "wipe failure -> error" "ERROR" "$out"
check_not_contains "no false success text" "passphrase required at next boot" "$out"
collect_now
check "wipe failure leaves DISARMED" "DISARMED" "$(classify_inventory)"

reset_env; fixture_clevis_pcr7
out=$(printf 'ARM\n' | arm_travel_mode 2>&1 || true)
collect_now
check "post-arm clevis state ARMED" "ARMED" "$(classify_inventory)"
check_contains "clevis unbind invoked" "clevis luks unbind -d /dev/sda -s 2" "$(cat "$TS_LOG")"

reset_env; fixture_clevis_multi
out=$(printf 'ARM\n' | arm_travel_mode 2>&1 || true)
check_contains "slot 2 unbound" "clevis luks unbind -d /dev/sda -s 2" "$(cat "$TS_LOG")"
check_contains "slot 3 unbound" "clevis luks unbind -d /dev/sda -s 3" "$(cat "$TS_LOG")"
collect_now
check "multi-slot arm -> ARMED" "ARMED" "$(classify_inventory)"

reset_env; fixture_clevis_multi
export TS_CLEVIS_FAIL_SLOT=3
out=$(printf 'ARM\n' | arm_travel_mode 2>&1 || true)
check_contains "midway failure -> ERROR" "ERROR" "$out"
check_not_contains "no false success on failure" "passphrase required at next boot" "$out"
collect_now
check "midway failure leaves binding" "DISARMED" "$(classify_inventory)"

reset_env; fixture_clevis_pcr7
export TS_CLEVIS_CANCEL=1
out=$(printf 'ARM\n' | arm_travel_mode 2>&1 || true)
check_contains "cancel/no-change -> ERROR" "ERROR" "$out"
check_not_contains "cancel must not claim ARMED" "passphrase required at next boot" "$out"
collect_now
check "cancel leaves binding" "DISARMED" "$(classify_inventory)"

reset_env; fixture_mixed
out=$(printf 'ARM\n' | arm_travel_mode 2>&1 || true)
collect_now
check "mixed arm -> ARMED" "ARMED" "$(classify_inventory)"
check_contains "mixed arm wipes systemd" "systemd-cryptenroll --wipe-slot=tpm2 /dev/sda" "$(cat "$TS_LOG")"
check_contains "mixed arm unbinds clevis" "clevis luks unbind -d /dev/sda -s 2" "$(cat "$TS_LOG")"

reset_env; fixture_no_survivors
out=$(printf 'ARM\n' | arm_travel_mode 2>&1 || true)
check_contains "zero survivors refuses" "REFUSING" "$out"
check_not_contains "no removal with zero survivors" "clevis luks unbind" "$(cat "$TS_LOG")"
check_not_contains "no wipe with zero survivors" "systemd-cryptenroll --wipe" "$(cat "$TS_LOG")"

reset_env; fixture_survivor_tang_referenced
out=$(printf 'ARM\n' | arm_travel_mode 2>&1 || true)
check_contains "tang-referenced slot not a survivor -> refuse" "REFUSING" "$out"

reset_env; fixture_clevis_pcr7
out=$(printf 'no\n' | arm_travel_mode 2>&1 || true)
check_contains "wrong ack cancels" "Cancelled" "$out"
collect_now
check "wrong ack leaves state" "DISARMED" "$(classify_inventory)"
check_not_contains "no removal after cancel" "clevis luks unbind" "$(cat "$TS_LOG")"

reset_env; fixture_clevis_pcr7
export TS_SUDO_DENIED=1
out=$(printf 'ARM\n' | arm_travel_mode 2>&1 || true)
check_contains "sudo denied -> fail closed" "no changes made" "$out"
check_not_contains "no removal without sudo" "clevis luks unbind" "$(cat "$TS_LOG")"
TS_SUDO_DENIED=1
if ensure_sudo 2>/dev/null; then bad "ensure_sudo fails without sudo (expected failure)"; else ok "ensure_sudo fails without sudo"; fi
export TS_SUDO_DENIED=0

reset_env; fixture_malformed
out=$(printf 'ARM\n' | arm_travel_mode 2>&1 || true)
check_contains "UNKNOWN refuses arming" "UNKNOWN" "$out"
check_not_contains "no removal from unknown" "clevis luks unbind" "$(cat "$TS_LOG")"

printf '== Disarming ==\n'

reset_env; fixture_no_tokens
out=$(printf 'y\n' | disarm_travel_mode 2>&1 || true)
check_contains "disarm systemd success" "DISARMED" "$out"
check_contains "systemd enrolls PCR7 sha256" "--tpm2-pcrs=7:sha256" "$(cat "$TS_LOG")"
collect_now
check "post-enroll state DISARMED" "DISARMED" "$(classify_inventory)"
check "fingerprint stored after enroll" "1" "$([[ -f "$TS_STATE_DIR/pcr7-${TS_UUID}.sha256" ]] && echo 1 || echo 0)"

reset_env; fixture_no_tokens
PATH="$WORK/hide-systemd-cryptenroll"
out=$(printf 'y\n' | disarm_travel_mode 2>&1 || true)
check_contains "disarm clevis success" "DISARMED" "$out"
check_contains "clevis binds exact PCR7 config" '{"pcr_bank":"sha256","pcr_ids":"7"}' "$(cat "$TS_LOG")"
check_not_contains "no legacy {} binding" "tpm2 '{}'" "$(cat "$TS_LOG")"
collect_now
check "post-clevis-enroll DISARMED" "DISARMED" "$(classify_inventory)"
s=$(inventory_summary)
check_contains "new binding is pcr7" "|pcr7" "$s"
PATH="$ROOT/tests/bin:$ORIG_PATH"

reset_env; fixture_systemd_one
out=$(printf 'y\n' | disarm_travel_mode 2>&1 || true)
check_contains "already configured -> direct to re-enroll" "already configured" "$out"
check_not_contains "no duplicate enrollment" "systemd-cryptenroll --tpm2-device" "$(cat "$TS_LOG")"

reset_env; fixture_no_tokens
export TS_SYSTEMD_FAIL=1
out=$(printf 'y\n' | disarm_travel_mode 2>&1 || true)
check_contains "enroll failure -> error" "enrollment failed" "$out"
check_not_contains "enroll failure no success" "DISARMED — TPM auto-unlock enabled" "$out"

printf '== Re-enrollment ==\n'

reset_env; fixture_clevis_legacy
PATH="$WORK/hide-systemd-cryptenroll"
out=$(printf 'ARM\n' | reenroll_binding 2>&1 || true)
check_contains "re-enroll legacy success" "DISARMED" "$out"
check "legacy re-enroll -> exactly one clevis pcr7" "1" "$(jq -r '[.tokens | to_entries[] | select(.value.type=="clevis")] | length' "$TS_HEADER")"
collect_now
s=$(inventory_summary)
check_contains "re-enrolled binding pcr7" "|pcr7" "$s"
PATH="$ROOT/tests/bin:$ORIG_PATH"

reset_env; fixture_mixed
out=$(printf 'ARM\n' | reenroll_binding 2>&1 || true)
check_contains "mixed re-enroll success" "DISARMED" "$out"
check "mixed re-enroll -> exactly one systemd token" "1" "$(jq -r '[.tokens | to_entries[] | select(.value.type=="systemd-tpm2")] | length' "$TS_HEADER")"
check "mixed re-enroll -> no clevis tokens" "0" "$(jq -r '[.tokens | to_entries[] | select(.value.type=="clevis")] | length' "$TS_HEADER")"
check_contains "old systemd keyslot wiped by number" "--wipe-slot=1" "$(cat "$TS_LOG")"
check_not_contains "replacement not type-wiped" "--wipe-slot=tpm2" "$(cat "$TS_LOG")"

reset_env; fixture_mixed
export TS_SYSTEMD_FAIL=1
out=$(printf 'ARM\n' | reenroll_binding 2>&1 || true)
check_contains "enroll-fail re-enroll -> error" "enrollment failed" "$out"
check "enroll-fail leaves old systemd" "1" "$(jq -r '[.tokens | to_entries[] | select(.value.type=="systemd-tpm2")] | length' "$TS_HEADER")"
check "enroll-fail leaves old clevis" "1" "$(jq -r '[.tokens | to_entries[] | select(.value.type=="clevis")] | length' "$TS_HEADER")"

reset_env; fixture_no_survivors
out=$(printf 'ARM\n' | reenroll_binding 2>&1 || true)
check_contains "re-enroll zero survivors refused" "REFUSING" "$out"
check "refusal keeps old systemd plus new" "2" "$(jq -r '[.tokens | to_entries[] | select(.value.type=="systemd-tpm2")] | length' "$TS_HEADER")"
check "refusal keeps old clevis" "1" "$(jq -r '[.tokens | to_entries[] | select(.value.type=="clevis")] | length' "$TS_HEADER")"

# No-op enrollment: command succeeds but no NEW token appears.  The old
# systemd token already has the exact PCR7 policy — set-difference must
# still reject it as the "replacement".
reset_env; fixture_systemd_one
export TS_SYSTEMD_NOOP=1
out=$(printf 'ARM\n' | reenroll_binding 2>&1 || true)
check_contains "no-op systemd enroll not accepted as replacement" "staged systemd replacement not verified" "$out"
check "no-op leaves old systemd" "1" "$(jq -r '[.tokens | to_entries[] | select(.value.type=="systemd-tpm2")] | length' "$TS_HEADER")"

reset_env; fixture_clevis_legacy
export TS_CLEVIS_NOOP=1
PATH="$WORK/hide-systemd-cryptenroll"
out=$(printf 'ARM\n' | reenroll_binding 2>&1 || true)
check_contains "no-op clevis bind not accepted as replacement" "staged clevis replacement not verified" "$out"
check "no-op leaves old clevis" "1" "$(jq -r '[.tokens | to_entries[] | select(.value.type=="clevis")] | length' "$TS_HEADER")"
PATH="$ROOT/tests/bin:$ORIG_PATH"

reset_env; fixture_clevis_legacy
export TS_CLEVIS_FAIL_SLOT=2
PATH="$WORK/hide-systemd-cryptenroll"
out=$(printf 'ARM\n' | reenroll_binding 2>&1 || true)
check_contains "re-enroll failure -> ERROR" "ERROR" "$out"
check_not_contains "re-enroll failure no success" "Re-enrolled" "$out"
PATH="$ROOT/tests/bin:$ORIG_PATH"

reset_env; fixture_mixed
export TS_SYSTEMD_WIPE_FAIL=1
out=$(printf 'ARM\n' | reenroll_binding 2>&1 || true)
check_contains "systemd wipe-fail-after-enroll -> ERROR" "ERROR" "$out"
check_not_contains "wipe-fail no success" "Re-enrolled" "$out"
check "wipe-fail leaves systemd tokens" "2" "$(jq -r '[.tokens | to_entries[] | select(.value.type=="systemd-tpm2")] | length' "$TS_HEADER")"

reset_env; fixture_clevis_pcr7
export TS_CLEVIS_FAIL_SLOT=2
arm_travel_mode <<< 'ARM' >"$WORK/arm1.txt" 2>&1 || true
st=$(menu_status)
check_contains "menu shows ERROR after failed arm" "ERROR" "$st"
check_not_contains "menu never ARMED after failure" "ARMED — passphrase required" "$st"
export TS_CLEVIS_FAIL_SLOT=
arm_travel_mode <<< 'ARM' >"$WORK/arm2.txt" 2>&1 || true
st=$(menu_status)
check_contains "menu recovers after verified success" "ARMED — passphrase required" "$st"

printf '== TUI smoke (real /dev/tpm0 present, stubs elsewhere) ==\n'

if [[ -e /dev/tpm0 || -e /dev/tpmrm0 ]]; then
    reset_env; fixture_no_tokens
    out=$(printf 'q\n' | bash -c 'source "$1"; main ""' _ "$ROOT/travelshield.sh" 2>&1 || true)
    check_contains "TUI shows ARMED" "ARMED" "$out"

    reset_env; fixture_systemd_one
    out=$(printf 'q\n' | bash -c 'source "$1"; main ""' _ "$ROOT/travelshield.sh" 2>&1 || true)
    check_contains "TUI shows DISARMED" "DISARMED" "$out"

    reset_env; fixture_malformed
    out=$(printf 'q\n' | bash -c 'source "$1"; main ""' _ "$ROOT/travelshield.sh" 2>&1 || true)
    check_contains "TUI shows UNKNOWN" "UNKNOWN" "$out"

    reset_env; fixture_tang
    out=$(printf 'q\n' | bash -c 'source "$1"; main ""' _ "$ROOT/travelshield.sh" 2>&1 || true)
    check_contains "TUI shows ARMED (TPM) for unmanaged" "non-TPM auto-unlock still configured" "$out"
else
    echo "  skip - no /dev/tpm* on this host (TUI smoke)"
fi

printf '== Misc ==\n'

check "sourcing does not run main" "OK" "$(bash -c 'source "$1" >/dev/null 2>&1; echo OK' _ "$ROOT/travelshield.sh")"
check "version string" "TravelShield 2.0.3" "$("$ROOT/travelshield.sh" --version)"

# ── Summary ──
echo
echo "Passed: $PASS   Failed: $FAIL"
if (( FAIL > 0 )); then
    printf 'Failed tests:\n'
    for n in "${FAILED_NAMES[@]}"; do printf '  - %s\n' "$n"; done
    exit 1
fi
echo "All tests passed."
