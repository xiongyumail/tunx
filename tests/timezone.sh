#!/usr/bin/env bash
# Time zone and WSL configuration tests. Only temporary files are changed.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# shellcheck source-path=SCRIPTDIR/..
. ./install.sh
ZONEINFO_DIR=$tmp/zoneinfo
mkdir -p "$ZONEINFO_DIR/Etc" "$ZONEINFO_DIR/Europe" "$ZONEINFO_DIR/Asia"
touch "$ZONEINFO_DIR/Etc/UTC" "$ZONEINFO_DIR/Europe/London" "$ZONEINFO_DIR/Asia/Tokyo"
fail() { echo "FAIL: $*" >&2; exit 1; }
is_wsl() { true; }
curl() { printf '{"timezone":"%s"}\n' "$target"; }
timedatectl() {
    case "$1" in
        show) [ "$lookup_fail" = 0 ] || return 1; cat "$case_dir/current" ;;
        set-timezone)
            printf '%s\n' "$2" >>"$case_dir/set.calls"
            [ "$set_fail" = 0 ] || return 1
            printf '%s\n' "$2" >"$case_dir/current" ;;
        *) fail "unexpected timedatectl command: $*" ;;
    esac
}
fresh_case() {
    case_dir=$(mktemp -d "$tmp/case.XXXXXX")
    STATE_DIR=$case_dir/state
    WSL_CONF=$case_dir/wsl.conf
    TIMEZONE_FILE=$case_dir/timezone
    mkdir "$STATE_DIR"
    printf 'Etc/UTC\n' >"$case_dir/current"
    printf 'Etc/UTC\n\n# original bytes without a final newline' >"$TIMEZONE_FILE"
    printf '[network]\ngenerateResolvConf=true\n' >"$WSL_CONF"
    target=Europe/London lookup_fail=0 set_fail=0
}
expect_failure() {
    if ("$@") >"$case_dir/out" 2>"$case_dir/err"; then fail "unexpected success: $*"; fi
}
uninstall_must_stop() (
    systemctl() { fail 'uninstall reached host operations'; }
    cmd_uninstall
)

fresh_case
cp "$TIMEZONE_FILE" "$case_dir/exact"
cp "$WSL_CONF" "$case_dir/wsl-exact"
cmd_tz >"$case_dir/out"
grep -qx 'Etc/UTC' "$STATE_DIR/timezone.orig" || fail 'first zone not saved'
grep -qx present "$STATE_DIR/timezone.file.state" || fail 'file presence not saved'
cmp -s "$case_dir/exact" "$STATE_DIR/timezone.file.orig" || fail 'file backup is not exact'
grep -qx 'Europe/London' "$TIMEZONE_FILE" || fail 'time zone file not updated'
grep -q 'Windows time zone is unchanged' "$case_dir/out" || fail 'Windows scope missing'
grep -q 'Running applications' "$case_dir/out" || fail 'application cache notice missing'
target=Asia/Tokyo
cmd_tz >"$case_dir/out"
grep -qx 'Etc/UTC' "$STATE_DIR/timezone.orig" || fail 'repeat replaced original zone'
cmp -s "$case_dir/exact" "$STATE_DIR/timezone.file.orig" || fail 'repeat replaced file backup'
cmp -s "$case_dir/wsl-exact" "$STATE_DIR/wsl.conf.orig" || fail 'repeat replaced WSL backup'
restore_timezone >"$case_dir/out"
grep -qx 'Etc/UTC' "$case_dir/current" || fail 'zone not restored'
cmp -s "$case_dir/exact" "$TIMEZONE_FILE" || fail 'file restoration is not exact'
echo 'ok: first save, repeated tz and exact file restoration'

for failure in empty lookup; do
    fresh_case
    if [ "$failure" = empty ]; then : >"$case_dir/current"; else lookup_fail=1; fi
    cp "$WSL_CONF" "$case_dir/wsl-exact"
    expect_failure cmd_tz
    grep -q 'cannot read .*original Linux time zone' "$case_dir/err" || fail 'missing lookup error'
    [ ! -e "$STATE_DIR/timezone.orig" ] || fail 'failed lookup saved a fake zone'
    [ ! -e "$case_dir/set.calls" ] || fail 'failed lookup changed the zone'
    cmp -s "$WSL_CONF" "$case_dir/wsl-exact" || fail 'failed lookup changed WSL'
done
echo 'ok: failed or empty original-zone lookup stops before changes'

fresh_case
cp "$TIMEZONE_FILE" "$case_dir/exact"
set_fail=1
expect_failure cmd_tz
grep -q 'cannot set Linux time zone' "$case_dir/err" || fail 'missing set error'
cmp -s "$TIMEZONE_FILE" "$case_dir/exact" || fail 'failed set changed time zone file'
[ -r "$STATE_DIR/timezone.orig" ] || fail 'failed set lost backup'
if grep -q 'Linux time zone set to' "$case_dir/out"; then fail 'false set success'; fi
set_fail=0
cmd_tz >/dev/null
set_fail=1
expect_failure restore_timezone
grep -q 'cannot restore Linux time zone' "$case_dir/err" || fail 'missing restore error'
grep -qx 'Europe/London' "$TIMEZONE_FILE" || fail 'failed restore changed time zone file'
[ -r "$STATE_DIR/timezone.orig" ] || fail 'failed restore lost backup'
if grep -q 'Restored Linux time zone' "$case_dir/out"; then fail 'false restore success'; fi
# Uninstall must return before removing state or reaching host operations.
expect_failure uninstall_must_stop
grep -q 'cannot restore Linux time zone' "$case_dir/err" || fail 'uninstall reached host operations'
[ -r "$STATE_DIR/timezone.orig" ] || fail 'uninstall deleted failed-restore state'
echo 'ok: failed set/restore retain backups and stop uninstall'

fresh_case
cmd_tz >/dev/null
(
    # Called by restore_timezone from the sourced installer.
    # shellcheck disable=SC2329
    cp() { return 1; }
    expect_failure restore_timezone
    grep -q 'cannot restore .*timezone' "$case_dir/err" || fail 'missing file restore error'
    [ -r "$STATE_DIR/timezone.orig" ] || fail 'file restore failure lost backup'
    if grep -q 'Restored Linux time zone' "$case_dir/out"; then fail 'false file restore success'; fi
    expect_failure uninstall_must_stop
    grep -q 'cannot restore .*timezone' "$case_dir/err" || fail 'uninstall reached host operations'
    [ -r "$STATE_DIR/timezone.file.orig" ] || fail 'uninstall lost exact file backup'
)
echo 'ok: failed exact file restoration retains state'

fresh_case
rm "$TIMEZONE_FILE"
cmd_tz >/dev/null
grep -qx absent "$STATE_DIR/timezone.file.state" || fail 'original absence not saved'
printf 'Europe/London\n' >"$TIMEZONE_FILE"
(
    # Called by restore_timezone from the sourced installer.
    # shellcheck disable=SC2329
    rm() { return 1; }
    expect_failure restore_timezone
    grep -q 'cannot remove .*restore its absence' "$case_dir/err" || fail 'missing absence restore error'
    [ -r "$STATE_DIR/timezone.orig" ] || fail 'absence restore failure lost backup'
)
restore_timezone >/dev/null
[ ! -e "$TIMEZONE_FILE" ] || fail 'originally absent file not removed'
echo 'ok: originally absent file, including removal failure'

for presence in present absent; do
    fresh_case
    printf 'Etc/UTC\n' >"$STATE_DIR/timezone.orig"
    printf 'Europe/London\n' >"$case_dir/current"
    if [ "$presence" = absent ]; then rm "$TIMEZONE_FILE"; fi
    cmd_tz >/dev/null
    [ ! -e "$STATE_DIR/timezone.file.state" ] || fail 'legacy state invented exact backup'
    restore_timezone >/dev/null
    grep -qx 'Etc/UTC' "$case_dir/current" || fail 'legacy zone not restored'
    if [ "$presence" = present ]; then
        grep -qx 'Etc/UTC' "$TIMEZONE_FILE" || fail 'legacy existing file not updated'
    else
        [ ! -e "$TIMEZONE_FILE" ] || fail 'legacy missing file created'
    fi
done
echo 'ok: legacy zone-only backups preserve compatibility'

fresh_case
cp "$WSL_CONF" "$case_dir/wsl-exact"
(
    # Called by the sourced WSL updater.
    # shellcheck disable=SC2329
    cp() {
        # Leave a partial destination just as a failed filesystem copy can.
        printf 'partial' >"$2"
        return 1
    }
    expect_failure wsl_conf_set time useWindowsTimezone false
)
[ ! -e "$STATE_DIR/wsl.conf.orig" ] || fail 'failed copy published a WSL backup'
cmp -s "$case_dir/wsl-exact" "$WSL_CONF" || fail 'failed backup changed WSL configuration'
if compgen -G "$STATE_DIR/wsl.conf.orig.*" >/dev/null; then fail 'failed WSL copy left a temporary backup'; fi
wsl_conf_set time useWindowsTimezone false
cmp -s "$case_dir/wsl-exact" "$STATE_DIR/wsl.conf.orig" || fail 'retry did not save an exact WSL backup'
[ "$(stat -c %a "$STATE_DIR/wsl.conf.orig")" = 600 ] || fail 'WSL backup permissions are not restrictive'
wsl_conf_set network generateResolvConf false
cmp -s "$case_dir/wsl-exact" "$STATE_DIR/wsl.conf.orig" || fail 'later update replaced WSL backup'
# Only the WSL branch of restore_dns is enabled by these isolated paths.
NM_CONF=$case_dir/no-network-manager-config
restore_dns >/dev/null
cmp -s "$case_dir/wsl-exact" "$WSL_CONF" || fail 'retry backup did not restore WSL exactly'
echo 'ok: partial WSL backup failure cleans up; retry and restoration are exact'

fresh_case
cp "$WSL_CONF" "$case_dir/wsl-exact"
wsl_conf_set time useWindowsTimezone false &
time_update=$!
wsl_conf_set network generateResolvConf false &
dns_update=$!
wait "$time_update"
wait "$dns_update"
cmp -s "$case_dir/wsl-exact" "$STATE_DIR/wsl.conf.orig" || fail 'concurrent updates replaced the original backup'
grep -qx 'useWindowsTimezone=false' "$WSL_CONF" || fail 'concurrent update lost time setting'
grep -qx 'generateResolvConf=false' "$WSL_CONF" || fail 'concurrent update lost DNS setting'
echo 'ok: concurrent WSL updates retain one original backup and both settings'

fresh_case
cat >"$WSL_CONF" <<'EOF'
# comment
[other]
useWindowsTimezone=true
generateResolvConf=true
  [ time ] ; section comment
  # useWindowsTimezone=true
  useWindowsTimezone = true  # keep comment
other=value
[network]
  generateResolvConf = true ; DNS comment
[time]
useWindowsTimezone=true
EOF
cp "$WSL_CONF" "$case_dir/wsl-exact"
wsl_conf_set time useWindowsTimezone false
wsl_conf_set network generateResolvConf false
python3 -I - "$WSL_CONF" <<'EOF'
import sys
text = open(sys.argv[1]).read()
assert '[other]\nuseWindowsTimezone=true\ngenerateResolvConf=true' in text
assert '  # useWindowsTimezone=true' in text
assert '  useWindowsTimezone = false  # keep comment' in text
assert '[time]\nuseWindowsTimezone=false' in text
assert '  generateResolvConf = false ; DNS comment' in text
assert 'other=value' in text
EOF
cmp -s "$case_dir/wsl-exact" "$STATE_DIR/wsl.conf.orig" || fail 'original WSL config not retained'
timezone_status >"$case_dir/status"
grep -q 'Time zone: Etc/UTC (Linux)' "$case_dir/status" || fail 'Linux zone missing from status'
grep -q 'WSL time sync: false (configured; applies after distribution restart; Windows unchanged)' "$case_dir/status" || fail 'WSL status incorrect'
echo 'ok: section-aware WSL updates preserve indentation, comments and unrelated keys'

for formatting in missing-section empty-section missing-newline crlf; do
    fresh_case
    case "$formatting" in
        missing-section) printf '[other]\nuseWindowsTimezone=true\n' >"$WSL_CONF" ;;
        empty-section) printf '  [time] # comment\n[other]\nuseWindowsTimezone=true\n' >"$WSL_CONF" ;;
        missing-newline) printf '[time]' >"$WSL_CONF" ;;
        crlf) printf '[time]\r\n  useWindowsTimezone = true ; comment\r\n' >"$WSL_CONF" ;;
    esac
    wsl_conf_set time useWindowsTimezone false
    timezone_status >"$case_dir/status"
    grep -q 'WSL time sync: false' "$case_dir/status" || fail "WSL formatting: $formatting"
    if [ "$formatting" = crlf ]; then
        python3 -I - "$WSL_CONF" <<'EOF'
import sys
data = open(sys.argv[1], 'rb').read()
assert data == b'[time]\r\n  useWindowsTimezone = false ; comment\r\n'
EOF
    fi
done
echo 'ok: missing section/key, final newline and CRLF WSL formats'
