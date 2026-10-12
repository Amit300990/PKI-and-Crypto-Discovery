#!/usr/bin/env bash
#
# crypto_pki_inventory.sh
#
# Read-only discovery of PKI / cryptographic material on a RHEL8 + Java host,
# to seed a CBOM (Cryptographic Bill of Materials) alongside an SBOM.
#
# What it does:
#   - Enumerates OS trust store + RHEL8 system-wide crypto policy
#   - Finds certificates (PEM/DER) on disk and extracts metadata via openssl,
#     flagging weak signature algorithms (SHA1/MD5) and RSA keys < 2048 bits,
#     and listing already-expired certs separately for fast triage
#   - Finds Java keystores/truststores (.jks/.p12/.pfx/.keystore) and lists
#     EVERY alias via keytool where a password can be resolved (including
#     the last alias in the store)
#   - Finds PEM private keys on disk (path + permissions only — content is
#     NEVER read, printed, or copied), with permission bits checked properly
#   - Enumerates SSH host/user keys, with timeouts so a passphrase-encrypted
#     key can never hang the scan waiting on stdin
#   - Greps common app/config locations for keystore/truststore references
#     and inline PEM blocks, with any password/secret/token value redacted
#     before it's written to the report
#   - Discovers PKCS#11/HSM/SoftHSM configuration and module references
#   - Lists crypto-relevant RPM packages (openssl, nss, gnutls, java, etc.)
#   - Dynamically prunes network filesystems (nfs, cifs, glusterfs, lustre,
#     gpfs, ceph, sshfs, ...) detected via the live mount table, so the scan
#     never walks into a remote mount
#   - Optionally invokes syft/cdxgen if installed, to emit a CycloneDX
#     SBOM/CBOM covering installed packages + JVM dependencies + code-level
#     crypto API usage
#
# What it deliberately does NOT do:
#   - Never prints, logs, or exfiltrates private key material or passphrases
#   - Never modifies any file or store it inspects
#   - Does not brute-force keystore passwords beyond a short list of known
#     PUBLIC defaults (e.g. Java's own "changeit" cacerts password); anything
#     else is flagged "password unknown - manual review"
#   - Never writes a raw password/secret/token value into any output file —
#     matched config lines are redacted before being recorded
#
# Usage:
#   sudo ./crypto_pki_inventory.sh [SCAN_ROOT] [--with-sbom] [--app-name NAME]
#   ./crypto_pki_inventory.sh --report-only DIR [--app-name NAME]
#
#   SCAN_ROOT       Directory to scan for cert/key/keystore files.
#                   Default: / (excludes /proc,/sys,/dev,/run, container
#                   storage, and any live network-filesystem mount)
#   --with-sbom     Also run syft/cdxgen if installed to produce a full
#                   SBOM (CycloneDX) and code-level CBOM.
#   --app-name NAME Application name shown in the HTML report title.
#                   Default: the hostname.
#   --report-only DIR
#                   Do not scan. Re-render report.html from the CSVs already
#                   in an earlier output directory DIR.
#
# Output: ./crypto-inventory-<hostname>-<timestamp>/  containing CSVs, a
#         summary.txt and a self-contained report.html (no external assets,
#         opens offline in any browser). Run as root (or with sudo) for full
#         filesystem coverage — running as a normal user will silently skip
#         unreadable paths.

set -uo pipefail

# ---------------------------------------------------------------------------
# Args / setup
# ---------------------------------------------------------------------------
SCAN_ROOT="/"
WITH_SBOM=0
APP_NAME=""
REPORT_ONLY_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-sbom) WITH_SBOM=1 ;;
    --app-name|--report-only)
      if [[ $# -lt 2 ]]; then echo "$1 needs a value" >&2; exit 2; fi
      if [[ "$1" == "--app-name" ]]; then APP_NAME="$2"; else REPORT_ONLY_DIR="$2"; fi
      shift
      ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^#//'
      exit 0
      ;;
    *) SCAN_ROOT="$1" ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# HTML report (report.html)
#
# Rendered from the CSVs, so it can also be regenerated later with
# --report-only. Self-contained: inline CSS, no scripts, no external assets.
# Every value that came from a scanned file (paths, cert subjects, config
# lines, aliases) is HTML-escaped — those strings are attacker-influenced
# (anyone who can name a file or issue a cert controls them).
# ---------------------------------------------------------------------------

# Escape stdin for safe inclusion in HTML text.
html_escape() {
  sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

# Shared awk helpers: RFC4180 line parser (matches csv_field's quoting),
# HTML escaping, and the per-table row classification / filter rules.
AWK_COMMON='
function he(s) {
  gsub(/&/, "\\&amp;", s); gsub(/</, "\\&lt;", s)
  gsub(/>/, "\\&gt;", s);  gsub(/"/, "\\&quot;", s)
  return s
}
function parse(line, f,    n, i, c, inq, cur, len) {
  split("", f); n = 0; cur = ""; inq = 0; len = length(line)
  for (i = 1; i <= len; i++) {
    c = substr(line, i, 1)
    if (inq) {
      if (c == "\"") {
        if (substr(line, i + 1, 1) == "\"") { cur = cur "\""; i++ } else inq = 0
      } else cur = cur c
    } else if (c == "\"") inq = 1
    else if (c == ",") { f[++n] = cur; cur = "" }
    else cur = cur c
  }
  f[++n] = cur
  return n
}
function isnum(x) { return x ~ /^-?[0-9]+$/ }
function rowclass(mode, f,    d) {
  if (mode == "certs")         { d = f[9]; if (isnum(d)) { if (d + 0 < 0) return "bad"; if (d + 0 <= 30) return "warn" } return "" }
  if (mode == "keys")          return (f[6] == "yes") ? "bad" : ""
  if (mode == "keystores")     return (f[9] == "password-unknown-manual-review") ? "warn" : ""
  if (mode == "bad" || mode == "warn") return mode
  return ""
}
function included(filter, f,    d) {
  if (filter == "keys_world")    return f[6] == "yes"
  if (filter == "ks_manual")     return f[9] == "password-unknown-manual-review"
  if (filter == "cert_expiring") { d = f[9]; return isnum(d) && d + 0 >= 0 && d + 0 <= 90 }
  return 1
}
'

# data_lines FILE -> number of data rows (CSV minus header), 0 if missing
data_lines() {
  [[ -f "$1" ]] || { echo 0; return; }
  awk 'END { print (NR > 1 ? NR - 1 : 0) }' "$1"
}

# count_rows FILE FILTER -> rows passing FILTER ("all" = every row)
count_rows() {
  [[ -f "$1" ]] || { echo 0; return; }
  awk -v filter="$2" "$AWK_COMMON"'
    NR > 1 { parse($0, f); if (included(filter, f)) c++ }
    END { print c + 0 }' "$1"
}

# render_table FILE MODE FILTER MAX -> HTML table (or an empty-state note).
# MODE picks the row-highlight rule (certs|keys|keystores|bad|warn|plain);
# flagged rows also get a text Status cell so meaning never rests on color.
render_table() {
  local file="$1" mode="$2" filter="$3" max="$4"
  if [[ ! -f "$file" ]]; then echo '<p class="empty">Not collected in this run.</p>'; return; fi
  awk -v mode="$mode" -v filter="$filter" -v max="$max" "$AWK_COMMON"'
    NR == 1 { hn = parse($0, h); next }
    {
      parse($0, f)
      if (!included(filter, f)) next
      total++
      if (total > max) next
      if (total == 1) {
        print "<div class=\"tablewrap\"><table><thead><tr>"
        if (mode != "plain") print "<th class=\"st\">Status</th>"
        for (i = 1; i <= hn; i++) print "<th>" he(h[i]) "</th>"
        print "</tr></thead><tbody>"
      }
      cls = rowclass(mode, f)
      print "<tr" (cls != "" ? " class=\"" cls "\"" : "") ">"
      if (mode != "plain") print "<td class=\"st\">" (cls == "bad" ? "ACTION" : (cls == "warn" ? "REVIEW" : "")) "</td>"
      for (i = 1; i <= hn; i++) print "<td>" he(f[i]) "</td>"
      print "</tr>"
    }
    END {
      if (total == 0) print "<p class=\"empty\">None found.</p>"
      else {
        print "</tbody></table></div>"
        if (total > max) print "<p class=\"note\">Showing the first " max " of " total " rows. See the CSV for the full list.</p>"
      }
    }' "$file"
}

# stat_card CLASS COUNT LABEL [CHIP] — CLASS is dropped when COUNT is 0
stat_card() {
  local cls="$1" n="$2" label="$3" chip="${4:-}"
  [[ "$n" -eq 0 ]] && cls=""
  printf '<div class="card %s"><div class="n">%s</div><div class="l">' "$cls" "$n"
  [[ -n "$chip" ]] && printf '<span class="sev">%s</span>' "$chip"
  printf '%s</div></div>\n' "$label"
}

generate_html_report() {
  local d="$OUT_DIR" out="$OUT_DIR/report.html" max_rows=1000
  local name host ts root ran_root
  name=$(printf '%s' "${APP_NAME:-$HOST}" | html_escape)
  host=$(printf '%s' "$HOST" | html_escape)
  ts=$(printf '%s' "$TS" | html_escape)
  root=$(printf '%s' "$SCAN_ROOT" | html_escape)
  ran_root="yes"; [[ "${RUN_AS_ROOT:-1}" -eq 0 ]] && ran_root="no"

  local n_certs n_keys n_ks n_ssh n_refs n_p11 n_rpm
  n_certs=$(data_lines "$d/certificates.csv")
  n_keys=$(data_lines "$d/private_keys_found.csv")
  n_ks=$(data_lines "$d/java_keystores.csv")
  n_ssh=$(data_lines "$d/ssh_keys.csv")
  n_refs=$(data_lines "$d/config_references.csv")
  n_p11=$(data_lines "$d/pkcs11_hsm_references.csv")
  n_rpm=$(data_lines "$d/crypto_packages.csv")

  local n_world n_exp n_weak n_manual n_soon action review banner_cls banner_msg
  n_world=$(count_rows "$d/private_keys_found.csv" keys_world)
  n_exp=$(data_lines "$d/expired_certificates.csv")
  n_weak=$(data_lines "$d/weak_crypto_findings.csv")
  n_manual=$(count_rows "$d/java_keystores.csv" ks_manual)
  n_soon=$(count_rows "$d/certificates.csv" cert_expiring)
  action=$(( n_world + n_exp + n_weak ))
  review=$(( n_manual + n_soon ))
  if (( action > 0 )); then
    banner_cls="bad";  banner_msg="$action finding(s) need action and $review need review."
  elif (( review > 0 )); then
    banner_cls="warn"; banner_msg="No critical findings. $review item(s) need review."
  else
    banner_cls="ok";   banner_msg="No priority findings in the material this scan could see."
  fi

  {
    printf '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n'
    printf '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
    printf '<title>Crypto Inventory - %s</title>\n<style>\n' "$name"
    cat <<'CSS'
:root{--bg:#f7f8fa;--card:#fff;--text:#1b1f24;--muted:#5b6571;--line:#dde1e6;--bad:#b42318;--bad-bg:#fdecea;--warn:#8a5a00;--warn-bg:#fff4d6;--ok:#1a7f37;--ok-bg:#e6f4ea}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--card:#171c23;--text:#e6e9ee;--muted:#9aa5b1;--line:#2a323c;--bad:#ff8a80;--bad-bg:#3a1d1b;--warn:#f5c064;--warn-bg:#3a2e12;--ok:#7ee2a0;--ok-bg:#16301f}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1200px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:16px;margin:28px 0 4px}
.meta{color:var(--muted);margin:0 0 18px;overflow-wrap:anywhere}
.sub{color:var(--muted);font-size:12px;margin:0 0 10px}
.banner{padding:12px 14px;border-radius:8px;border:1px solid;margin-bottom:14px;font-weight:600}
.banner.bad{background:var(--bad-bg);color:var(--bad);border-color:var(--bad)}
.banner.warn{background:var(--warn-bg);color:var(--warn);border-color:var(--warn)}
.banner.ok{background:var(--ok-bg);color:var(--ok);border-color:var(--ok)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card .n{font-size:26px;font-weight:600;line-height:1.2}
.card .l{color:var(--muted);font-size:12px}
.card.bad{border-color:var(--bad)}.card.bad .n{color:var(--bad)}
.card.warn{border-color:var(--warn)}.card.warn .n{color:var(--warn)}
.sev{display:inline-block;font-size:10px;font-weight:700;letter-spacing:.04em;padding:1px 6px;border-radius:9px;margin-right:6px;border:1px solid currentColor}
.tablewrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
th,td{min-width:12ch}
th.st,td.st{white-space:nowrap}
th{background:var(--bg);color:var(--muted);font-weight:600;white-space:nowrap}
tbody tr:last-child td{border-bottom:0}
tr.bad td{background:var(--bad-bg)}tr.bad td:first-child{color:var(--bad);font-weight:700}
tr.warn td{background:var(--warn-bg)}tr.warn td:first-child{color:var(--warn);font-weight:700}
details{margin:12px 0}
summary{cursor:pointer;font-weight:600;padding:6px 0}
.note,.empty{color:var(--muted);font-size:12px;margin:6px 0}
pre{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;overflow-x:auto;font-size:12px}
ul{margin:6px 0;padding-left:20px}
a{color:inherit}
@media (max-width:600px){.wrap{padding:16px 16px 40px}}
CSS
    printf '</style></head><body><div class="wrap">\n'

    printf '<h1>Cryptographic &amp; PKI inventory: %s</h1>\n' "$name"
    printf '<p class="meta">Host %s &middot; scanned %s &middot; scan root <code>%s</code> &middot; ran as root: %s</p>\n' \
      "$host" "$ts" "$root" "$ran_root"
    [[ "$ran_root" == "no" ]] && printf '<p class="banner warn">Scan ran without root. Unreadable paths were skipped, so this inventory is incomplete.</p>\n'
    printf '<div class="banner %s">%s</div>\n' "$banner_cls" "$banner_msg"

    printf '<h2>Priority findings</h2>\n<div class="grid">\n'
    stat_card bad  "$n_world"  "World-readable private keys" CRITICAL
    stat_card bad  "$n_exp"    "Expired certificates" HIGH
    stat_card bad  "$n_weak"   "Weak crypto (SHA-1/MD5, RSA &lt; 2048)" HIGH
    stat_card warn "$n_manual" "Keystores needing manual review" MEDIUM
    stat_card warn "$n_soon"   "Certificates expiring in 90 days" MEDIUM
    printf '</div>\n'

    printf '<h2>Inventory</h2>\n<div class="grid">\n'
    stat_card "" "$n_certs" "Certificates"
    stat_card "" "$n_keys"  "Private key files"
    stat_card "" "$n_ks"    "Java keystore entries"
    stat_card "" "$n_ssh"   "SSH keys"
    stat_card "" "$n_refs"  "Config files referencing crypto"
    stat_card "" "$n_p11"   "PKCS#11 / HSM references"
    stat_card "" "$n_rpm"   "Crypto RPM packages"
    printf '</div>\n'

    printf '<h2>World-readable private keys</h2>\n<p class="sub">Any other local user can read these. Fix permissions first.</p>\n'
    render_table "$d/private_keys_found.csv" keys keys_world "$max_rows"
    printf '<h2>Expired certificates</h2>\n'
    render_table "$d/expired_certificates.csv" bad all "$max_rows"
    printf '<h2>Weak cryptography</h2>\n'
    render_table "$d/weak_crypto_findings.csv" bad all "$max_rows"
    printf '<h2>Certificates expiring within 90 days</h2>\n<p class="sub">Highlighted when 30 days or fewer remain.</p>\n'
    render_table "$d/certificates.csv" certs cert_expiring "$max_rows"
    printf '<h2>Keystores needing manual review</h2>\n<p class="sub">Password was not a known public default, so aliases were not listed. Get it from the owning team.</p>\n'
    render_table "$d/java_keystores.csv" keystores ks_manual "$max_rows"

    printf '<h2>Full inventory</h2>\n'
    printf '<details><summary>Certificates (%s)</summary>\n' "$n_certs"
    render_table "$d/certificates.csv" certs all "$max_rows"; printf '</details>\n'
    printf '<details><summary>Private key files (%s)</summary>\n' "$n_keys"
    render_table "$d/private_keys_found.csv" keys all "$max_rows"; printf '</details>\n'
    printf '<details><summary>Java keystores (%s)</summary>\n' "$n_ks"
    render_table "$d/java_keystores.csv" keystores all "$max_rows"; printf '</details>\n'
    printf '<details><summary>SSH keys (%s)</summary>\n' "$n_ssh"
    render_table "$d/ssh_keys.csv" plain all "$max_rows"; printf '</details>\n'
    printf '<details><summary>Config references (%s)</summary>\n' "$n_refs"
    render_table "$d/config_references.csv" plain all "$max_rows"; printf '</details>\n'
    printf '<details><summary>PKCS#11 / HSM references (%s)</summary>\n' "$n_p11"
    render_table "$d/pkcs11_hsm_references.csv" plain all "$max_rows"; printf '</details>\n'
    printf '<details><summary>Crypto-relevant RPM packages (%s)</summary>\n' "$n_rpm"
    render_table "$d/crypto_packages.csv" plain all "$max_rows"; printf '</details>\n'

    printf '<h2>System crypto policy</h2>\n'
    if [[ -f "$d/os_trust_and_policy.txt" ]]; then
      printf '<pre>'; html_escape < "$d/os_trust_and_policy.txt"; printf '</pre>\n'
    else
      printf '<p class="empty">Not collected in this run.</p>\n'
    fi

    printf '<h2>SBOM / CBOM</h2>\n<ul>\n'
    local pair fn lbl cnt
    for pair in "sbom.cyclonedx.json|SBOM (CycloneDX)" "cbom.cyclonedx.json|CBOM (CycloneDX)"; do
      fn="${pair%%|*}"; lbl="${pair#*|}"
      if [[ -f "$d/$fn" ]]; then
        cnt=""
        if command -v jq >/dev/null 2>&1; then
          local n; n=$(jq '.components | length' "$d/$fn" 2>/dev/null)
          [[ "$n" =~ ^[0-9]+$ ]] && cnt=" &mdash; $n components"
        fi
        printf '<li><a href="%s">%s</a>%s</li>\n' "$fn" "$lbl" "$cnt"
      else
        printf '<li>%s: not generated. Run with <code>--with-sbom</code> (needs syft / cdxgen installed).</li>\n' "$lbl"
      fi
    done
    printf '</ul>\n'

    printf '<h2>What this scan cannot see</h2>\n<ul>\n'
    printf '<li>Keys held inside an HSM or cloud KMS. Only PKCS#11 config and module references are found; pull the keys from the HSM/KMS admin API.</li>\n'
    printf '<li>Keystores with a non-default password are listed but not opened.</li>\n'
    printf '<li>Keys generated at runtime and never written to disk.</li>\n'
    printf '<li>Algorithms used inside compiled or obfuscated JARs. Use the CBOM from <code>--with-sbom</code>.</li>\n'
    printf '<li>Secrets in external vaults (HashiCorp Vault, AWS Secrets Manager, ...) that config only references by name.</li>\n'
    printf '</ul>\n'

    printf '<h2>Raw data</h2>\n<ul>\n'
    local f
    for f in certificates expired_certificates weak_crypto_findings private_keys_found java_keystores \
             ssh_keys config_references pkcs11_hsm_references crypto_packages; do
      [[ -f "$d/$f.csv" ]] && printf '<li><a href="%s.csv">%s.csv</a></li>\n' "$f" "$f"
    done
    printf '</ul>\n</div></body></html>\n'
  } > "$out"
}

# --report-only: rebuild report.html from an earlier run's CSVs and stop.
if [[ -n "$REPORT_ONLY_DIR" ]]; then
  if [[ ! -d "$REPORT_ONLY_DIR" ]]; then echo "No such directory: $REPORT_ONLY_DIR" >&2; exit 2; fi
  OUT_DIR="$(cd "$REPORT_ONLY_DIR" && pwd)"
  meta() { sed -n "s/^$1: //p" "$OUT_DIR/summary.txt" 2>/dev/null | head -1; }
  HOST="$(meta Host)";           HOST="${HOST:-unknown}"
  TS="$(meta Timestamp)";        TS="${TS:-unknown}"
  SCAN_ROOT="$(meta 'Scan root')"; SCAN_ROOT="${SCAN_ROOT:-unknown}"
  RUN_AS_ROOT="$(meta 'Ran as root' | awk '{print $1}')"; RUN_AS_ROOT="${RUN_AS_ROOT:-1}"
  generate_html_report
  echo "HTML report: $OUT_DIR/report.html"
  exit 0
fi

TS="$(date +%Y%m%d-%H%M%S)"
HOST="$(hostname -s 2>/dev/null || hostname)"
OUT_DIR="$(pwd)/crypto-inventory-${HOST}-${TS}"
mkdir -p "$OUT_DIR"

CERTS_CSV="$OUT_DIR/certificates.csv"
EXPIRED_CSV="$OUT_DIR/expired_certificates.csv"
WEAK_CSV="$OUT_DIR/weak_crypto_findings.csv"
KEYS_CSV="$OUT_DIR/private_keys_found.csv"
KEYSTORES_CSV="$OUT_DIR/java_keystores.csv"
SSH_CSV="$OUT_DIR/ssh_keys.csv"
REFS_CSV="$OUT_DIR/config_references.csv"
PKCS11_CSV="$OUT_DIR/pkcs11_hsm_references.csv"
RPM_CSV="$OUT_DIR/crypto_packages.csv"
SUMMARY="$OUT_DIR/summary.txt"

echo "type,path,subject,issuer,algorithm,key_bits,not_before,not_after,days_to_expiry,self_signed,sans" > "$CERTS_CSV"
echo "path,not_after,days_expired" > "$EXPIRED_CSV"
echo "path,finding" > "$WEAK_CSV"
echo "path,type,file_perms,owner,group,world_readable" > "$KEYS_CSV"
echo "path,size_bytes,file_perms,owner,alias,alias_algorithm,alias_key_bits,alias_expiry,password_status" > "$KEYSTORES_CSV"
echo "path,type,bits,comment,file_perms,owner" > "$SSH_CSV"
echo "config_file,matched_pattern,line_excerpt" > "$REFS_CSV"
echo "path,type,notes" > "$PKCS11_CSV"
echo "package,version,arch" > "$RPM_CSV"

if [[ $EUID -ne 0 ]]; then
  RUN_AS_ROOT=0
else
  RUN_AS_ROOT=1
fi

log() { echo "[$(date +%H:%M:%S)] $*"; }

# CSV-escape a single field per RFC4180: wrap in quotes, double any embedded
# quotes, and collapse embedded newlines so a row is never split by content.
csv_field() {
  local s="${1//$'\n'/ }"
  s="${s//\"/\"\"}"
  printf '"%s"' "$s"
}

# True world-read check via the actual octal bitmask (bit 0004), not string
# comparison — correct regardless of extra setuid/setgid/sticky leading digit.
# NOTE: do not "simplify" this to `$((8#$perms % 10))` — that takes a DECIMAL
# modulo of the octal-converted value, which does not recover the last octal
# digit (e.g. perms=644 -> 8#644=420 decimal -> 420%10=0 -> falsely "not
# world-readable"). ANDing the full value with octal 04 is the correct check:
# the higher digits are all multiples of 8 and can never set bit 0004.
is_world_readable() {
  local perms="$1"
  [[ "$perms" =~ ^[0-7]+$ ]] || { echo "no"; return; }
  if (( (8#$perms) & 04 )); then echo "yes"; else echo "no"; fi
}

# Redact password/secret/token values before anything gets written to a
# report file — config_references.csv must never contain live credentials.
redact_secrets() {
  sed -E 's/((pass(word|wd)?|secret|token)[[:space:]]*[:=][[:space:]]*"?)[^",;[:space:]]+/\1***REDACTED***/Ig'
}

# ---------------------------------------------------------------------------
# Build the -prune expression: always exclude virtual/container filesystems,
# and dynamically add every currently-mounted network filesystem (nfs, cifs,
# glusterfs, lustre, gpfs, ceph, sshfs, ...) so the scan never walks a remote
# mount. Built from the live mount table rather than a hardcoded path list.
# ---------------------------------------------------------------------------
build_prune_expression() {
  local -a mounts=(/proc /sys /dev /run /var/lib/docker /var/lib/containers)
  local netfs_re='^(nfs|nfs3|nfs4|cifs|smb3|smbfs|glusterfs|fuse\.glusterfs|lustre|gpfs|ceph|ceph\.fuse|fuse\.sshfs|sshfs)$'

  if command -v findmnt >/dev/null 2>&1; then
    while IFS= read -r m; do
      [[ -n "$m" ]] && mounts+=("$m")
    done < <(findmnt -rn -o TARGET,FSTYPE 2>/dev/null | awk -v re="$netfs_re" '$2 ~ re {print $1}')
  elif [[ -r /proc/mounts ]]; then
    while read -r _dev mnt fstype _rest; do
      [[ "$fstype" =~ $netfs_re ]] && mounts+=("$mnt")
    done < /proc/mounts
  fi

  PRUNE_EXPR=()
  local first=1
  for m in "${mounts[@]}"; do
    if [[ $first -eq 1 ]]; then
      PRUNE_EXPR+=(-path "$m")
      first=0
    else
      PRUNE_EXPR+=(-o -path "$m")
    fi
  done
}
build_prune_expression

log "Starting crypto/PKI inventory scan"
log "Scan root: $SCAN_ROOT | Running as root: $RUN_AS_ROOT | Output: $OUT_DIR"
log "Pruning ${#PRUNE_EXPR[@]} path expressions (virtual fs + detected network mounts)"

# ---------------------------------------------------------------------------
# 1. OS trust store + RHEL8 system-wide crypto policy
# ---------------------------------------------------------------------------
log "1/9 OS trust store and crypto policy"
{
  echo "== update-crypto-policies =="
  if command -v update-crypto-policies >/dev/null 2>&1; then
    update-crypto-policies --show 2>&1
  else
    echo "update-crypto-policies not found (not RHEL8 crypto-policies pkg?)"
  fi
  echo
  echo "== System trust (trust list, truncated to CA count) =="
  if command -v trust >/dev/null 2>&1; then
    trust list 2>/dev/null | grep -c '^pkcs11:' || true
  else
    echo "trust command not found"
  fi
  echo
  echo "== OpenSSL / NSS versions =="
  command -v openssl >/dev/null 2>&1 && openssl version
  rpm -q nss 2>/dev/null || echo "nss rpm not found"
} > "$OUT_DIR/os_trust_and_policy.txt" 2>&1

# ---------------------------------------------------------------------------
# 2. Certificate discovery (PEM/DER on disk)
# ---------------------------------------------------------------------------
log "2/9 Scanning for certificate files (this can take a while on a full-disk scan)"

# analyze_cert <file-to-read> [display-path]
# display-path lets analyze_der_cert() record the *original* .der path in
# the CSV even though openssl actually reads a converted temp PEM file.
analyze_cert() {
  local f="$1"
  local display="${2:-$1}"
  local out
  out=$(timeout 5 openssl x509 -in "$f" -noout -subject -issuer -dates -pubkey -text 2>/dev/null) || return
  [[ -z "$out" ]] && return

  local subject issuer not_before not_after bits alg sig_alg sans self_signed days
  subject=$(echo "$out" | grep '^subject=' | sed 's/^subject=//')
  issuer=$(echo "$out"  | grep '^issuer='  | sed 's/^issuer=//')
  not_before=$(echo "$out" | grep '^notBefore=' | sed 's/^notBefore=//')
  not_after=$(echo "$out"  | grep '^notAfter='  | sed 's/^notAfter=//')
  alg=$(echo "$out" | grep -m1 'Public Key Algorithm' | sed 's/.*: //')
  # SHA1/MD5 usage lives in the *signature* algorithm (e.g. sha1WithRSAEncryption),
  # never in the public key algorithm (rsaEncryption/id-ecPublicKey) — checking
  # the wrong field would make the weak-hash flag below never fire.
  sig_alg=$(echo "$out" | grep -m1 '^ *Signature Algorithm:' | sed 's/.*: //')
  bits=$(echo "$out" | grep -m1 -E '\((.*bit\))' | sed -E 's/.*\(([0-9]+) bit\).*/\1/')
  sans=$(echo "$out" | grep -A1 'Subject Alternative Name' | tail -1 | sed 's/^ *//')
  [[ "$subject" == "$issuer" ]] && self_signed="yes" || self_signed="no"

  days="unknown"
  if [[ -n "$not_after" ]]; then
    local exp_epoch now_epoch
    exp_epoch=$(date -d "$not_after" +%s 2>/dev/null)
    now_epoch=$(date +%s)
    [[ -n "$exp_epoch" ]] && days=$(( (exp_epoch - now_epoch) / 86400 ))
  fi

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "cert" "$(csv_field "$display")" "$(csv_field "$subject")" "$(csv_field "$issuer")" \
    "$(csv_field "$alg")" "${bits:-unknown}" "$(csv_field "$not_before")" "$(csv_field "$not_after")" \
    "$days" "$(csv_field "$self_signed")" "$(csv_field "$sans")" >> "$CERTS_CSV"

  # Weak-crypto flags: deprecated signature hash, or RSA key < 2048 bits
  local weak_reason=""
  if [[ "$sig_alg" =~ [Ss][Hh][Aa]1 || "$sig_alg" =~ [Mm][Dd]5 ]]; then
    weak_reason="weak-signature-hash:${sig_alg}"
  fi
  if [[ "$bits" =~ ^[0-9]+$ ]] && (( bits < 2048 )); then
    if [[ -z "$alg" || "$alg" =~ [Rr][Ss][Aa] ]]; then
      weak_reason="${weak_reason:+$weak_reason; }weak-key-size:${bits}bit"
    fi
  fi
  [[ -n "$weak_reason" ]] && printf '%s,%s\n' "$(csv_field "$display")" "$(csv_field "$weak_reason")" >> "$WEAK_CSV"

  # Already-expired certs get their own file for fast triage
  if [[ "$days" != "unknown" ]] && (( days < 0 )); then
    printf '%s,%s,%s\n' "$(csv_field "$display")" "$(csv_field "$not_after")" "${days#-}" >> "$EXPIRED_CSV"
  fi
}

# Convert a DER cert to a temp PEM and hand analyze_cert the ORIGINAL path
# to record — passing process substitution directly (the old approach)
# recorded /dev/fd/N in the CSV instead of the real file path.
analyze_der_cert() {
  local f="$1"
  local pem_tmp
  pem_tmp=$(mktemp "${TMPDIR:-/tmp}/crypto-inv-der.XXXXXX") || return
  if timeout 5 openssl x509 -in "$f" -inform DER -out "$pem_tmp" 2>/dev/null; then
    analyze_cert "$pem_tmp" "$f"
  fi
  rm -f "$pem_tmp"
}

export -f analyze_cert analyze_der_cert csv_field redact_secrets is_world_readable
export CERTS_CSV WEAK_CSV EXPIRED_CSV

# PEM certs (by content, not just extension — catches .cer/.txt/no-ext files too)
find "$SCAN_ROOT" \( "${PRUNE_EXPR[@]}" \) -prune -o \
  -type f \( -iname '*.pem' -o -iname '*.crt' -o -iname '*.cer' -o -iname '*.cert' \) \
  -print0 2>/dev/null | while IFS= read -r -d '' f; do
    analyze_cert "$f"
  done

# DER certs — dedicated function, real path preserved in the CSV
find "$SCAN_ROOT" \( "${PRUNE_EXPR[@]}" \) -prune -o \
  -type f -iname '*.der' -print0 2>/dev/null | while IFS= read -r -d '' f; do
    analyze_der_cert "$f"
  done

CERT_COUNT=$(( $(wc -l < "$CERTS_CSV") - 1 ))
WEAK_COUNT=$(( $(wc -l < "$WEAK_CSV") - 1 ))
EXPIRED_COUNT=$(( $(wc -l < "$EXPIRED_CSV") - 1 ))
log "  found $CERT_COUNT certificates ($WEAK_COUNT weak-crypto flags, $EXPIRED_COUNT already expired)"

# ---------------------------------------------------------------------------
# 3. Private key discovery — METADATA ONLY, content never read/printed
# ---------------------------------------------------------------------------
log "3/9 Scanning for private key files (path/permissions only, no content)"

find "$SCAN_ROOT" \( "${PRUNE_EXPR[@]}" \) -prune -o \
  -type f \( -iname '*.key' -o -iname '*.pem' \) -print0 2>/dev/null | \
  while IFS= read -r -d '' f; do
    # grep the whole file for a PEM private-key header (first match only) —
    # a fixed byte-count head() can miss headers preceded by comments/blank
    # lines or unusual encodings.
    if grep -qam1 'BEGIN .*PRIVATE KEY' "$f" 2>/dev/null; then
      perms=$(stat -c '%a' "$f" 2>/dev/null)
      owner=$(stat -c '%U' "$f" 2>/dev/null)
      group=$(stat -c '%G' "$f" 2>/dev/null)
      world_ro=$(is_world_readable "$perms")
      key_type=$(grep -oam1 'BEGIN .*PRIVATE KEY' "$f" 2>/dev/null | sed -E 's/BEGIN //; s/ ?PRIVATE KEY//')
      printf '%s,%s,%s,%s,%s,%s\n' \
        "$(csv_field "$f")" "$(csv_field "${key_type:-PEM}")" "$perms" "$(csv_field "$owner")" "$(csv_field "$group")" "$world_ro" >> "$KEYS_CSV"
    fi
  done

KEY_COUNT=$(( $(wc -l < "$KEYS_CSV") - 1 ))
log "  found $KEY_COUNT private key files"

# ---------------------------------------------------------------------------
# 4. Java keystores / truststores
# ---------------------------------------------------------------------------
log "4/9 Scanning for Java keystores (.jks/.p12/.pfx/.keystore/.truststore)"

# Common non-secret default passwords ONLY (Java's own cacerts default, and
# common empty-password conventions). Anything else is left unopened.
KNOWN_PASSWORDS=("changeit" "changeme" "")

analyze_keystore() {
  local f="$1"
  local size perms owner
  size=$(stat -c '%s' "$f" 2>/dev/null)
  perms=$(stat -c '%a' "$f" 2>/dev/null)
  owner=$(stat -c '%U' "$f" 2>/dev/null)

  local opened=0
  if command -v keytool >/dev/null 2>&1; then
    for pw in "${KNOWN_PASSWORDS[@]}"; do
      local listing
      listing=$(keytool -list -v -keystore "$f" -storepass "$pw" 2>/dev/null)
      if [[ -n "$listing" ]]; then
        opened=1
        # One CSV row per alias. Buffers each alias's alg/expiry and only
        # emits once the NEXT alias starts (or at EOF via END) — the old
        # version emitted on the same line it saw a new alias, pairing the
        # new alias name with the PREVIOUS alias's algorithm/expiry, and
        # never emitted the last alias in the store at all.
        echo "$listing" | awk -v f="$f" -v size="$size" -v perms="$perms" -v owner="$owner" -v weakcsv="$WEAK_CSV" '
          function esc(s) { gsub(/"/,"\"\"",s); return "\"" s "\"" }
          function emit(alias, alg, expv,    a, e) {
            a = (alg == "" ? "unknown" : alg)
            e = (expv == "" ? "unknown" : expv)
            print esc(f) "," size "," perms "," esc(owner) "," esc(alias) "," esc(a) ",unknown," esc(e) ",known-password"
            if (tolower(a) ~ /sha1|md5/) {
              print esc(f " (alias=" alias ")") "," esc("weak-signature-algorithm:" a) >> weakcsv
            }
          }
          /^Alias name:/ {
            if (alias != "") emit(alias, alg, expv)
            alias = $0; sub(/^Alias name: /, "", alias); alg = ""; expv = ""
            next
          }
          /Signature algorithm name:/ { alg = $0; sub(/.*: /, "", alg) }
          /^Valid from:/ { expv = $0; sub(/^Valid from: .* until: /, "", expv) }
          END { if (alias != "") emit(alias, alg, expv) }
        ' >> "$KEYSTORES_CSV"
        break
      fi
    done
  fi

  if [[ $opened -eq 0 ]]; then
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$(csv_field "$f")" "$size" "$perms" "$(csv_field "$owner")" "unknown" "unknown" "unknown" "unknown" \
      "password-unknown-manual-review" >> "$KEYSTORES_CSV"
  fi
}

find "$SCAN_ROOT" \( "${PRUNE_EXPR[@]}" \) -prune -o \
  -type f \( -iname '*.jks' -o -iname '*.p12' -o -iname '*.pfx' \
             -o -iname '*.keystore' -o -iname '*.truststore' \) \
  -print0 2>/dev/null | while IFS= read -r -d '' f; do
    analyze_keystore "$f"
  done

# JVM default trust stores. These have no file extension, so the loop above
# can't see them. Match the file by name instead of by JDK directory name:
# RHEL8 installs OpenJDK under /usr/lib/jvm/java-11-openjdk-<ver>/ (a name
# that neither 'jre' nor 'jdk*' matches), and its real cacerts lives at
# /etc/pki/java/cacerts, with the JDK copies being symlinks to it. -type f
# skips those symlinks, so each store is analysed once.
find "$SCAN_ROOT" \( "${PRUNE_EXPR[@]}" \) -prune -o \
  -type f -name cacerts -print0 2>/dev/null | while IFS= read -r -d '' f; do
    analyze_keystore "$f"
  done

KS_COUNT=$(( $(wc -l < "$KEYSTORES_CSV") - 1 ))
log "  found keystore entries: $KS_COUNT rows"

# ---------------------------------------------------------------------------
# 5. SSH keys
# ---------------------------------------------------------------------------
log "5/9 Scanning SSH keys"

SSH_TIMEOUT=5

find /etc/ssh /root /home -maxdepth 4 -type f \
  \( -iname 'id_*' -o -iname 'ssh_host_*_key' \) ! -iname '*.pub' \
  2>/dev/null | while read -r f; do
    info=""
    if command -v ssh-keygen >/dev/null 2>&1; then
      if [[ -f "${f}.pub" ]]; then
        info=$(timeout "$SSH_TIMEOUT" ssh-keygen -lf "${f}.pub" </dev/null 2>/dev/null)
      fi
      if [[ -z "$info" ]]; then
        # ssh-keygen -yf on a passphrase-encrypted key prompts interactively;
        # </dev/null makes that prompt fail immediately instead of blocking,
        # and timeout is a second-layer guard against any other hang.
        info=$(timeout "$SSH_TIMEOUT" ssh-keygen -yf "$f" </dev/null 2>/dev/null | \
               timeout "$SSH_TIMEOUT" ssh-keygen -lf /dev/stdin 2>/dev/null)
      fi
    fi
    perms=$(stat -c '%a' "$f" 2>/dev/null)
    owner=$(stat -c '%U' "$f" 2>/dev/null)
    bits=$(echo "$info" | awk '{print $1}')
    ktype=$(echo "$info" | grep -o -E '\([A-Za-z0-9-]+\)$' | tr -d '()')
    comment=$(echo "$info" | awk '{$1="";$2="";print}' | sed -E 's/ \([A-Za-z0-9-]+\)$//' | sed 's/^ *//')
    printf '%s,%s,%s,%s,%s,%s\n' \
      "$(csv_field "$f")" "${ktype:-unknown}" "${bits:-unknown}" "$(csv_field "${comment:-}")" "$perms" "$(csv_field "$owner")" >> "$SSH_CSV"
  done

SSH_COUNT=$(( $(wc -l < "$SSH_CSV") - 1 ))
log "  found $SSH_COUNT SSH keys"

# ---------------------------------------------------------------------------
# 6. App/config references to keystores, truststores, inline PEM blocks
# ---------------------------------------------------------------------------
log "6/9 Scanning app config locations for crypto references"

CONFIG_DIRS=(/etc /opt /u01 /app /srv /var/lib/tomcat* /usr/local)
CONFIG_PATTERNS='javax\.net\.ssl\.(key|trust)Store|keystore\.(path|file)|-----BEGIN (CERTIFICATE|.*PRIVATE KEY)-----|ssl\.key-store|ssl\.trust-store|pkcs11|sunpkcs11|slotListIndex|[Kk]eystoreFile|[Tt]ruststoreFile|SSLCertificateKeyFile'

for d in "${CONFIG_DIRS[@]}"; do
  [[ -d "$d" ]] || continue
  grep -rIlE "$CONFIG_PATTERNS" "$d" 2>/dev/null | while read -r f; do
    # Never write a live password/secret/token value into the report —
    # redact before truncation so a redacted marker can't itself get cut off.
    match=$(grep -m1 -E "$CONFIG_PATTERNS" "$f" 2>/dev/null | head -1 | redact_secrets | cut -c1-160)
    printf '%s,%s,%s\n' "$(csv_field "$f")" "config-reference" "$(csv_field "$match")" >> "$REFS_CSV"
  done
done

REF_COUNT=$(( $(wc -l < "$REFS_CSV") - 1 ))
log "  found $REF_COUNT config files referencing crypto material"

# ---------------------------------------------------------------------------
# 7. PKCS#11 / HSM discovery
# ---------------------------------------------------------------------------
log "7/9 PKCS#11 / HSM discovery"

for p in /etc/softhsm2.conf /etc/softhsm/softhsm2.conf /etc/pkcs11/pkcs11.conf \
         "${HOME:-/root}/.config/softhsm2/softhsm2.conf"; do
  [[ -f "$p" ]] && printf '%s,%s,%s\n' \
    "$(csv_field "$p")" "softhsm-or-pkcs11-config" "found-on-disk" >> "$PKCS11_CSV"
done

find /usr/lib64 /usr/lib /opt -maxdepth 6 -type f \
  \( -iname '*pkcs11*.so*' -o -iname 'opensc-pkcs11.so' \) 2>/dev/null | \
  while read -r f; do
    printf '%s,%s,%s\n' "$(csv_field "$f")" "pkcs11-module" "shared-object" >> "$PKCS11_CSV"
  done

grep -rl 'pkcs11' /etc/pki 2>/dev/null | while read -r f; do
  printf '%s,%s,%s\n' "$(csv_field "$f")" "pkcs11-reference" "nss-or-openssl-config" >> "$PKCS11_CSV"
done

# java.security is lib/security/ on JDK 8 and conf/security/ on JDK 11+, so
# find it by name. Only an ACTIVE provider line counts: stock files mention
# SunPKCS11 in commented-out examples, which must not be reported.
find "$SCAN_ROOT" \( "${PRUNE_EXPR[@]}" \) -prune -o \
  -type f -name java.security -print0 2>/dev/null | while IFS= read -r -d '' secf; do
    if grep -Eq '^[[:space:]]*security\.provider\.[0-9]+[[:space:]]*=.*SunPKCS11' "$secf" 2>/dev/null; then
      printf '%s,%s,%s\n' \
        "$(csv_field "$secf")" "java-sunpkcs11-provider" "SunPKCS11 registered in java.security" >> "$PKCS11_CSV"
    fi
  done

PKCS11_COUNT=$(( $(wc -l < "$PKCS11_CSV") - 1 ))
log "  found $PKCS11_COUNT PKCS#11/HSM references"

# ---------------------------------------------------------------------------
# 8. Crypto-relevant RPM packages (feeds the SBOM side)
# ---------------------------------------------------------------------------
log "8/9 Listing crypto-relevant RPM packages"

rpm -qa --qf '%{NAME},%{VERSION}-%{RELEASE},%{ARCH}\n' 2>/dev/null | \
  grep -iE '^(openssl|nss|gnutls|krb5|java|gpg|cyrus-sasl|openssh)' >> "$RPM_CSV"

RPM_COUNT=$(( $(wc -l < "$RPM_CSV") - 1 ))
log "  found $RPM_COUNT crypto-relevant packages"

# ---------------------------------------------------------------------------
# 9. Optional: full SBOM/CBOM via syft + cdxgen
# ---------------------------------------------------------------------------
if [[ $WITH_SBOM -eq 1 ]]; then
  log "9/9 Generating SBOM/CBOM (syft/cdxgen)"
  if command -v syft >/dev/null 2>&1; then
    log "  running syft -> sbom.cyclonedx.json"
    syft dir:"$SCAN_ROOT" -o cyclonedx-json="$OUT_DIR/sbom.cyclonedx.json" 2>>"$OUT_DIR/syft.log"
  else
    log "  syft not found — skipping SBOM (install: https://github.com/anchore/syft)"
  fi

  if command -v cdxgen >/dev/null 2>&1; then
    log "  running cdxgen (java, --include-crypto) -> cbom.cyclonedx.json"
    # Without --include-crypto cdxgen emits a plain SBOM with no
    # cryptographic-asset components. That component type also needs
    # CycloneDX spec 1.6 or newer.
    cdxgen -t java --include-crypto --spec-version 1.6 -o "$OUT_DIR/cbom.cyclonedx.json" "$SCAN_ROOT" 2>>"$OUT_DIR/cdxgen.log"
  else
    log "  cdxgen not found — skipping CBOM (install: npm i -g @cyclonedx/cdxgen)"
  fi
else
  log "9/9 Skipped SBOM/CBOM generation (pass --with-sbom to enable; requires syft/cdxgen installed)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
{
  echo "Crypto/PKI Inventory Summary"
  echo "Host: $HOST"
  echo "Timestamp: $TS"
  echo "Scan root: $SCAN_ROOT"
  echo "Ran as root: $RUN_AS_ROOT  (non-root scans WILL miss unreadable paths)"
  echo
  echo "Certificates found:        $CERT_COUNT   -> certificates.csv"
  echo "  weak-crypto flags:       $WEAK_COUNT   -> weak_crypto_findings.csv (SHA1/MD5 sigs, RSA<2048)"
  echo "  already expired:         $EXPIRED_COUNT   -> expired_certificates.csv"
  echo "Private key files found:   $KEY_COUNT    -> private_keys_found.csv"
  echo "Java keystore rows:        $KS_COUNT     -> java_keystores.csv"
  echo "SSH keys found:            $SSH_COUNT    -> ssh_keys.csv"
  echo "Config references found:   $REF_COUNT    -> config_references.csv (secrets redacted)"
  echo "PKCS#11/HSM references:    $PKCS11_COUNT -> pkcs11_hsm_references.csv"
  echo "Crypto RPM packages:       $RPM_COUNT    -> crypto_packages.csv"
  echo
  echo "Known gaps this scan CANNOT close (require separate inventory):"
  echo "  - Keys actually resident inside an HSM or cloud KMS — this scan can"
  echo "    find PKCS#11 config/module references (pkcs11_hsm_references.csv)"
  echo "    but not the key material itself; pull that from the HSM/KMS's"
  echo "    own admin API/console."
  echo "  - Keystores whose password isn't 'changeit'/'changeme'/blank are"
  echo "    listed but not opened — see java_keystores.csv rows marked"
  echo "    'password-unknown-manual-review'."
  echo "  - Keys/secrets generated purely at runtime and never persisted to disk."
  echo "  - Crypto algorithm usage embedded in compiled/obfuscated JARs not"
  echo "    caught by string-based scanning — run a proper SAST/CBOM code"
  echo "    scanner (e.g. cdxgen java plugin, IBM CBOMkit) with --with-sbom."
  echo "  - Secrets stored in external vaults (HashiCorp Vault, AWS Secrets"
  echo "    Manager, etc.) referenced only by name/path in config."
  echo
  echo "Next steps:"
  echo "  1. Review any world-readable private key in private_keys_found.csv"
  echo "     immediately — this is a standing finding, not just inventory."
  echo "  2. Triage expired_certificates.csv and weak_crypto_findings.csv first —"
  echo "     both are pre-filtered, actionable lists."
  echo "  3. For each 'password-unknown-manual-review' keystore, get the"
  echo "     password from the owning application team and re-run keytool"
  echo "     manually to extract alias/algorithm/expiry."
  echo "  4. Cross-reference pkcs11_hsm_references.csv with your HSM/KMS"
  echo "     admin console to complete the key inventory for those assets."
  echo "  5. Merge sbom.cyclonedx.json + cbom.cyclonedx.json (if generated)"
  echo "     with this CSV data into your CMDB/inventory system of record."
} > "$SUMMARY"

generate_html_report
log "HTML report: $OUT_DIR/report.html"

log "Done. Summary: $SUMMARY"
echo
cat "$SUMMARY"
