# PKI-and-Crypto-Discovery

Read-only discovery of PKI and cryptographic material on a **RHEL 8 + Java** host. It builds the inventory
behind a **CBOM** (Cryptography Bill of Materials) and, optionally, an **SBOM**, and writes a one-page HTML
summary of what it found.

One script: [`crypto_pki_inventory.sh`](crypto_pki_inventory.sh).

## What it finds

| Area | How |
|---|---|
| Certificates (PEM and DER) | `openssl x509`: subject, issuer, key algorithm and size, validity, days to expiry, self-signed, SANs |
| Weak crypto | Certificates: SHA-1 / MD5 signature hash and RSA keys under 2048 bits. Keystore aliases: SHA-1 / MD5 signature hash only |
| Expired certificates | Listed separately for triage |
| Private key files | Path, owner, permissions, world-readable flag. **Key content is never read or printed** |
| Java keystores / truststores | `.jks .p12 .pfx .keystore .truststore` plus the JVM `cacerts`; every alias listed via `keytool` where the password is a known public default |
| SSH keys | Host and user keys, with a timeout so a passphrase-protected key cannot hang the scan |
| Config references | Keystore / truststore settings in `/etc /opt /u01 /app /srv /usr/local /var/lib/tomcat*`, with password / secret / token values redacted |
| PKCS#11 / HSM | SoftHSM and OpenSC config and modules, NSS `pkcs11.txt`, active `SunPKCS11` providers in `java.security` |
| OS crypto settings | `update-crypto-policies`, system trust store size, OpenSSL and NSS versions |
| Crypto packages | openssl, nss, gnutls, krb5, java, gpg, cyrus-sasl, openssh from `rpm` |
| SBOM / CBOM (optional) | `syft` for the SBOM, `cdxgen` for code-level crypto assets, both CycloneDX JSON |

## Quick start

```bash
# Full scan. Run as root, otherwise unreadable paths are silently skipped.
sudo ./crypto_pki_inventory.sh

# Scope it to the application and name the report
sudo ./crypto_pki_inventory.sh /opt --app-name "Orders Service"

# Also generate the SBOM and CBOM (needs syft and cdxgen installed)
sudo ./crypto_pki_inventory.sh /opt --with-sbom

# Rebuild report.html from an earlier run's CSVs, without rescanning
./crypto_pki_inventory.sh --report-only ./crypto-inventory-<host>-<timestamp>
```

| Option | Meaning |
|---|---|
| `SCAN_ROOT` | Directory to scan. Default `/` |
| `--with-sbom` | Run `syft` and `cdxgen` if installed |
| `--app-name NAME` | Name shown in the report title. Default: hostname |
| `--report-only DIR` | Only re-render `report.html` from the CSVs in `DIR` |

**Requirements:** bash 4+ and GNU coreutils (`stat -c`, `date -d`, `timeout`), `openssl`, `awk`, `sed`, `grep`,
`find`. Optional: `keytool`, `ssh-keygen`, `findmnt`, `rpm`, `syft`, `cdxgen`, `jq`. It is written for RHEL 8
and will not run correctly on macOS.

The scan skips `/proc /sys /dev /run`, container storage, and any mounted network filesystem (nfs, cifs,
glusterfs, lustre, gpfs, ceph, sshfs), detected from the live mount table.

## Output

Each run writes `crypto-inventory-<host>-<timestamp>/`:

| File | Contents |
|---|---|
| `report.html` | Self-contained summary page. Inline CSS, no scripts, no external assets, opens offline |
| `summary.txt` | Counts, known gaps, next steps |
| `certificates.csv` | All certificates found |
| `expired_certificates.csv` | Expired certificates, with days expired |
| `weak_crypto_findings.csv` | Weak hash or key size, on certificates and keystore aliases |
| `private_keys_found.csv` | Private key files and their permissions |
| `java_keystores.csv` | One row per keystore alias, or one row for a keystore that could not be opened |
| `ssh_keys.csv` | SSH keys |
| `config_references.csv` | Config files that reference keystores, truststores, PEM blocks or PKCS#11 (redacted) |
| `pkcs11_hsm_references.csv` | PKCS#11 / HSM configuration and modules |
| `crypto_packages.csv` | Crypto-relevant RPMs |
| `os_trust_and_policy.txt` | System crypto policy and library versions |
| `sbom.cyclonedx.json`, `cbom.cyclonedx.json` | Only with `--with-sbom` |

### The HTML report

`report.html` opens with a verdict banner, then **priority findings**, each with its own table:

| Severity | Finding |
|---|---|
| Critical | World-readable private keys |
| High | Expired certificates; weak cryptography |
| Medium | Keystores that need a password from their owner; certificates expiring within 90 days |

Below that are the inventory counts, collapsible full tables, the system crypto policy, links to the
SBOM / CBOM, what the scan cannot see, and links to the raw CSVs. Flagged rows carry a text label
(`ACTION` / `REVIEW`), not just a colour. Tables cap at 1,000 rows; the CSV always has everything.

## Safety

- **Read-only.** Nothing it inspects is modified.
- **No key material in any output.** Private keys are detected by their PEM header; only path and permissions
  are recorded. Config lines have `password`, `secret`, `token` and `passwd` values replaced with
  `***REDACTED***` before they are written.
- **Known-default passwords only.** For keystores it tries `changeit`, `changeme` and an empty password, and
  nothing else. A keystore with any other password is listed as `password-unknown-manual-review`.
- **The report escapes everything from scanned files.** File names, certificate subjects and config lines are
  attacker-influenced, so they are HTML-escaped and the page contains no scripts.

## What a file-system scan cannot see

This is an inventory of what is on disk. It does **not** capture:

- Keys held in an HSM or cloud KMS. It finds the PKCS#11 config and modules, not the keys; pull those from the
  HSM / KMS admin API.
- Keystores with a non-default password. They are listed but not opened.
- Keys generated at runtime and never written to disk.
- Algorithms used inside compiled or obfuscated JARs. That is what the CBOM from `--with-sbom` is for.
- Secrets in external vaults that config refers to only by name.

## Sample output

[`samples/`](samples) holds one run of each kind, rendered from **synthetic data** for a made-up host
(`app-prod-01`, scan date 2026-10-13). Every host, name and path is fictitious.

| Folder | What it shows |
|---|---|
| [`samples/without-sbom/`](samples/without-sbom) | A default run. `report.html` says the SBOM / CBOM were not generated |
| [`samples/with-sbom/`](samples/with-sbom) | The same host run with `--with-sbom`: adds the two CycloneDX files, linked from the report |

Open `samples/*/report.html` in a browser to see the report. The CSVs and `summary.txt` use the script's exact
formats; `summary.txt` was produced by the script's own summary code and `report.html` by its own renderer.

Two simplifications to be aware of: the keystore sample lists 2 of the roughly 140 `cacerts` aliases, and the
two CycloneDX files are short hand-written illustrations of the format, not real `syft` / `cdxgen` output
(which is much larger).

## Status

The helpers (CSV escaping, secret redaction, permission check, keystore alias parsing, certificate weak/expiry
detection, `cacerts` and `java.security` discovery, report rendering) were tested individually against
generated data. The full end-to-end scan has **not yet been run on a RHEL 8 host**. Before a fleet rollout, do a
dry run with a narrow `SCAN_ROOT`, for example `sudo ./crypto_pki_inventory.sh /opt`, and check `summary.txt`.

`cdxgen` is invoked as `cdxgen -t java --include-crypto --spec-version 1.6`. Per the cdxgen documentation the
crypto inventory needs `--include-crypto`, and `cryptographic-asset` components need CycloneDX 1.6 or newer.
Confirm the flags against the cdxgen version you install.
