# Compliance matrix

Every requirement from the team's ALPR compliance brief, mapped to what this
codebase does about it. Read this before writing "compliant" anywhere.

**The short version.** Software can switch controls on; it cannot make a
deployment compliant. CJIS, FedRAMP, GovRAMP, SOC 2 and ISO 27001 are granted
to an *organization and its deployment* after an assessment. What this project
can truthfully say is: "designed to align with NIST SP 800-53 Rev. 5 and the
FBI CJIS Security Policy; the technical controls below are implemented and
tested; certification has not been sought."

## How to read the status column

| Status | Meaning |
|---|---|
| **Built, tested** | In the code, with automated tests that pass on a laptop. |
| **Built, not run on hardware** | In the code, but it needs the Pi, TPM, camera or a specific OS to exercise, and that has not happened. |
| **Partial** | Some of it is built. The gap is stated. |
| **Outside the software** | A purchase, a contract, a policy, an audit or a person. Code cannot do it. |
| **Does not apply** | The requirement is about something this system does not have (a cloud, tenants, a vendor support team). |

Check the live state of any device with:

```bash
python scripts/compliance_check.py                          # the settings this device would start with
python scripts/compliance_check.py config/compliance.yaml   # the strict profile
python scripts/check_bom.py                                 # hardware against NDAA Section 889
```

The same report is on the dashboard under Reports, and goes into every audit
package.

## 1. Frameworks by sector

| Framework | Status | Why |
|---|---|---|
| NIST SP 800-53 Rev. 5 (Moderate) | Partial | The technical controls in section 2 are built. Most of the baseline's other controls (planning, training, contingency, assessment...) are organizational. |
| FedRAMP / GovRAMP | Does not apply | Both authorize *cloud services*. This system is one self-hosted device with no cloud. They would apply the day someone hosts it for customers. |
| FIPS 140-3 | Partial | See B1 below. Approved algorithms throughout; a validated module depends on the operating system. |
| NDAA Section 889 | Partial | See A1. The screen is built; three parts on the list are not yet chosen. |
| FBI CJIS Security Policy | Outside the software | Applies once the device holds real NCIC hot-list data. Needs an agency agreement, the Security Addendum, fingerprint-based checks and an audit. The technical side (encryption, MFA, audit, roles) is built. |
| State ALPR statutes | Partial | Retention, audit and reporting are configurable. Which numbers the law requires is a legal question for each state. |
| NIST CSF 2.0 | Outside the software | A way of organizing a security programme, not a feature. |
| SOC 2 Type II, ISO/IEC 27001 | Outside the software | Third-party audits of a company over months. |
| State privacy laws (CCPA/CPRA, TDPSA) | Outside the software | Notices, contracts and rights requests. Data minimisation and deletion are built. |

## 2. Technical requirements

### A. Edge camera and hardware

| # | Requirement | Status | Where | What is still needed |
|---|---|---|---|---|
| A1 | NDAA 889 supply chain: no barred vendors or chipsets | Partial | `config/hardware_bom.yaml`, `security/supply_chain.py`, `scripts/check_bom.py` | The Pi 5, Coral accelerator and SanDisk card are cleared. **The IP camera, the SSD and the TPM board are not chosen yet.** The camera is the real risk: many low-cost IP cameras are Hikvision or Dahua products, or use a HiSilicon (Huawei) processor, under another label. The script is a name screen, not a legal determination. |
| A2 | Secure boot | Built, not run on hardware | `security/secure_boot.py`, `security.require_attestation` | The device refuses to load keys if TPM boot measurements differ from the recorded value. Enabling secure boot itself is a step on the Pi, not in this code. |
| A3 | Hardware root of trust (TPM 2.0) | Built, not run on hardware | `privacy/key_manager.py`, `scripts/setup_tpm.sh` | Run on the real TPM module. |
| A4 | Encrypted local storage: a stolen card yields no readable plate photos | Partial | `evidence/vault.py`, `evidence/snapshots.py`, `compliance.on_encrypted_volume` | Footage and review snapshots are always encrypted by the application, and the device holds no key that opens footage. Plates are never stored. The index (hashes and attributes), the audit log and the device certificate key are ordinary files: they need full-disk encryption (LUKS unlocked by the TPM), which is documented in the operator guide but not scripted or tested. The compliance report says whether the data directory is on an encrypted volume. |
| A5 | Tamper detection and alert when the enclosure is opened | Built, not run on hardware | `security/tamper_detect.py`, `security/fail_closed.py` | Lens-covering detection is tested. The case switch needs wiring to a GPIO pin; the accelerometer needs a driver function passed to `MotionSensor`. On tamper the device wipes keys and locks; it does not send a message to anyone, because it has nowhere to send one. |
| A6 | Signed firmware and model updates | Built, tested (application layer) | `security/signed_update.py`, `scripts/sign_update.py`, `scripts/apply_update.py` | Models, hot lists and software bundles are checked against an ECDSA P-384 signature before use; the device refuses to start on an unsigned or altered model. There is no over-the-air channel: an update is copied to the device and applied by hand. The operating system and bootloader are covered by secure boot, not by this. |
| A7 | Device authentication with a unique certificate (mutual TLS) | Partial | `security/device_identity.py`, `matching/hotlist_sync.py` | Each device gets its own P-384 key, a certificate request for the agency's CA, and uses mutual TLS 1.3 to a pinned CA when fetching the hot list. Tested against a local test server. The private key is a file, not held inside the TPM, so it is not yet "hardware-backed". |

### B. Cryptography and transmission

| # | Requirement | Status | Where | What is still needed |
|---|---|---|---|---|
| B1 | FIPS 140-3 validated cryptography | Partial | `crypto.py`, `crypto.require_fips_provider` | Every algorithm is on the approved lists (HMAC-SHA-256, AES-256-GCM, ECDH and ECDSA P-384, HKDF, PBKDF2). X25519 and scrypt were removed for this. That is *not* the same as validated: the standard is met only when OpenSSL runs a FIPS provider that holds a certificate, which depends on the operating system. With the setting on, the device refuses to start without one. Whether a validated module exists for the Pi's operating system has not been checked. Splitting the vault key (Shamir) is secret sharing and has no FIPS equivalent. |
| B2 | TLS 1.3 in transit | Built, tested | `api/serve.py`, `api.tls` | Off by default for localhost development. Turn it on for anything reachable from another machine. Older TLS versions are refused. |
| B3 | AES-256 at rest | Built, tested (footage); Partial (index) | `evidence/vault.py` | See A4. |
| B4 | Tenant separation, GovCloud hosting | Does not apply | | One agency, one device, no cloud, no data sharing between organizations. |

### C. Identity, access and query justification

| # | Requirement | Status | Where | What is still needed |
|---|---|---|---|---|
| C1 | Multi-factor sign-in for everyone | Built, tested | `api/auth.py`, `api.require_mfa` | |
| C2 | Phishing-resistant MFA (FIDO2 / WebAuthn) for privileged users | Built, tested | `api/auth.py`, `dashboard/src/webauthn.js`, `api.phishing_resistant_roles` | Tested with a software authenticator and in a browser with a virtual one. Not yet tried with a physical key. Roles listed in the setting can do nothing but enroll a key until they have one. |
| C3 | No search without a case number or purpose | Built, tested | `api/server.py` (`/api/search`) | Enforced by the server, not just the screen. |
| C4 | Separate roles for live alerts, historical search and supervision | Built, tested | `api/auth.py` (`ROLE_PERMISSIONS`) | Five roles: reviewer, investigator, supervisor, auditor, admin. The admin cannot search or review. |
| C5 | Supervisor approval for multi-jurisdiction sharing | Does not apply | | The device shares vehicle data with no one. |
| C6 | Session timeout and lockout | Built, tested | `api.session_minutes`, `api.max_login_failures` | 30 minutes idle, lock after 5 failures. |

### D. Audit logging

| # | Requirement | Status | Where | What is still needed |
|---|---|---|---|---|
| D1 | Append-only, tamper-evident log | Built, tested | `audit/audit_log.py` | Each entry carries the hash of the one before it. Cutting off the *end* of the log is only detectable if the latest hash was recorded somewhere else; every report and audit package includes it for that purpose. |
| D2 | Logged events: sign-in, search, hot-list change, export, sharing change | Built, tested | throughout; `tests/integration/test_reports.py` | Sign-ins (including failures), searches, hot-list updates, reviews, unseals, holds, purges, exports, account and security-key changes are logged. There is no sharing switch to log. |
| D3 | Each entry: user, agency, time, search criteria, case number | Partial | `audit/audit_log.py`, `organization` setting | All present, with one deliberate exception: a plate search is logged as "plate search (hashed)" with its case number, but neither the plate nor its hash is written to the log. An auditor can see who searched by plate, when and for which case, but not which plate. Logging the hash would close that gap at the cost of putting a trackable identifier in a long-lived file. This is a design decision the team should make on purpose. |
| D4 | Transparency report and one-click audit export | Built, tested | `audit/reports.py`, Reports page | Totals for any date range, and one zip with the report, the audit log, its integrity check and the control settings. Counts are kept after the sightings they count are purged, so yearly totals add up. |

### E. Privacy, retention and AI governance

| # | Requirement | Status | Where | What is still needed |
|---|---|---|---|---|
| E1 | Configurable automatic hard deletion | Built, tested | `evidence/purge.py`, `retention` settings | Footage is purged by destroying its key; index rows are deleted with SQLite secure-delete; snapshots expire. Limits: periods are whole days, checked hourly by default, so a statute measured in minutes cannot be met; hits and non-hits share one period (a legal hold keeps a bounded window longer); flash storage can retain deleted blocks (see the threat model). |
| E2 | Per-customer retention | Does not apply | | Single agency per device. |
| E3 | Human confirmation before acting on a hot-list alert | Built, tested (differently from the brief) | `matching/alert_queue.py`, Review Queue | The brief describes showing the plate crop beside the OCR text. This system never keeps the OCR text, so the reviewer compares the snapshot with the case file themselves and must record a written reason to confirm. That is stricter on privacy; it also means the reviewer reads the plate with their own eyes rather than checking a machine's reading. |
| E4 | Blur faces and pedestrians | Built, tested | `vision/redaction.py`, `privacy.redaction` | Faces are found by a small detector and pixelated in everything stored or shown. Pedestrians are blurred when the vehicle detector reports them. A detector misses some faces (glare, night, profile). Bumper stickers are not detected. The extra work per frame has not been timed on the Pi. |
| E5 | No use of collected images to train AI | Partial | | No code path exports images: footage goes only into the sealed vault and nothing is sent off the device. The rest is a promise made in a contract or policy. |

## 3. People and operations

| Requirement | Status | Note |
|---|---|---|
| Fingerprint-based background checks, CJIS Security Addendum | Outside the software | Applies to whoever administers a device holding real hot-list data. |
| Annual security and privacy training | Outside the software | |
| US data residency and US-based support | Does not apply / Outside the software | Data never leaves the device. Where the device is and who services it is the agency's decision. |

## 4. Corrections to the brief worth knowing before citing it

* **Two control numbers do not match the NIST catalogue.** The brief cites SI-10 for
  human review of alerts and PT-4 for blurring. In SP 800-53 Rev. 5, SI-10 is
  "Information Input Validation" and PT-4 is "Consent". PT-2 is "Authority to
  Process Personally Identifiable Information", not a rule about AI training.
  This document and the compliance report therefore label those two rows "Hit
  confirmation" and "PII minimisation" instead of a control number. Look up any
  control number in the catalogue before quoting it in a report.
* **"Meeting Moderate plus CJIS satisfies roughly 95% of requirements"** has no
  source. Do not repeat the figure.
* **The brief is written for a company selling a cloud product to many
  agencies.** Much of it (FedRAMP, tenants, GovCloud, vendor staff vetting) is
  about that business model. A self-hosted device avoids those requirements by
  not having the thing they regulate, which is a point in the project's favour
  and worth saying in the report.

## 5. What "strict mode" needs before it will start

`config/compliance.yaml` turns every technical control on. Under it the device
refuses to start unless all of these are true:

1. TPM keys exist (`scripts/setup_tpm.sh`) and boot measurements match.
2. The operating system runs OpenSSL with a FIPS provider.
3. `config/update_signing.pub` is installed and every model is in a signed manifest.
4. The face-detector model is present.

The first three have not been exercised on the team's hardware yet.
