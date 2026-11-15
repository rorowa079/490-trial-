# Self-Hosted Vehicle Recognition System

CPSC 490 · Saif, Kevin, Rami, Bryan

A privacy-preserving alternative to cloud ALPR. Everything runs on one device
you own. License plates are turned into keyed hashes in memory and are never
written to disk; a hotlist match only ever becomes a *question for a human*.

## Try it in two minutes (no camera needed)

```bash
pip install -r requirements.txt
python scripts/run_demo.py          # then open http://localhost:8000
```

Password for every demo account: `demo-password-123`.

| Account | Role | Sees |
|---|---|---|
| `carol` | reviewer | live view, review queue |
| `alice` | investigator | + search, unseal requests |
| `bob` | supervisor | + legal holds, audit log, reports |
| `dana` | auditor | audit log and reports only |
| `admin` | admin | accounts, device, audit, reports (cannot search or review) |

Simulated cars drive past; some are on the demo watch list, and two of those
deliberately do **not** fully match it, so there is something real to review.
Custodian key shares for trying the two-person unseal are in
`data-demo/DEMO_SHARES.txt`. Use `localhost` in the address bar, not
`127.0.0.1`: browsers only allow security keys on localhost or HTTPS.

```bash
python -m pytest tests -q                                   # 85 tests
python scripts/compliance_check.py config/compliance.yaml   # which controls are on
python scripts/check_bom.py                                 # hardware vs NDAA Section 889
```

## What happens to a vehicle

```
camera -> motion gate -> detect -> track -> attributes + speed -> OCR
       (faces and pedestrians are blurred in every frame that is kept)
       -> normalize -> HMAC-SHA256 with the device key -> wipe the plate from RAM
       -> compare hash with the hashed watch list
            no match: store hash + attributes, seal the clip
            match:    same, plus a pending alert for a human reviewer
```

* **Hash first.** The plate is hashed before anything is compared or stored.
  The watch list is hashed with the same key, so matching is hash-to-hash and
  no readable list of plates exists on the device.
* **Sealed footage.** Event clips are encrypted with a per-day key. The device
  can seal but not unseal: opening a clip takes key shares from two different
  signed-in people (2-of-3 by default, configurable).
* **Rolling retention.** Clips 30 days, hash index 90 days. A day is purged by
  destroying its key. Legal holds pause the purge for one bounded window.
* **Human gate.** A match does nothing by itself. A reviewer sees matching *and*
  non-matching attributes; confirming requires a written reason.
* **Tamper response.** Covered lens or opened case: keys are wiped, processing
  stops, and the device stays locked until an admin inspects it.
* **Audit log.** Every sign-in, search, review, unseal, purge, export and
  account change goes into a hash-chained log with the user, agency, time and
  case number; editing or deleting an entry is detectable.

## Security and compliance controls

Built to line up with NIST SP 800-53 Rev. 5 and the FBI CJIS Security Policy.
**This is not a certification.** `docs/compliance_matrix.md` maps every
requirement to code, tests, or the reason code cannot meet it.

| Control | What it does | Setting |
|---|---|---|
| Roles | reviewer, investigator, supervisor, auditor, admin; the server checks every request | set per account |
| Security keys (FIDO2) | phishing-resistant sign-in; can be required per role | `api.phishing_resistant_roles` |
| TLS 1.3 | HTTPS only, older versions refused; optional browser certificates | `api.tls` |
| Device certificate | unique P-384 key and certificate; mutual TLS to the hot-list server | `hotlist_sync` |
| Approved cryptography | HMAC-SHA-256, AES-256-GCM, ECDH/ECDSA P-384, PBKDF2; can refuse to start without a FIPS-validated module | `crypto.require_fips_provider` |
| Signed updates | models, hot lists and software bundles checked against a signature before use | `updates.require_signed_models` |
| Face and pedestrian blurring | applied before anything is buffered, shown or sealed | `privacy.redaction` |
| Transparency report | usage totals for any period, and a one-click audit package | Reports page |
| Hardware screen | parts list checked against NDAA Section 889 | `config/hardware_bom.yaml` |

`config/compliance.yaml` switches all of them on at once. The device then
refuses to start without a TPM, a FIPS-validated OpenSSL and signed models.

## Layout (one folder per subsystem)

| Folder | Subsystem | What is in it |
|---|---|---|
| `src/vrs/capture/` | Sensing & capture | camera/file/simulated sources, motion gate, in-RAM frame buffer |
| `src/vrs/vision/` | Vision & inference | detector, tracker, color/body attributes, OCR, Kalman speed, face/pedestrian blurring |
| `src/vrs/privacy/` | Privacy & hashing | normalizer, keyed hasher, memory scrubber, key custody (TPM/software) |
| `src/vrs/matching/` | Matching & alerting | hashed hotlist, matcher, review queue |
| `src/vrs/evidence/` | Evidence vault | sealed clips, Shamir shares, unseal flow, legal holds, purge |
| `src/vrs/security/` | Anti-tampering | sensors, fail-closed controller, boot attestation, signed updates, device certificate, hardware screen |
| `src/vrs/audit/` | Audit | hash-chained log, daily counters, transparency report and audit package |
| `src/vrs/api/` + `dashboard/` | Operator interface | FastAPI backend with roles and security keys, React UI (Login, Dashboard, Review Queue, Search, Evidence, Audit Log, Reports, Account) |
| `src/vrs/crypto.py` | — | every cryptographic primitive, in one file |
| `src/vrs/compliance.py` | — | reports which controls are in force |
| `src/vrs/pipeline.py` | — | ties the stages together in the order above |
| `src/vrs/system.py` | — | builds and wires every subsystem; startup and shutdown |

`config/` holds settings, `db/schema.sql` the index schema, `scripts/` the
provisioning and maintenance commands, `tests/` unit and end-to-end tests,
`deploy/` the Dockerfile and systemd unit, `docs/` the threat model, operator
guide and compliance matrix.

## What is real and what is not yet

**Built and tested here:** hashing, scrubbing, key custody (software backend),
hotlist, matching, review queue, evidence vault, Shamir split/combine, unseal,
legal holds, purge, audit log, lens-obstruction tamper detection, fail-closed
lock, roles, authenticator codes and security keys (with a software key in the
tests and a virtual one in a browser), TLS 1.3, the device certificate and
mutual-TLS hot-list feed (against a local test server), signed models and
updates, face blurring (on a test photo), the transparency report and audit
package, the full API, the dashboard, and the pipeline end to end on simulated
traffic.

**Written but not run on real hardware or models** (needs your Pi, camera and
weights):

* `YoloDetector` (ultralytics YOLOv8 + ByteTrack) and `PaddlePlateReader`
* `TpmKeyBackend`, `secure_boot.py`, `scripts/setup_tpm.sh`
* GPIO case switch and accelerometer sensors
* `deploy/Dockerfile` and the systemd unit
* The Coral USB Accelerator: nothing in the code uses it yet. `YoloDetector`
  runs YOLO on the Pi's CPU. Ultralytics can export a model for the Edge TPU
  and load it by file name, so pointing `vision.yolo_weights` at that file is
  the likely route, but it is untried here
* A physical security key, a FIPS-validated OpenSSL, and disk encryption
  released by the TPM
* Speed on the Pi: face detection now runs on every kept frame, and its cost on
  the Pi 5 has not been measured

**Not built:** make/model and damage classifiers (there is a plug-in point in
`vision/attributes.py`; until a model exists those fields stay empty on real
video), camera calibration tooling, multi-camera support, bumper-sticker
blurring, an over-the-air update channel (updates are signed but applied by
hand), keeping the device certificate key inside the TPM, and a separate
retention period for non-hits.

**Known limit, stated plainly:** Python cannot wipe immutable strings. Our own
plate buffers are zeroed, but an OCR library that returns a `str` leaves a copy
in memory until it is reused. Plaintext never reaches disk (a test scans every
file to prove it), but "never in RAM" would need the OCR-to-hash step in native
code. See `docs/threat_model.md`.

## Moving to real hardware

1. `pip install ultralytics paddleocr` and put weights in `src/vrs/vision/models/`.
2. In `config/local.yaml` set `capture.source: camera`, `vision.detector: yolo`,
   `vision.ocr: paddle`, and measure `vision.meters_per_pixel` on site.
3. Fill in `config/hardware_bom.yaml` with the exact camera, SSD and TPM board
   and run `python scripts/check_bom.py` **before buying the camera**.
4. Run `scripts/setup_tpm.sh`, set `keys.backend: tpm` and
   `security.require_attestation: true`. Put the data directory on an encrypted
   volume (operator guide, "Disk encryption").
5. Set `organization`, `api.tls.enabled: true`, and the host name in
   `api.tls.hostnames` and `api.webauthn`.
6. `python scripts/init_device.py --admin <name>`, hand out the custodian
   shares, and send `data/identity/device.csr` to your certificate authority.
7. Create a signing key off the device (`scripts/sign_update.py keygen`), copy
   the public half to `config/update_signing.pub`, sign the models, and set
   `updates.require_signed_models: true`.
8. `python scripts/hash_hotlist.py <list.csv> --replace`, or set `hotlist_sync`.
9. `make dashboard && make run`, then `python scripts/compliance_check.py`.
