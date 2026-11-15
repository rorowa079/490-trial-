# Threat model

What the system protects, against whom, and where the protection stops.

## Assets

| Asset | Where it lives | Protection |
|---|---|---|
| Plaintext plates | RAM only, for one function call | hashed then zeroed; never written |
| Plate hashes + attributes | `data/index.db` | useless without the HMAC key; deleted after 90 days |
| HMAC key, review key | TPM (deployed) / files (dev) | sealed to boot state; zeroed on tamper and shutdown |
| Event footage | `data/vault/clips` | AES-256-GCM under per-day keys wrapped to the vault public key |
| Vault private key | nowhere on the device | Shamir shares held by custodians |
| Audit log | `data/audit.log` | hash chain makes edits and deletions detectable |
| Device certificate key | `data/identity/device.key` | file permissions and disk encryption; not yet held in the TPM |
| Update signing key | never on the device | the device holds only the public half |
| Faces of drivers and passers-by | not kept | pixelated before a frame is buffered, shown or sealed |

## Attackers and outcomes

**Someone steals the device or copies its disk.** They get hashes they cannot
reverse (no key outside the TPM), clips they cannot decrypt (no private key on
the device), and an audit log. With the *software* key backend this does not
hold: the HMAC key is a file. Never deploy that backend.

**Someone pulls power and reads the RAM (cold boot).** They can recover whatever
keys were loaded: the HMAC key, the review key and today's day key. This is why
keys are scrubbed on tamper and why the case switch matters. Residual risk: an
attacker fast enough to beat the sensors. Memory encryption is out of scope.

**A curious or malicious insider.** Roles limit what each person can reach: a
reviewer cannot search history, an admin cannot search or review, an auditor
sees no vehicle data. Nobody can view footage alone (it needs a second
custodian) or search without a case number, and every search and view is in a
log they cannot silently edit. Reviewers *can* see snapshots for watch-listed
vehicles; that is the job. Residual risks: two colluding custodians, and an
admin who gives themselves a second account with another role (the audit log
records account changes, so it is visible, not prevented).

**Someone who phishes a password.** With a security key enrolled, the password
alone yields only a challenge that the key signs for this site's address, so a
look-alike site gets nothing reusable. Accounts still on authenticator codes
can be phished in real time; list their roles in `api.phishing_resistant_roles`
to close that.

**Someone on the network.** With `api.tls.enabled` the dashboard is HTTPS with
TLS 1.3 only. Without it, traffic is readable by anyone on the path; the
default binds to localhost for that reason.

**Someone who can edit the watch list.** Adding a plate causes that vehicle to
be flagged. The list is writable through `hash_hotlist.py` on the device or the
agency feed, and every change is audited. With signature checking on, a list is
accepted only if it was signed with the update key, and the feed is fetched
over mutual TLS from a pinned server, so a forged feed or an edited file is
refused. Whoever holds the signing key still controls targeting. List updates
should need the same two-person approval as an unseal. Not built.

**Someone who swaps a model or pushes a fake update.** A model that reads every
plate as one on the watch list would be an attack. With
`updates.require_signed_models` the device refuses to start unless each model
matches a signed manifest, and `apply_update.py` unpacks nothing unsigned.
Residual risk: theft of the signing key, which is why it stays off the device
and behind a passphrase.

**Someone who edits the audit log.** Changing or removing an entry breaks the
chain and the dashboard shows where. Residual risk: truncating the *end* of the
log is not detectable from the file alone. Every report and audit package
includes the newest hash; a copy kept off the device exposes a later
truncation. Sending it somewhere automatically is not built.

**The reviewer's own bias.** The largest practical risk and not a software
problem. The UI shows mismatches as prominently as matches, makes confirming
harder than dismissing, and never scores reviewers on throughput. It cannot
make an organisation give reviewers real authority to say no.

## Known gaps

* **Plaintext in RAM.** Our buffers are zeroed; an OCR library's immutable `str`
  result is not. Plaintext never reaches disk. Closing this needs the
  OCR-to-hash step in native code.
* **Key deletion on flash.** Destroying a day key overwrites then deletes the
  file, but flash wear-levelling can keep old blocks. On the TPM build, keep
  wrapped day keys in TPM NV storage instead.
* **The index is a movement history.** Even hashed, 90 days of sightings of the
  same hash is a pattern of life for anyone who learns one hash. Shorter
  `retention.index_days` reduces this; it does not remove it.
* **Look-alike folding** (O/0, I/1, Q/0) means a few distinct plates share a
  hash. It causes false candidates, never missed wipes; the review gate absorbs it.
* **The index and audit log are not encrypted by the application.** Footage and
  snapshots are. The rest depends on full-disk encryption released by the TPM,
  which is described in the operator guide and not yet tested on the device.
* **Approved algorithms are not a validated module.** FIPS 140-3 is met only on
  an operating system whose OpenSSL FIPS provider holds a certificate. See
  `docs/compliance_matrix.md`.
* **Face blurring misses faces.** Small, dark, glared or turned faces can get
  through, and writing on vehicles (bumper stickers) is not detected at all.
* **The device certificate key is a file.** Anyone who copies an unencrypted
  disk can impersonate the device to the hot-list server until the certificate
  is revoked.
* **Authenticator codes use HMAC-SHA-1** because authenticator apps require it.
  Security keys are the path that avoids this.
* **Swap and core dumps** could write RAM to disk. Disable swap on the device;
  the systemd unit sets `LimitCORE=0`.
