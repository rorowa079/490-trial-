# Operator guide

## Roles
Each account has one role. The server enforces these; a hidden tab is not the control.

| Role | Can do | Cannot do |
|---|---|---|
| Reviewer | Watch the live view, review possible matches | Search history, see footage, read the audit log |
| Investigator | Everything a reviewer can, plus search past sightings, request an unseal, hold a key share | Legal holds, audit log, reports |
| Supervisor | Everything an investigator can, plus legal holds, audit log, reports | Manage accounts or the device |
| Auditor | Read the audit log, reports and control settings | See any vehicle data |
| Admin | Accounts, purge, tamper unlock, legal holds, audit log, reports; may hold a key share | Search or review. The person who runs the device does not investigate with it. |

## Signing in
Username and password, then a second factor:

* **Security key** (a USB or NFC key, or the fingerprint or face unlock built
  into your computer). After the password, touch the key. This is the strong
  option: it cannot be typed into a fake site.
* **Authenticator code** (6 digits from an app). Accepted only until you add a
  security key. If your role requires a key, signing in with a code lets you
  do one thing: add a key.

Sessions end after 30 minutes idle. Five wrong attempts lock the account for
15 minutes. Everything you do after signing in is logged with your name.

## Adding a security key
Account page, "Add security key", then touch the key. From then on the key is
required every time and authenticator codes stop working for your account.
Add a second key as a spare. Security keys need the dashboard to be opened
over HTTPS, or as `http://localhost` on the device itself.

**Lost key:** an admin chooses "Reset keys" for your account. You sign in with
your authenticator code and add a new key.

## Dashboard
Live view, device health, and the list of possible matches waiting for review.
Faces and pedestrians are blurred in the live view and in everything stored.
"Retention" tells you how long footage is kept and when the oldest will be
destroyed. A red banner means the device locked itself after a tamper event.

## Reviewing a possible match
A possible match means only that a plate *hash* matched the watch list. It can
be wrong: a misread character, a cloned plate, a stale list.

1. Open it from the Review Queue. Look at the snapshot and the comparison
   cards. Red cards are attributes that do **not** match the watch list.
2. Check the case file yourself and record what you see under Confirm details.
   The system does not show you its own reading of the plate, because it never
   keeps one. Read the plate in the snapshot and compare it with the case file.
3. Answer "Is this the wanted vehicle?"
   * **No** dismisses it. Nothing else happens. Dismissing is never held against you.
   * **Yes** needs a written reason, which goes in the audit log under your name.
4. The snapshot is deleted as soon as you submit. Unreviewed snapshots are
   deleted after 72 hours.

When in doubt, dismiss. A missed match costs an alert; a wrong confirmation can
put a stranger in a felony stop.

## Searching after an incident (investigator, supervisor)
Every search needs a case number. Filter by colour, make, model, body type,
direction and time. You may type a plate: it is hashed before searching and is
never stored or logged. Results show attributes only, not footage.

## Viewing footage (unseal)
Footage is sealed. To view a clip:

1. From Search results, choose "request unseal" and give the reason.
2. On the Evidence page, enter your custodian key share.
3. A second custodian signs in as themselves and enters theirs.
4. The clip opens for 10 minutes for the people on the request, then is gone
   from memory. The request, reason, custodians and viewing are all logged.

## Legal holds (supervisor, admin)
Footage is destroyed after 30 days. If a clip is needed for longer, place a
hold on the Evidence page for that case and time window (72 hours at most).
Only that window is kept; the hold itself expires.

## Reports and audits (supervisor, auditor, admin)
The Reports page shows usage totals for any date range: vehicles read,
watch-list matches, confirmed and dismissed reviews, searches by user, footage
opened, footage destroyed. "Download audit package" saves one zip with that
report, the audit log for the period, the result of checking the log for
tampering, and the security settings in force. It holds counts and log entries
only. Downloading it is itself logged.

The package includes the newest audit hash. Keep a copy somewhere off the
device (email it, print it): if the end of the log were ever cut off, that
copy is what would show it.

## If the device locks
A covered lens or opened case wipes the keys and stops processing. An admin
must physically inspect the device, record what they found (Dashboard, Admin
unlock), and restart the service. Sealed footage and the index are unaffected.

---

# Administrator tasks

## Accounts
Account page. Create an account with a temporary password and a role; give the
new user the authenticator secret shown once. Change a role, disable an
account, or reset a lost security key from the same table. The last active
admin cannot be removed.

## HTTPS
Set `api.tls.enabled: true`. The device then serves HTTPS only, TLS 1.3 only,
using the certificate made at provisioning (`data/identity/device.crt`). That
first certificate is self-signed, so browsers warn. To fix that, have your
certificate authority sign `data/identity/device.csr` and save the result over
`device.crt`. Put the host name people type in `api.tls.hostnames` and
`api.webauthn` before provisioning. To also require a certificate from every
browser, set `api.tls.client_ca_file`.

## Signed updates
Whoever publishes updates creates a signing key once, on their own machine,
never on the device:

    python scripts/sign_update.py keygen --out ~/vrs-signing

Copy `update_signing.pub` to `config/` on each device. After changing any model
file, sign the set:

    python scripts/sign_update.py models --key ~/vrs-signing/update_signing.key --version 2026.11

With `updates.require_signed_models: true` the device will not start if a model
is missing from the signed list or differs from it. Hot lists and software
bundles are signed with `sign_update.py file` and checked by
`hash_hotlist.py` and `apply_update.py`.

## Hot list from the agency server
Set `hotlist_sync.url` (https only), `hotlist_sync.ca_file` (the CA that signed
the server's certificate) and keep `require_signature: true`. The device
presents its own certificate, accepts only that CA, checks the list's
signature, hashes the list in memory and replaces the old one. A failed or
forged update leaves the current list in place and is logged.

## Disk encryption (not yet tested on the device)
Footage is encrypted by the application. The index, the audit log and the
device certificate key are ordinary files and rely on the disk being
encrypted. On the device, put the data directory on a LUKS volume whose key is
released by the TPM, so the disk opens only in this device with an unmodified
boot chain. With systemd this is, in outline:

    cryptsetup luksFormat /dev/<data partition>
    systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+2+4+7 /dev/<data partition>
    # add the volume to /etc/crypttab with tpm2-device=auto, mount it at the data directory

These commands have not been run on the Pi for this project. Test them, and
keep a recovery key somewhere safe, before relying on them. The compliance
report (Reports page, or `scripts/compliance_check.py`) shows whether the data
directory is on an encrypted volume.

## Checking the settings
    python scripts/compliance_check.py config/compliance.yaml
    python scripts/check_bom.py

The first lists each technical control and whether it is in force. The second
screens the hardware list against NDAA Section 889. `docs/compliance_matrix.md`
explains what neither can tell you.
