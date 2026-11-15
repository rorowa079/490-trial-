#!/usr/bin/env bash
# One-time TPM 2.0 provisioning for a deployed device.
#
# Generates the two device keys INSIDE this script's memory, seals each to the
# TPM under a PCR policy, and leaves only TPM-sealed objects on disk. After
# this, config must say:   keys.backend: tpm
#
# NOT YET RUN ON REAL HARDWARE. Written against tpm2-tools 5.x; test it on your
# TPM module (e.g. Infineon SLB9670/9672 on the Pi 5) before relying on it.
set -euo pipefail

DIR=/var/lib/vrs/tpm
PCRS="${VRS_TPM_PCRS:-sha256:0,2,4,7}"

command -v tpm2_createprimary >/dev/null || { echo "install tpm2-tools first"; exit 1; }
HANDLE_HMAC=0x81010001
HANDLE_REVIEW=0x81010002
tpm2_readpublic -c "$HANDLE_HMAC" >/dev/null 2>&1 && { echo "already provisioned: $HANDLE_HMAC exists"; exit 1; }
umask 077
mkdir -p "$DIR"
cd "$DIR"

tpm2_createprimary -C o -g sha256 -G ecc -c primary.ctx
tpm2_pcrread -o pcr.bin "$PCRS"
tpm2_createpolicy --policy-pcr -l "$PCRS" -f pcr.bin -L pcr.policy

seal() {  # name, persistent handle
  # 32 random bytes from the TPM's own generator, sealed without touching disk.
  tpm2_getrandom 32 | tpm2_create -C primary.ctx -L pcr.policy -i - -u "$1.pub" -r "$1.priv"
  tpm2_load -C primary.ctx -u "$1.pub" -r "$1.priv" -c "$1.ctx"
  tpm2_evictcontrol -C o -c "$1.ctx" "$2"      # make it survive reboots
  rm -f "$1.ctx"
}
seal hmac "$HANDLE_HMAC"
seal review "$HANDLE_REVIEW"
rm -f pcr.bin

echo "Keys sealed at $HANDLE_HMAC and $HANDLE_REVIEW."
echo "Record this digest as security.expected_pcr_digest and set require_attestation: true:"
tpm2_pcrread "$PCRS" | awk -F: '/0x/ {gsub(/ /,"",$2); printf "%s", $2}' | sha256sum | cut -d' ' -f1
