// Browser side of security-key sign-in (WebAuthn / FIDO2).
// The server sends options with base64url strings; the browser API wants bytes.

const toBytes = (text) => {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0)).buffer;
};

const toText = (buffer) =>
  btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export const securityKeysSupported = () =>
  typeof window.PublicKeyCredential !== "undefined" && window.isSecureContext;

const explain = (err) => {
  if (err.name === "NotAllowedError") return new Error("The security key request was cancelled or timed out.");
  if (err.name === "InvalidStateError") return new Error("That security key is already registered to this account.");
  if (err.name === "SecurityError") return new Error("Security keys only work over HTTPS or on localhost.");
  return err;
};

// Register a new key. Returns the JSON the server verifies.
export async function createCredential(options) {
  const publicKey = {
    ...options,
    challenge: toBytes(options.challenge),
    user: { ...options.user, id: toBytes(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: toBytes(c.id) })),
  };
  const credential = await navigator.credentials.create({ publicKey }).catch((err) => { throw explain(err); });
  return {
    id: credential.id,
    rawId: toText(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: toText(credential.response.clientDataJSON),
      attestationObject: toText(credential.response.attestationObject),
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

// Sign a login challenge with an enrolled key.
export async function getAssertion(options) {
  const publicKey = {
    ...options,
    challenge: toBytes(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: toBytes(c.id) })),
  };
  const credential = await navigator.credentials.get({ publicKey }).catch((err) => { throw explain(err); });
  return {
    id: credential.id,
    rawId: toText(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: toText(credential.response.clientDataJSON),
      authenticatorData: toText(credential.response.authenticatorData),
      signature: toText(credential.response.signature),
      userHandle: credential.response.userHandle ? toText(credential.response.userHandle) : null,
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}
