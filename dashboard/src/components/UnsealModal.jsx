import React, { useState } from "react";
import { api, formatTime } from "../client.js";

// Files an unseal request for one sealed clip. Filing it shows nothing:
// the footage only opens once enough custodians add their key shares.
export default function UnsealModal({ sighting, caseRef, onClose, onFiled }) {
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api("/unseal", { method: "POST", body: { clip_id: sighting.clip_id, case_ref: caseRef, reason } });
      onFiled();
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <form className="card modal" onClick={(e) => e.stopPropagation()} onSubmit={submit}>
        <h2>Request to unseal footage</h2>
        <p className="muted">
          Sighting at {formatTime(sighting.ts)} · case {caseRef}. This footage is sealed. Filing a request does not
          open it: custodians must each add their key share under their own sign-in, and the request, the reason
          and everyone involved are written to the audit log.
        </p>
        <label>
          Reason
          <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={3} required minLength={10}
                    placeholder="Why this clip is needed for the case" />
        </label>
        {error && <div className="banner danger">{error}</div>}
        <div className="row end">
          <button type="button" className="ghost" onClick={onClose}>Cancel</button>
          <button className="primary" disabled={busy}>File request</button>
        </div>
      </form>
    </div>
  );
}
