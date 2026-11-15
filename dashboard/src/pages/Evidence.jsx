import React, { useEffect, useState } from "react";
import { api, can, formatTime } from "../client.js";
import AuthedImage from "../components/AuthedImage.jsx";

const STATUS = { awaiting_shares: "Waiting for key shares", unsealed: "Unsealed", failed: "Failed", expired: "Expired" };

function Viewer({ request }) {
  const [frame, setFrame] = useState(0);
  return (
    <div className="viewer">
      <AuthedImage path={`/unseal/${request.id}/frames/${frame}`} alt={`Frame ${frame + 1}`} className="snapshot"
                   fallback="Viewing window closed" />
      <div className="row">
        <button className="ghost" disabled={frame === 0} onClick={() => setFrame(frame - 1)}>◀ Previous</button>
        <span className="muted small">Frame {frame + 1} of {request.frame_count}</span>
        <button className="ghost" disabled={frame >= request.frame_count - 1} onClick={() => setFrame(frame + 1)}>Next ▶</button>
      </div>
      <p className="muted small">Held in memory only and removed when the viewing window closes. Viewing is logged.</p>
    </div>
  );
}

function RequestCard({ request, user, onChanged }) {
  const [share, setShare] = useState("");
  const [error, setError] = useState("");
  const involved = request.requested_by === user.username || request.contributors.includes(user.username);
  const canContribute = can(user, "custody") && request.status === "awaiting_shares" &&
    !request.contributors.includes(user.username);

  const submit = async (event) => {
    event.preventDefault();
    setError("");
    try {
      await api(`/unseal/${request.id}/share`, { method: "POST", body: { share } });
      setShare("");
      onChanged();
    } catch (err) {
      setError(err.message);
      onChanged();
    }
  };

  return (
    <div className="request">
      <div className="row between">
        <strong>Request #{request.id} · case {request.case_ref}</strong>
        <span className={`badge req-${request.status}`}>{STATUS[request.status] || request.status}</span>
      </div>
      <p className="small">
        Filed by {request.requested_by} on {formatTime(request.created_ts)}. Reason: {request.reason}
      </p>
      <p className="muted small">
        Key shares: {request.contributors.length} of {request.shares_needed} needed
        {request.contributors.length > 0 && <> (from {request.contributors.join(", ")})</>}
      </p>
      {canContribute && (
        <form className="row" onSubmit={submit}>
          <input type="password" value={share} onChange={(e) => setShare(e.target.value)} required
                 autoComplete="off" placeholder="Your custodian key share" aria-label="Your custodian key share" />
          <button className="primary">Add my share</button>
        </form>
      )}
      {error && <div className="banner danger">{error}</div>}
      {request.viewable && involved && <Viewer request={request} />}
      {request.status === "unsealed" && !request.viewable && (
        <p className="muted small">The viewing window has closed. File a new request to see this clip again.</p>
      )}
    </div>
  );
}

function Holds({ user }) {
  const [holds, setHolds] = useState([]);
  const [form, setForm] = useState({ case_ref: "", from: "", to: "", hold_days: 30 });
  const [error, setError] = useState("");
  const load = () => api("/holds").then(setHolds).catch(() => {});
  useEffect(() => { load(); }, []);

  const create = async (event) => {
    event.preventDefault();
    setError("");
    try {
      await api("/holds", { method: "POST", body: {
        case_ref: form.case_ref, hold_days: Number(form.hold_days),
        ts_start: new Date(form.from).getTime() / 1000, ts_end: new Date(form.to).getTime() / 1000,
      } });
      setForm({ case_ref: "", from: "", to: "", hold_days: 30 });
      load();
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <section className="card">
      <h2>Legal holds <span className="count">{holds.length}</span></h2>
      <p className="muted small">
        A hold pauses the automatic purge for one time window only (72 hours at most). Everything outside it is
        still deleted on schedule, and the hold itself expires.
      </p>
      {holds.length > 0 && (
        <table>
          <thead><tr><th>Case</th><th>Footage from</th><th>to</th><th>Hold expires</th><th>By</th><th /></tr></thead>
          <tbody>
            {holds.map((h) => (
              <tr key={h.id}>
                <td>{h.case_ref}</td><td>{formatTime(h.ts_start)}</td><td>{formatTime(h.ts_end)}</td>
                <td>{formatTime(h.expires_ts)}</td><td>{h.created_by}</td>
                <td className="right">
                  {can(user, "holds") && (
                    <button className="ghost" onClick={() => api(`/holds/${h.id}`, { method: "DELETE" }).then(load)}>Release</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {can(user, "holds") && (
        <form onSubmit={create}>
          <div className="grid four">
            <label>Case number<input value={form.case_ref} required onChange={(e) => setForm({ ...form, case_ref: e.target.value })} /></label>
            <label>Footage from<input type="datetime-local" value={form.from} required onChange={(e) => setForm({ ...form, from: e.target.value })} /></label>
            <label>Footage to<input type="datetime-local" value={form.to} required onChange={(e) => setForm({ ...form, to: e.target.value })} /></label>
            <label>Hold for (days)<input type="number" min={1} max={180} value={form.hold_days} onChange={(e) => setForm({ ...form, hold_days: e.target.value })} /></label>
          </div>
          {error && <div className="banner danger">{error}</div>}
          <button className="primary">Place hold</button>
        </form>
      )}
    </section>
  );
}

export default function Evidence({ user }) {
  const [requests, setRequests] = useState([]);
  const load = () => api("/unseal").then(setRequests).catch(() => {});

  useEffect(() => {
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, []);

  return (
    <>
      <section className="card">
        <h2>Unseal requests <span className="count">{requests.length}</span></h2>
        <p className="muted small">
          Sealed footage cannot be opened by one person. A request is filed from Search; it opens only after enough
          custodians, each signed in as themselves, add their key share.
        </p>
        {requests.length === 0 && <p className="muted">No requests yet.</p>}
        {requests.map((r) => <RequestCard key={r.id} request={r} user={user} onChanged={load} />)}
      </section>
      <Holds user={user} />
    </>
  );
}
