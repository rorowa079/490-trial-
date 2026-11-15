import React, { useEffect, useState } from "react";
import { api, can, formatTime, titleCase } from "../client.js";
import AuthedImage from "../components/AuthedImage.jsx";
import ConfidenceBadge from "../components/ConfidenceBadge.jsx";

const Dot = ({ ok, label }) => (
  <span className={ok ? "status ok" : "status bad"}>{ok ? "●" : "▲"} {label}</span>
);

function Unlock() {
  const [note, setNote] = useState("");
  const [message, setMessage] = useState("");
  const submit = async (event) => {
    event.preventDefault();
    try {
      const result = await api("/admin/unlock", { method: "POST", body: { inspection_note: note } });
      setMessage(`Lock cleared: ${result.note}.`);
    } catch (err) {
      setMessage(err.message);
    }
  };
  return (
    <form className="row" onSubmit={submit}>
      <input value={note} onChange={(e) => setNote(e.target.value)} required minLength={10}
             placeholder="What you found when you inspected the device" aria-label="Inspection note" />
      <button className="primary">Clear lock</button>
      {message && <span className="small">{message}</span>}
    </form>
  );
}

export default function Dashboard({ onReview, user }) {
  const [status, setStatus] = useState(null);
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    const load = () => {
      api("/status").then(setStatus).catch(() => {});
      if (can(user, "alerts")) api("/alerts?status=pending").then(setAlerts).catch(() => {});
    };
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, []);

  if (!status) return <p className="muted">Loading…</p>;
  const retention = status.retention;
  const storage = Math.round(status.storage_used_fraction * 100);

  return (
    <>
      {status.locked && (
        <div className="banner danger">
          <strong>Device locked: {status.lock_info?.reason}.</strong> Keys were wiped from memory and processing has
          stopped. An admin must inspect the device before it can be unlocked.
          {can(user, "unlock") && <Unlock />}
        </div>
      )}
      {status.key_backend === "software" && (
        <div className="banner warn">
          Development mode: device keys are stored in files, not a TPM. Do not use real plates or deploy like this.
        </div>
      )}
      <div className="grid two">
        {can(user, "live") && (
          <section className="card">
            <h2>Live feed</h2>
            <AuthedImage path="/live.jpg" alt="Live camera view" refreshMs={1000} className="live"
                         fallback="Video offline" />
            <p className="muted small">
              Live view only. Nothing shown here is recorded unless it becomes a sealed event clip.
              {status.redaction.faces && " Faces are blurred before anything is shown or stored."}
            </p>
          </section>
        )}

        <section className="card">
          <h2>System status</h2>
          <dl className="facts">
            <dt>Agency</dt><dd>{status.organization || "—"} · {status.camera_id}</dd>
            <dt>Server</dt><dd><Dot ok={!status.locked} label={status.locked ? "Locked" : "Online"} /></dd>
            <dt>Video</dt><dd><Dot ok={status.video_online} label={status.video_online ? "Online" : "Offline"} /></dd>
            <dt>Storage</dt>
            <dd>
              <div className="meter"><div style={{ width: `${storage}%` }} /></div>
              {storage}% used · {status.vault.clips} sealed clips
            </dd>
            <dt>Retention</dt>
            <dd>
              Clips {retention.clip_days} days · index {retention.index_days} days
              <div className="muted small">
                Oldest clip: {formatTime(retention.oldest_clip_ts)}
                {retention.next_clip_purge_ts && <> · purged by {formatTime(retention.next_clip_purge_ts)}</>}
                {retention.active_holds > 0 && <> · {retention.active_holds} legal hold(s) active</>}
              </div>
            </dd>
            <dt>Privacy</dt>
            <dd><Dot ok={status.redaction.faces}
                     label={status.redaction.faces ? "Faces blurred in stored images" : "Face blurring is off"} /></dd>
            <dt>Watch list</dt>
            <dd>
              {status.hotlist_entries} hashed entries
              {status.hotlist_sync.enabled && (
                <div className="muted small">Signed feed · last update {formatTime(status.hotlist_sync.last_ok)}</div>
              )}
            </dd>
            <dt>Vehicles indexed</dt><dd>{status.sightings_indexed}</dd>
            <dt>Audit log</dt>
            <dd><Dot ok={status.audit_chain_ok}
                     label={status.audit_chain_ok ? "Chain intact" : `Altered at entry ${status.audit_first_bad_seq}`} /></dd>
          </dl>
        </section>
      </div>

      {can(user, "alerts") && <section className="card">
        <h2>Pending reviews <span className="count">{alerts.length}</span></h2>
        {alerts.length === 0 ? (
          <p className="muted">Nothing waiting. Possible matches appear here and go nowhere until someone reviews them.</p>
        ) : (
          <table>
            <thead>
              <tr><th>Seen</th><th>Vehicle</th><th>Case</th><th>Confidence</th><th /></tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <tr key={a.id}>
                  <td>{formatTime(a.sighting_ts)}</td>
                  <td>{[a.color, a.make, a.model].filter(Boolean).map(titleCase).join(" ") || "Unknown vehicle"}</td>
                  <td>{a.case_ref || "—"}</td>
                  <td><ConfidenceBadge value={a.confidence} /></td>
                  <td className="right"><button className="primary" onClick={() => onReview(a.id)}>Review</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>}
    </>
  );
}
