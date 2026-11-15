import React, { useEffect, useState } from "react";
import { api, formatTime, titleCase } from "../client.js";
import AttributeCard from "../components/AttributeCard.jsx";
import AuthedImage from "../components/AuthedImage.jsx";
import ConfidenceBadge from "../components/ConfidenceBadge.jsx";

const FIELDS = [["color", "Color"], ["make_model", "Make / model"], ["body_type", "Body type"], ["damage", "Damage"]];
const CHOICES = [["", "Choose…"], ["matches", "Matches the case"], ["differs", "Does not match"], ["unclear", "Can't tell"]];
const EMPTY = { observations: {}, decision: "", justification: "" };

export default function ReviewQueue({ initialId }) {
  const [alerts, setAlerts] = useState([]);
  const [selected, setSelected] = useState(initialId);
  const [form, setForm] = useState(EMPTY);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = () =>
    api("/alerts?status=pending").then((rows) => {
      setAlerts(rows);
      setSelected((current) => (rows.some((r) => r.id === current) ? current : rows[0]?.id ?? null));
    }).catch(() => {});

  useEffect(() => { load(); }, []);
  useEffect(() => { setForm(EMPTY); setError(""); }, [selected]);

  const alert = alerts.find((a) => a.id === selected);
  const mismatches = alert ? alert.attr_report.filter((r) => r.state === "mismatch") : [];

  const submit = async (event) => {
    event.preventDefault();
    setError("");
    try {
      await api(`/alerts/${alert.id}/review`, {
        method: "POST",
        body: {
          decision: form.decision === "yes" ? "approved" : "dismissed",
          justification: form.justification,
          observations: form.observations,
        },
      });
      setNotice(form.decision === "yes" ? "Match confirmed and logged." : "Dismissed and logged. No action was taken.");
      load();
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="grid sidebar">
      <section className="card">
        <h2>Review queue <span className="count">{alerts.length}</span></h2>
        {alerts.length === 0 && <p className="muted">No possible matches are waiting.</p>}
        <ul className="list">
          {alerts.map((a) => (
            <li key={a.id}>
              <button className={a.id === selected ? "item active" : "item"} onClick={() => { setSelected(a.id); setNotice(""); }}>
                <strong>{[a.color, a.make, a.model].filter(Boolean).map(titleCase).join(" ") || "Unknown vehicle"}</strong>
                <span className="muted small">{formatTime(a.sighting_ts)} · case {a.case_ref || "—"}</span>
              </button>
            </li>
          ))}
        </ul>
      </section>

      <section className="card">
        {notice && <div className="banner ok">{notice}</div>}
        {!alert ? (
          <p className="muted">Select a possible match to review it.</p>
        ) : (
          <>
            <div className="row between">
              <h2>Possible match · case {alert.case_ref || "—"}</h2>
              <ConfidenceBadge value={alert.confidence} />
            </div>
            <p className="muted small">
              Seen {formatTime(alert.sighting_ts)} on {alert.camera_id}
              {alert.direction && <> · heading {alert.direction}</>}
              {alert.speed_kph != null && <> · about {Math.round(alert.speed_kph)} km/h (estimate)</>}
              {" "}· plate read confidence {Math.round((alert.ocr_confidence || 0) * 100)}%
            </p>
            <p className="notice">
              The system only says the plate <em>hash</em> matched a watch-list entry. It can be wrong: a misread
              character, a cloned plate, or an out-of-date list. Nothing happens unless you confirm.
            </p>

            <div className="grid two">
              <div>
                <h3>Footage</h3>
                {alert.has_snapshot
                  ? <AuthedImage path={`/alerts/${alert.id}/snapshot`} alt="Vehicle snapshot" className="snapshot" />
                  : <div className="image-placeholder snapshot">Snapshot expired. Dismiss, or request an unseal from Search.</div>}
              </div>
              <div>
                <h3>System comparison</h3>
                {mismatches.length > 0 && (
                  <div className="banner warn">
                    {mismatches.length} attribute{mismatches.length > 1 ? "s do" : " does"} not match the watch list.
                  </div>
                )}
                <div className="attrs">
                  {alert.attr_report.map((item) => <AttributeCard key={item.attribute} item={item} />)}
                </div>
              </div>
            </div>

            <form onSubmit={submit}>
              <h3>Confirm details</h3>
              <p className="muted small">Compare the footage with the case file yourself and record what you see.</p>
              <div className="grid four">
                {FIELDS.map(([key, label]) => (
                  <label key={key}>
                    {label}
                    <select value={form.observations[key] || ""}
                            onChange={(e) => setForm({ ...form, observations: { ...form.observations, [key]: e.target.value } })}>
                      {CHOICES.map(([value, text]) => <option key={value} value={value}>{text}</option>)}
                    </select>
                  </label>
                ))}
              </div>
              <fieldset>
                <legend>Is this the wanted vehicle?</legend>
                <label className="radio">
                  <input type="radio" name="decision" checked={form.decision === "no"}
                         onChange={() => setForm({ ...form, decision: "no" })} /> No, dismiss
                </label>
                <label className="radio">
                  <input type="radio" name="decision" checked={form.decision === "yes"}
                         onChange={() => setForm({ ...form, decision: "yes" })} /> Yes, confirm the match
                </label>
              </fieldset>
              {form.decision === "yes" && (
                <label>
                  Why are you sure? (required, written to the audit log)
                  <textarea rows={3} value={form.justification} required minLength={20}
                            onChange={(e) => setForm({ ...form, justification: e.target.value })}
                            placeholder="What in the footage matches the case file" />
                </label>
              )}
              {error && <div className="banner danger">{error}</div>}
              <button className="primary" disabled={!form.decision}>Submit</button>
            </form>
          </>
        )}
      </section>
    </div>
  );
}
