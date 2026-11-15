import React, { useState } from "react";
import { api, formatTime, titleCase } from "../client.js";
import UnsealModal from "../components/UnsealModal.jsx";

const EMPTY = { case_ref: "", plate: "", color: "", make: "", model: "", body_type: "", direction: "", from: "", to: "" };
const toTs = (value) => (value ? new Date(value).getTime() / 1000 : null);

export default function Search({ onUnsealFiled }) {
  const [form, setForm] = useState(EMPTY);
  const [results, setResults] = useState(null);
  const [searchedCase, setSearchedCase] = useState("");
  const [error, setError] = useState("");
  const [unseal, setUnseal] = useState(null);

  const field = (name) => ({ value: form[name], onChange: (e) => setForm({ ...form, [name]: e.target.value }) });

  const submit = async (event) => {
    event.preventDefault();
    setError("");
    try {
      const { from, to, ...rest } = form;
      const data = await api("/search", { method: "POST", body: { ...rest, ts_from: toTs(from), ts_to: toTs(to) } });
      setResults(data.results);
      setSearchedCase(form.case_ref.trim());
      setForm({ ...form, plate: "" });           // do not leave a typed plate sitting on screen
    } catch (err) {
      setError(err.message);
      setResults(null);
    }
  };

  return (
    <>
      <form className="card" onSubmit={submit}>
        <h2>Search</h2>
        <p className="muted small">Every search is recorded in the audit log with your name and the case number.</p>
        <div className="grid four">
          <label>Case number (required)<input {...field("case_ref")} required placeholder="e.g. 24-0117" /></label>
          <label>
            License plate
            <input {...field("plate")} autoComplete="off" spellCheck={false} placeholder="optional" />
            <span className="hint">Hashed before searching. The plate you type is never stored or logged.</span>
          </label>
          <label>Color<input {...field("color")} placeholder="e.g. silver" /></label>
          <label>Make<input {...field("make")} placeholder="e.g. toyota" /></label>
          <label>Model<input {...field("model")} placeholder="e.g. camry" /></label>
          <label>
            Body type
            <select {...field("body_type")}>
              <option value="">Any</option>
              {["car", "truck", "bus", "motorcycle"].map((v) => <option key={v} value={v}>{titleCase(v)}</option>)}
            </select>
          </label>
          <label>
            Direction
            <select {...field("direction")}>
              <option value="">Any</option>
              {["N", "NE", "E", "SE", "S", "SW", "W", "NW"].map((v) => <option key={v}>{v}</option>)}
            </select>
          </label>
          <span />
          <label>From<input type="datetime-local" {...field("from")} /></label>
          <label>To<input type="datetime-local" {...field("to")} /></label>
        </div>
        {error && <div className="banner danger">{error}</div>}
        <button className="primary">Search</button>
      </form>

      {results && (
        <section className="card">
          <h2>Results <span className="count">{results.length}</span></h2>
          {results.length === 0 ? (
            <p className="muted">No indexed vehicle matches those filters within the retention window.</p>
          ) : (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr><th>Time</th><th>Camera</th><th>Vehicle</th><th>Body</th><th>Direction</th><th>Speed (est.)</th><th>Footage</th></tr>
                </thead>
                <tbody>
                  {results.map((r) => (
                    <tr key={r.id}>
                      <td>{formatTime(r.ts)}</td>
                      <td>{r.camera_id}</td>
                      <td>{[r.color, r.make, r.model].filter(Boolean).map(titleCase).join(" ") || "—"}</td>
                      <td>{titleCase(r.body_type)}</td>
                      <td>{r.direction || "—"}</td>
                      <td>{r.speed_kph != null ? `${Math.round(r.speed_kph)} km/h` : "—"}</td>
                      <td>
                        {r.clip_id
                          ? <button className="ghost" onClick={() => setUnseal(r)}>Sealed · request unseal</button>
                          : <span className="muted">Purged or not kept</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {unseal && (
        <UnsealModal sighting={unseal} caseRef={searchedCase} onClose={() => setUnseal(null)}
                     onFiled={() => { setUnseal(null); onUnsealFiled(); }} />
      )}
    </>
  );
}
