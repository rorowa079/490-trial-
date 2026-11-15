import React, { useEffect, useState } from "react";
import { api, download, formatTime } from "../client.js";

const isoDay = (date) => date.toISOString().slice(0, 10);
const LABEL = { pass: "In force", warn: "Relaxed", fail: "Not met" };
const MARK = { pass: "●", warn: "◆", fail: "▲" };

const Tile = ({ label, value, note }) => (
  <div className="tile">
    <div className="tile-label">{label}</div>
    <div className="tile-value">{value}</div>
    {note && <div className="muted small">{note}</div>}
  </div>
);

export default function Reports() {
  const today = new Date();
  const [period, setPeriod] = useState({
    from: isoDay(new Date(today.getTime() - 29 * 86400000)), to: isoDay(today),
  });
  const [report, setReport] = useState(null);
  const [posture, setPosture] = useState(null);
  const [error, setError] = useState("");
  const query = `day_from=${period.from}&day_to=${period.to}`;

  const load = () => {
    setError("");
    api(`/reports/transparency?${query}`).then(setReport).catch((err) => setError(err.message));
  };
  useEffect(() => { load(); api("/compliance").then(setPosture).catch(() => {}); }, []);

  const save = (path, name) => download(path, name).catch((err) => setError(err.message));
  const number = (n) => Number(n).toLocaleString();

  return (
    <>
      <section className="card">
        <div className="row between">
          <h2>Transparency report</h2>
          <button className="primary" onClick={() => save(`/reports/export?${query}`, "audit_package.zip")}>
            Download audit package
          </button>
        </div>
        <p className="muted small">
          Usage totals for publication. The audit package adds the full audit log for the period, its integrity
          proof and the security settings in force. It contains counts and log entries only: no plates or images.
          Downloading it is logged.
        </p>
        <form className="row" onSubmit={(e) => { e.preventDefault(); load(); }}>
          <label>From (UTC)<input type="date" value={period.from} max={period.to} required
                            onChange={(e) => setPeriod({ ...period, from: e.target.value })} /></label>
          <label>To (UTC)<input type="date" value={period.to} min={period.from} required
                          onChange={(e) => setPeriod({ ...period, to: e.target.value })} /></label>
          <button className="ghost">Update</button>
        </form>
        {error && <div className="banner danger" role="alert">{error}</div>}
        {report && (
          <>
            <div className="grid four">
              <Tile label="Vehicles read" value={number(report.vehicles_read)}
                    note={`${number(report.plates_hashed)} with a readable plate`} />
              <Tile label="Watch-list matches" value={number(report.hotlist_hits)}
                    note={`${report.hit_rate_percent}% of vehicles read`} />
              <Tile label="Matches confirmed" value={number(report.reviews.confirmed)}
                    note={`${number(report.reviews.dismissed)} dismissed · ${report.reviews.waiting_now} waiting now`} />
              <Tile label="Searches" value={number(report.searches.total)}
                    note={`${report.searches.distinct_cases} case(s) · ${report.searches.by_plate} by plate`} />
              <Tile label="Footage opened" value={number(report.footage_unseals.opened)}
                    note={`${report.footage_unseals.requested} requested`} />
              <Tile label="Shared outside" value={number(report.data_sharing.outside_recipients)}
                    note={`${report.data_sharing.exports} logged export(s)`} />
              <Tile label="Footage destroyed" value={number(report.retention.clips_destroyed)}
                    note={`Kept ${report.retention.clip_days} days, index ${report.retention.index_days} days`} />
              <Tile label="Audit log" value={report.audit_log.chain_intact ? "Intact" : "Altered"}
                    note={`${number(report.audit_log.entries_in_period)} entries in period`} />
            </div>
            {Object.keys(report.searches.by_user).length > 0 && (
              <>
                <h3>Searches by user</h3>
                <table>
                  <thead><tr><th>User</th><th>Searches</th></tr></thead>
                  <tbody>
                    {Object.entries(report.searches.by_user).map(([name, count]) => (
                      <tr key={name}><td>{name}</td><td>{count}</td></tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
            <p className="muted small">
              {report.organization} · {report.camera_id} · generated {report.generated.at} by {report.generated.by}
            </p>
          </>
        )}
      </section>

      {posture && (
        <section className="card">
          <div className="row between">
            <h2>Security controls in force</h2>
            <span className="small">
              {posture.summary.pass} in force · {posture.summary.warn} relaxed · {posture.summary.fail} not met
            </span>
          </div>
          <p className="muted small">
            What this device is doing right now, by NIST SP 800-53 control. This reports settings, not certification:
            hosting, hardware assessment, staff vetting and written policy sit outside the software. Checked{" "}
            {formatTime(posture.checked_ts)}.
          </p>
          <div className="table-scroll">
            <table>
              <thead><tr><th>Control</th><th>Requirement</th><th>Status</th><th>Detail</th></tr></thead>
              <tbody>
                {posture.items.map((item) => (
                  <tr key={item.name}>
                    <td className="nowrap small">{item.control}</td>
                    <td>{item.name}</td>
                    <td className="nowrap">
                      <span className={`badge posture-${item.status}`}>{MARK[item.status]} {LABEL[item.status]}</span>
                    </td>
                    <td className="small">{item.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </>
  );
}
