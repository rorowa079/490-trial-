import React, { useEffect, useState } from "react";
import { api, download, formatTime } from "../client.js";

const describe = (detail) =>
  Object.entries(detail || {})
    .filter(([, value]) => value !== null && value !== "" && !(typeof value === "object" && Object.keys(value).length === 0))
    .map(([key, value]) => `${key.replace(/_/g, " ")}: ${typeof value === "object" ? JSON.stringify(value) : value}`)
    .join(" · ");

export default function AuditLog() {
  const [entries, setEntries] = useState([]);
  const [filters, setFilters] = useState({ action: "", actor: "" });
  const [chain, setChain] = useState(null);

  const load = () => {
    const params = new URLSearchParams({ limit: "300" });
    if (filters.action) params.set("action", filters.action);
    if (filters.actor) params.set("actor", filters.actor);
    api(`/audit?${params}`).then((data) => setEntries(data.entries)).catch(() => {});
  };

  useEffect(() => { load(); api("/audit/verify").then(setChain).catch(() => {}); }, []);

  return (
    <section className="card">
      <div className="row between">
        <h2>Audit log</h2>
        {chain && (
          <span className={chain.ok ? "status ok" : "status bad"}>
            {chain.ok ? "● Chain intact: no entry has been altered or removed"
                      : `▲ Log altered at entry ${chain.first_bad_seq}`}
          </span>
        )}
      </div>
      <form className="row" onSubmit={(e) => { e.preventDefault(); load(); }}>
        <select value={filters.action} onChange={(e) => setFilters({ ...filters, action: e.target.value })}
                aria-label="Filter by type">
          <option value="">All activity</option>
          <option value="search">Searches</option>
          <option value="alert">Reviews</option>
          <option value="unseal">Unseals</option>
          <option value="hold">Legal holds</option>
          <option value="purge">Purges</option>
          <option value="login">Sign-ins</option>
          <option value="tamper">Tamper events</option>
          <option value="hotlist">Watch-list updates</option>
          <option value="user">Account changes</option>
          <option value="security_key">Security keys</option>
          <option value="export">Exports</option>
          <option value="integrity">Update checks</option>
        </select>
        <input placeholder="User" value={filters.actor} aria-label="Filter by user"
               onChange={(e) => setFilters({ ...filters, actor: e.target.value })} />
        <button className="ghost">Filter</button>
        <button type="button" className="ghost" title="Last 30 days, as a spreadsheet. The export is logged."
                onClick={() => download("/audit/export", "audit.csv").then(load).catch(() => {})}>
          Export CSV
        </button>
      </form>
      <div className="table-scroll">
        <table>
          <thead><tr><th>#</th><th>Time</th><th>User</th><th>Agency</th><th>Action</th><th>Details</th></tr></thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.seq}>
                <td className="muted">{e.seq}</td>
                <td className="nowrap">{formatTime(e.ts)}</td>
                <td>{e.actor}</td>
                <td className="small">{e.org || "—"}</td>
                <td className="nowrap">{e.action === "search.plate_hashed" ? "Plate search (hashed)" : e.action}</td>
                <td className="small">{describe(e.detail)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
