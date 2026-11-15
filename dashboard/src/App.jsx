import React, { useEffect, useState } from "react";
import { api, can, hasToken, setSignedOutHandler, setToken, titleCase } from "./client.js";
import Login from "./pages/Login.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import ReviewQueue from "./pages/ReviewQueue.jsx";
import Search from "./pages/Search.jsx";
import Evidence from "./pages/Evidence.jsx";
import AuditLog from "./pages/AuditLog.jsx";
import Reports from "./pages/Reports.jsx";
import Account from "./pages/Account.jsx";

// Each page lists the permissions that open it (any one is enough). The server
// enforces the same rules; hiding a tab is a courtesy, not the control.
const PAGES = [
  ["dashboard", "Dashboard", []],
  ["review", "Review Queue", ["alerts"]],
  ["search", "Search", ["search"]],
  ["evidence", "Evidence", ["unseal", "custody", "holds"]],
  ["audit", "Audit Log", ["audit"]],
  ["reports", "Reports", ["reports"]],
  ["account", "Account", []],
];

export default function App() {
  const [user, setUser] = useState(null);
  const [checking, setChecking] = useState(hasToken());
  const [page, setPage] = useState(window.location.hash.slice(1) || "dashboard");
  const [selectedAlert, setSelectedAlert] = useState(null);

  const refreshUser = () => api("/me").then(setUser).catch(() => {});

  useEffect(() => {
    setSignedOutHandler(() => setUser(null));
    if (hasToken()) {
      refreshUser().finally(() => setChecking(false));
    }
    const onHash = () => setPage(window.location.hash.slice(1) || "dashboard");
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const go = (next) => {
    window.location.hash = next;
    setPage(next);
  };

  const signOut = async () => {
    await api("/logout", { method: "POST" }).catch(() => {});
    setToken(null);
    setUser(null);
  };

  if (checking) return null;
  if (!user) return <Login onSignedIn={setUser} />;

  const pages = user.restricted ? [] : PAGES.filter(([, , needs]) => needs.length === 0 || can(user, ...needs));
  const current = user.restricted ? "account" : pages.some(([id]) => id === page) ? page : "dashboard";

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">Vehicle Recognition System</div>
        <nav aria-label="Sections">
          {pages.map(([id, label]) => (
            <button key={id} className={current === id ? "tab active" : "tab"} onClick={() => go(id)}>
              {label}
            </button>
          ))}
        </nav>
        <div className="who">
          <span>
            {user.username} <span className="muted">({titleCase(user.role)})</span>
          </span>
          <button className="ghost" onClick={signOut}>Sign out</button>
        </div>
      </header>
      <main>
        {current === "dashboard" && (
          <Dashboard user={user} onReview={(id) => { setSelectedAlert(id); go("review"); }} />
        )}
        {current === "review" && <ReviewQueue initialId={selectedAlert} />}
        {current === "search" && <Search onUnsealFiled={() => go("evidence")} />}
        {current === "evidence" && <Evidence user={user} />}
        {current === "audit" && <AuditLog />}
        {current === "reports" && <Reports />}
        {current === "account" && <Account user={user} onChanged={refreshUser} />}
      </main>
    </div>
  );
}
