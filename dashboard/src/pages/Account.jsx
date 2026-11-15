import React, { useEffect, useState } from "react";
import { api, can, formatTime, setToken, titleCase } from "../client.js";
import { createCredential, securityKeysSupported } from "../webauthn.js";

function SecurityKeys({ user, onChanged }) {
  const [keys, setKeys] = useState([]);
  const [name, setName] = useState("");
  const [message, setMessage] = useState(null);       // { kind, text }
  const [busy, setBusy] = useState(false);

  const load = () => api("/account/keys").then(setKeys).catch(() => {});
  useEffect(() => { load(); }, []);

  const add = async (event) => {
    event.preventDefault();
    setBusy(true);
    setMessage({ kind: "ok", text: "Touch your security key when it blinks." });
    try {
      const begun = await api("/account/keys/begin", { method: "POST" });
      const credential = await createCredential(begun.options);
      await api("/account/keys/finish", {
        method: "POST", body: { challenge_id: begun.challenge_id, credential, name },
      });
      setName("");
      setMessage({ kind: "ok", text: "Security key added. It is now required every time you sign in." });
      await load();
      onChanged();
    } catch (err) {
      setMessage({ kind: "danger", text: err.message });
    } finally {
      setBusy(false);
    }
  };

  const remove = async (key) => {
    if (!window.confirm(`Remove "${key.name}"? You will be signed out.`)) return;
    try {
      await api(`/account/keys/${key.id}`, { method: "DELETE" });
      setToken(null);
      window.location.reload();
    } catch (err) {
      setMessage({ kind: "danger", text: err.message });
    }
  };

  return (
    <section className="card">
      <h2>Security keys <span className="count">{keys.length}</span></h2>
      {user.restricted ? (
        <div className="banner warn">
          Your role requires a security key. Add one now to finish signing in; nothing else is available until you do.
        </div>
      ) : (
        <p className="muted small">
          A security key (a USB or NFC key, or the fingerprint or face unlock built into this computer) proves it is
          you without anything that can be typed into a fake site. Once you add one, authenticator codes stop working
          for your account.
        </p>
      )}
      {keys.length > 0 && (
        <table>
          <thead><tr><th>Name</th><th>Added</th><th>Last used</th><th /></tr></thead>
          <tbody>
            {keys.map((key) => (
              <tr key={key.id}>
                <td>{key.name}</td><td>{formatTime(key.created_ts)}</td><td>{formatTime(key.last_used_ts)}</td>
                <td className="right">
                  {!user.restricted && <button className="ghost" onClick={() => remove(key)}>Remove</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {securityKeysSupported() ? (
        <form className="row" onSubmit={add}>
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={40}
                 placeholder="Name for this key, e.g. Blue YubiKey" aria-label="Name for this key" />
          <button className="primary" disabled={busy}>{busy ? "Waiting for key…" : "Add security key"}</button>
        </form>
      ) : (
        <div className="banner warn">
          Security keys need HTTPS or the address http://localhost. Open the dashboard that way to add one.
        </div>
      )}
      {message && <div className={`banner ${message.kind}`} role="status">{message.text}</div>}
    </section>
  );
}

function Users({ me }) {
  const [data, setData] = useState({ users: [], roles: [] });
  const [form, setForm] = useState({ username: "", password: "", role: "reviewer" });
  const [created, setCreated] = useState(null);
  const [error, setError] = useState("");

  const load = () => api("/admin/users").then(setData).catch(() => {});
  useEffect(() => { load(); }, []);

  const act = async (run) => {
    setError("");
    try {
      await run();
      await load();
    } catch (err) {
      setError(err.message);
    }
  };
  const update = (username, body) => act(() => api(`/admin/users/${username}`, { method: "PATCH", body }));

  const create = (event) => {
    event.preventDefault();
    act(async () => {
      setCreated(await api("/admin/users", { method: "POST", body: form }));
      setForm({ username: "", password: "", role: "reviewer" });
    });
  };

  return (
    <section className="card">
      <h2>Accounts <span className="count">{data.users.length}</span></h2>
      <p className="muted small">
        Reviewers see live alerts. Investigators also search history and request footage. Supervisors also manage
        legal holds and read the audit log. Auditors read the log and reports only. Admins manage the device and
        accounts but cannot search.
      </p>
      <div className="table-scroll">
        <table>
          <thead><tr><th>User</th><th>Role</th><th>Security keys</th><th>Status</th><th /></tr></thead>
          <tbody>
            {data.users.map((u) => (
              <tr key={u.username}>
                <td>{u.username}</td>
                <td>
                  <select value={u.role} aria-label={`Role of ${u.username}`} disabled={u.username === me.username}
                          onChange={(e) => update(u.username, { role: e.target.value })}>
                    {data.roles.map((r) => <option key={r} value={r}>{titleCase(r)}</option>)}
                  </select>
                </td>
                <td>{u.security_keys}</td>
                <td>{u.disabled ? <span className="status bad">▲ Disabled</span> : <span className="status ok">● Active</span>}</td>
                <td className="right nowrap">
                  {u.security_keys > 0 && (
                    <button className="ghost" title="For a lost key: the user signs in with a code and adds a new one"
                            onClick={() => act(() => api(`/admin/users/${u.username}/keys`, { method: "DELETE" }))}>
                      Reset keys
                    </button>
                  )}{" "}
                  {u.username !== me.username && (
                    <button className="ghost" onClick={() => update(u.username, { disabled: !u.disabled })}>
                      {u.disabled ? "Enable" : "Disable"}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <h3>Add an account</h3>
      <form onSubmit={create}>
        <div className="grid four">
          <label>Username<input value={form.username} required
                                onChange={(e) => setForm({ ...form, username: e.target.value })} /></label>
          <label>Temporary password<input type="password" value={form.password} required minLength={12}
                                          autoComplete="new-password"
                                          onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
          <label>Role
            <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
              {data.roles.map((r) => <option key={r} value={r}>{titleCase(r)}</option>)}
            </select>
          </label>
        </div>
        <button className="primary">Create account</button>
      </form>
      {error && <div className="banner danger" role="alert">{error}</div>}
      {created && (
        <div className="banner ok">
          Account <strong>{created.username}</strong> created. Authenticator secret, shown once:{" "}
          <code>{created.totp_secret}</code>
        </div>
      )}
    </section>
  );
}

export default function Account({ user, onChanged }) {
  return (
    <>
      <SecurityKeys user={user} onChanged={onChanged} />
      {can(user, "users") && <Users me={user} />}
    </>
  );
}
