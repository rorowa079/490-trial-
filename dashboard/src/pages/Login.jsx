import React, { useEffect, useState } from "react";
import { api, setToken } from "../client.js";
import { getAssertion, securityKeysSupported } from "../webauthn.js";

export default function Login({ onSignedIn }) {
  const [form, setForm] = useState({ username: "", password: "", code: "" });
  const [info, setInfo] = useState({ mfa_required: true, locked: false, organization: "" });
  const [error, setError] = useState("");
  const [stage, setStage] = useState("idle");      // idle | password | key

  useEffect(() => {
    api("/public").then(setInfo).catch(() => {});
  }, []);

  const change = (field) => (event) => setForm({ ...form, [field]: event.target.value });

  const finish = async (session) => {
    setToken(session.token);
    onSignedIn(await api("/me"));
  };

  const submit = async (event) => {
    event.preventDefault();
    setStage("password");
    setError("");
    try {
      const result = await api("/login", { method: "POST", body: { ...form, code: form.code || null } });
      if (!result.webauthn) return await finish(result);
      // This account has a security key: the password alone gets a challenge, not a session.
      if (!securityKeysSupported()) throw new Error("This browser or address cannot use security keys.");
      setStage("key");
      const credential = await getAssertion(result.webauthn);
      await finish(await api("/login/security-key", {
        method: "POST", body: { challenge_id: result.challenge_id, credential },
      }));
    } catch (err) {
      setError(err.message);
      setStage("idle");
    }
  };

  return (
    <div className="login-wrap">
      <form className="card login" onSubmit={submit}>
        <h1>Vehicle Recognition System</h1>
        <p className="muted">
          {info.organization ? `${info.organization}. ` : ""}Authorized users only. Every action after this point is
          logged.
        </p>
        {info.locked && (
          <div className="banner danger">Device is locked after a tamper event. Processing is stopped.</div>
        )}
        <label>
          Username
          <input value={form.username} onChange={change("username")} autoComplete="username" autoFocus required />
        </label>
        <label>
          Password
          <input type="password" value={form.password} onChange={change("password")}
                 autoComplete="current-password" required />
        </label>
        {info.mfa_required && (
          <label>
            Authenticator code
            <input value={form.code} onChange={change("code")} inputMode="numeric" pattern="[0-9]{6}"
                   maxLength={6} placeholder="6 digits" autoComplete="one-time-code" />
            <span className="hint">Leave empty if you sign in with a security key.</span>
          </label>
        )}
        {stage === "key" && (
          <div className="banner ok" role="status">Password accepted. Touch your security key to finish.</div>
        )}
        {error && <div className="banner danger" role="alert">{error}</div>}
        <button className="primary" disabled={stage !== "idle"}>
          {stage === "idle" ? "Login" : stage === "key" ? "Waiting for security key…" : "Signing in…"}
        </button>
      </form>
    </div>
  );
}
