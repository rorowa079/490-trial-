// Thin wrapper around the operator API. The session token lives in
// sessionStorage, so closing the tab signs you out.

let token = sessionStorage.getItem("vrs-token");
let onSignedOut = () => {};

export function setSignedOutHandler(fn) {
  onSignedOut = fn;
}

export function setToken(value) {
  token = value;
  if (value) sessionStorage.setItem("vrs-token", value);
  else sessionStorage.removeItem("vrs-token");
}

export function hasToken() {
  return Boolean(token);
}

async function request(path, { method = "GET", body } = {}) {
  const response = await fetch(`/api${path}`, {
    method,
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (response.status === 401 && !path.startsWith("/login")) {
    setToken(null);
    onSignedOut();
  }
  return response;
}

export async function api(path, options) {
  const response = await request(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
}

// Images need the Authorization header, so they are fetched and turned into object URLs.
export async function imageUrl(path) {
  const response = await request(path);
  if (!response.ok) return null;
  return URL.createObjectURL(await response.blob());
}

// Fetch a file with the session token and hand it to the browser's download bar.
export async function download(path, fallbackName) {
  const response = await request(path);
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.detail || `Download failed (${response.status})`);
  }
  const name = /filename="([^"]+)"/.exec(response.headers.get("Content-Disposition") || "")?.[1] || fallbackName;
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export const can = (user, ...permissions) => permissions.some((p) => user?.permissions?.includes(p));
export const formatTime = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : "—");
export const titleCase = (s) => (s ? s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()) : "—");
