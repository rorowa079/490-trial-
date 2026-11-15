import React, { useEffect, useState } from "react";
import { imageUrl } from "../client.js";

// Shows an image from an API path that needs the session token.
// `refreshMs` re-fetches on a timer (used for the live feed).
export default function AuthedImage({ path, alt, refreshMs, className, fallback = "No image available" }) {
  const [url, setUrl] = useState(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let alive = true;
    let current = null;
    const load = async () => {
      const next = await imageUrl(path);
      if (!alive) {
        if (next) URL.revokeObjectURL(next);
        return;
      }
      setFailed(!next);
      if (next) {
        setUrl(next);
        if (current) URL.revokeObjectURL(current);
        current = next;
      }
    };
    setUrl(null);
    load();
    const timer = refreshMs ? setInterval(load, refreshMs) : null;
    return () => {
      alive = false;
      if (timer) clearInterval(timer);
      if (current) URL.revokeObjectURL(current);
    };
  }, [path, refreshMs]);

  if (!url) return <div className={`image-placeholder ${className || ""}`}>{failed ? fallback : "Loading…"}</div>;
  return <img className={className} src={url} alt={alt} />;
}
