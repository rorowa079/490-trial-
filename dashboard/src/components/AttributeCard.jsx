import React from "react";
import { titleCase } from "../client.js";

const LABEL = { match: "Matches watch list", mismatch: "Doesn't match watch list", unknown: "Not enough information" };

// One attribute: what the camera saw next to what the hotlist says.
export default function AttributeCard({ item }) {
  return (
    <div className={`attr attr-${item.state}`}>
      <div className="attr-name">{titleCase(item.attribute)}</div>
      <div className="attr-values">
        <span>Seen: <strong>{titleCase(item.observed)}</strong></span>
        <span>Watch list: <strong>{titleCase(item.expected)}</strong></span>
      </div>
      <div className="attr-state">{LABEL[item.state]}</div>
    </div>
  );
}
