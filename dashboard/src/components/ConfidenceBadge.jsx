import React from "react";

// Match confidence, always shown as a number and a word, never colour alone.
export default function ConfidenceBadge({ value }) {
  const percent = Math.round((value || 0) * 100);
  const level = percent >= 85 ? "high" : percent >= 65 ? "medium" : "low";
  return (
    <span className={`badge conf-${level}`} title="OCR confidence, reduced when attributes disagree with the hotlist">
      {percent}% confidence · {level}
    </span>
  );
}
