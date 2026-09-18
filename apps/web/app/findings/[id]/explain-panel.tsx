"use client";

import { useState } from "react";

/**
 * Asks the agent to explain a finding in prose.
 *
 * The structured evidence on the page above is the source of truth; this is a
 * narration of it. The panel says which backend answered, so a reader always
 * knows whether they are reading a model's prose or the deterministic fallback.
 */
export function ExplainPanel({ findingId }: { findingId: string }) {
  const [busy, setBusy] = useState(false);
  const [answer, setAnswer] = useState<{
    text: string;
    backend: string;
    toolCalls: string[];
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function explain() {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch("/api/agent/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_id: findingId }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data?.detail ?? `HTTP ${response.status}`);
      }
      setAnswer({
        text: data.text,
        backend: data.backend,
        toolCalls: (data.tool_calls ?? []).map((c: { name: string }) => c.name),
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <div className="spread" style={{ marginBottom: 10 }}>
        <h2 style={{ margin: 0 }}>AI investigation</h2>
        <button className="btn" onClick={explain} disabled={busy}>
          {busy ? "Investigating..." : answer ? "Ask again" : "Explain this finding"}
        </button>
      </div>

      {!answer && !error ? (
        <p className="muted" style={{ margin: 0 }}>
          The agent reads the same evidence shown above, plus CloudWatch,
          CloudTrail and AWS&apos;s own recommendations, and explains what it
          found. It can propose an action but cannot execute one.
        </p>
      ) : null}

      {error ? (
        <div className="banner banner-error" style={{ marginBottom: 0 }}>
          {error}
        </div>
      ) : null}

      {answer ? (
        <>
          <div className="prose" style={{ whiteSpace: "pre-wrap" }}>
            {answer.text}
          </div>
          <div className="faint" style={{ marginTop: 12 }}>
            Answered by {answer.backend}
            {answer.toolCalls.length
              ? ` after calling ${answer.toolCalls.join(", ")}`
              : ""}
            .
          </div>
        </>
      ) : null}
    </div>
  );
}
