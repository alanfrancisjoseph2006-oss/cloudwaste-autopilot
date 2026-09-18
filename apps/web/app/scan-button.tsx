"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";

/**
 * Triggers a scan. A real account takes minutes, so the button reports progress
 * rather than appearing to hang, and it reports what the scan found rather than
 * silently refreshing.
 */
export function ScanButton() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function scan() {
    setRunning(true);
    setError(null);
    setResult(null);
    try {
      const response = await fetch("/api/scan", { method: "POST" });
      if (!response.ok) {
        throw new Error((await response.text()) || `HTTP ${response.status}`);
      }
      const data = await response.json();
      setResult(
        `${data.findings_created} findings, ` +
          `$${Number(data.total_potential_monthly_savings).toLocaleString("en-US", {
            maximumFractionDigits: 0,
          })}/mo identified`,
      );
      startTransition(() => router.refresh());
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setRunning(false);
    }
  }

  return (
    <div style={{ textAlign: "right" }}>
      <button
        className="btn btn-primary"
        onClick={scan}
        disabled={running || pending}
      >
        {running ? "Scanning..." : pending ? "Refreshing..." : "Run scan"}
      </button>
      {result ? (
        <div className="faint" style={{ marginTop: 6 }}>
          {result}
        </div>
      ) : null}
      {error ? (
        <div
          style={{ marginTop: 6, fontSize: 12, color: "var(--risk-critical)" }}
        >
          {error}
        </div>
      ) : null}
    </div>
  );
}
