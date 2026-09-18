"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

/**
 * Approve, reject, execute and roll back.
 *
 * Rejection requires a typed reason, and execution of a non-dry-run action asks
 * for confirmation naming the resource. Both are friction on purpose: these are
 * the two buttons in the product that change somebody's infrastructure, and the
 * cost of a moment's hesitation is far lower than the cost of a misclick.
 */
export function ActionControls({
  actionId,
  approvalStatus,
  executionStatus,
  compact = false,
}: {
  actionId: string;
  approvalStatus: string;
  executionStatus: string;
  compact?: boolean;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(
    null,
  );
  const [rejecting, setRejecting] = useState(false);
  const [reason, setReason] = useState("");

  async function call(path: string, body?: unknown, label?: string) {
    setBusy(label ?? path);
    setMessage(null);
    try {
      const response = await fetch(`/api/actions/${actionId}/${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data?.detail ?? `HTTP ${response.status}`);
      }
      setMessage({
        ok: true,
        text: data.message ?? `${label ?? path} succeeded`,
      });
      router.refresh();
    } catch (cause) {
      setMessage({
        ok: false,
        text: cause instanceof Error ? cause.message : String(cause),
      });
    } finally {
      setBusy(null);
      setRejecting(false);
    }
  }

  const canApprove = approvalStatus === "PENDING";
  const canExecute =
    executionStatus === "NOT_STARTED" &&
    (approvalStatus === "APPROVED" || approvalStatus === "NOT_REQUIRED");
  const canRollback = executionStatus === "COMPLETED";

  return (
    <div style={{ textAlign: "right" }}>
      <div className="row" style={{ justifyContent: "flex-end" }}>
        {canApprove ? (
          <>
            <button
              className="btn btn-primary"
              disabled={busy !== null}
              onClick={() => call("approve", { note: "Approved in console" }, "approve")}
            >
              {busy === "approve" ? "..." : "Approve"}
            </button>
            <button
              className="btn btn-danger"
              disabled={busy !== null}
              onClick={() => setRejecting((value) => !value)}
            >
              Reject
            </button>
          </>
        ) : null}

        {canExecute ? (
          <button
            className="btn"
            disabled={busy !== null}
            onClick={() => {
              const ok = window.confirm(
                `Execute ${actionId}?\n\nThis runs the remediation state machine: ` +
                  `preflight, checkpoint, execute, verify, and roll back if ` +
                  `verification fails.`,
              );
              if (ok) call("execute?settle_seconds=0", undefined, "execute");
            }}
          >
            {busy === "execute" ? "Executing..." : "Execute"}
          </button>
        ) : null}

        {canRollback ? (
          <button
            className="btn btn-danger"
            disabled={busy !== null}
            onClick={() => {
              const ok = window.confirm(
                `Roll back ${actionId}?\n\nThis restores the checkpoint captured ` +
                  `before the action ran.`,
              );
              if (ok) call("rollback", undefined, "rollback");
            }}
          >
            {busy === "rollback" ? "..." : "Roll back"}
          </button>
        ) : null}
      </div>

      {rejecting ? (
        <div style={{ marginTop: 8, textAlign: "left" }}>
          <input
            className="btn"
            style={{ width: "100%", cursor: "text" }}
            placeholder="Why is this being rejected?"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
          <div className="row" style={{ marginTop: 6 }}>
            <button
              className="btn btn-danger"
              disabled={!reason.trim() || busy !== null}
              onClick={() => call("reject", { reason }, "reject")}
            >
              Confirm rejection
            </button>
            <button className="btn" onClick={() => setRejecting(false)}>
              Cancel
            </button>
          </div>
        </div>
      ) : null}

      {message && !compact ? (
        <div
          style={{
            marginTop: 8,
            fontSize: 12,
            textAlign: "left",
            color: message.ok ? "var(--save)" : "var(--risk-critical)",
          }}
        >
          {message.text}
        </div>
      ) : null}
    </div>
  );
}
