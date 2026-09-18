"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";

/**
 * Creates an action from a recommendation and shows what policy decided.
 *
 * Deliberately does not offer to execute. Proposing and approving are separate
 * steps taken by (ideally) separate people, and collapsing them into one button
 * would defeat the approval workflow this system is built around.
 */
export function ProposeButton({
  recommendationId,
  actionType,
}: {
  recommendationId: string;
  actionType: string;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<{
    actionId: string;
    decision: string;
    rule: string | null;
    reasons: string[];
    approvalStatus: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function propose() {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch("/api/actions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ recommendation_id: recommendationId }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data?.detail ?? `HTTP ${response.status}`);
      }
      setOutcome({
        actionId: data.action.action_id,
        decision: data.policy.decision,
        rule: data.policy.matched_rule,
        reasons: data.policy.reasons ?? [],
        approvalStatus: data.action.approval_status,
      });
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  if (outcome) {
    const denied = outcome.decision === "DENY";
    return (
      <div className={`banner ${denied ? "banner-error" : "banner-safe"}`} style={{ marginBottom: 0 }}>
        <div>
          <strong>
            {denied
              ? "Policy denied this action."
              : outcome.decision === "AUTO_EXECUTE"
                ? "Authorized for unattended execution."
                : "Queued for approval."}
          </strong>
          {outcome.rule ? (
            <div style={{ marginTop: 3 }}>
              Matched rule <span className="mono">{outcome.rule}</span>
            </div>
          ) : null}
          <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
            {outcome.reasons.map((reason, index) => (
              <li key={index}>{reason}</li>
            ))}
          </ul>
          {!denied ? (
            <div style={{ marginTop: 8 }}>
              <Link href="/actions" style={{ textDecoration: "underline" }}>
                Review and approve in Activity &rarr;
              </Link>
            </div>
          ) : null}
        </div>
      </div>
    );
  }

  return (
    <div>
      <button className="btn" onClick={propose} disabled={busy}>
        {busy ? "Checking policy..." : `Propose ${actionType}`}
      </button>
      <div className="faint" style={{ marginTop: 5 }}>
        Creates a pending action and runs it past the policy engine. Nothing is
        executed.
      </div>
      {error ? (
        <div style={{ marginTop: 6, fontSize: 12, color: "var(--risk-critical)" }}>
          {error}
        </div>
      ) : null}
    </div>
  );
}
