import Link from "next/link";
import { api, money, relativeTime, titleCase } from "@/lib/api";
import { EmptyState, ErrorState, RiskBadge, StatusBadge } from "@/components/ui";
import { ActionControls } from "./action-controls";

export const dynamic = "force-dynamic";

export default async function ActivityPage() {
  let actions, audit;
  try {
    [actions, audit] = await Promise.all([
      api.actions("?limit=100"),
      api.audit(40),
    ]);
  } catch (error) {
    return <ErrorState error={error} />;
  }

  const pending = actions.actions.filter((a) => a.approval_status === "PENDING");
  const escalated = actions.actions.filter(
    (a) => a.execution_status === "ROLLBACK_FAILED",
  );

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Activity</h1>
          <p className="subtitle">
            {actions.count} actions &middot; {pending.length} awaiting approval
          </p>
        </div>
      </div>

      {escalated.length > 0 ? (
        <div className="banner banner-error">
          <div>
            <strong>
              {escalated.length} action{escalated.length === 1 ? "" : "s"} failed
              AND could not be rolled back.
            </strong>
            <div style={{ marginTop: 3 }}>
              The affected resources may be in an intermediate state. Each
              action&apos;s audit record holds the checkpoint captured before
              execution.
            </div>
          </div>
        </div>
      ) : null}

      {pending.length > 0 ? (
        <>
          <h2>Awaiting approval</h2>
          <div className="stack" style={{ marginBottom: 26 }}>
            {pending.map((action) => (
              <div className="card" key={action.action_id}>
                <div className="spread" style={{ marginBottom: 10 }}>
                  <div>
                    <div className="row">
                      <span className="badge badge-neutral mono">
                        {action.action_type}
                      </span>
                      <Link
                        href={`/findings/${action.finding_id}`}
                        style={{ color: "var(--accent)" }}
                      >
                        <span className="mono">{action.resource_id}</span>
                      </Link>
                      <RiskBadge risk={action.risk} />
                      {action.dry_run ? (
                        <span className="badge badge-neutral">DRY RUN</span>
                      ) : null}
                    </div>
                    <div className="faint" style={{ marginTop: 5 }}>
                      Requested by {action.requested_by}
                      {action.agent_id ? ` (via ${action.agent_id})` : ""} ·{" "}
                      {relativeTime(action.created_at)}
                      {action.approval_expires_at
                        ? ` · approval expires ${new Date(
                            action.approval_expires_at,
                          ).toLocaleString()}`
                        : ""}
                    </div>
                  </div>
                  <ActionControls
                    actionId={action.action_id}
                    approvalStatus={action.approval_status}
                    executionStatus={action.execution_status}
                  />
                </div>
                {action.reason ? (
                  <p className="muted" style={{ margin: 0, fontSize: 13 }}>
                    {action.reason}
                  </p>
                ) : null}
                {action.policy_rule ? (
                  <div className="faint" style={{ marginTop: 6 }}>
                    Policy rule <span className="mono">{action.policy_rule}</span>
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        </>
      ) : null}

      <h2>All actions</h2>
      {actions.count === 0 ? (
        <EmptyState
          title="No actions have been proposed."
          hint="Open a finding and propose one of its recommendations."
        />
      ) : (
        <div className="table-wrap" style={{ marginBottom: 26 }}>
          <table>
            <thead>
              <tr>
                <th>Action</th>
                <th>Resource</th>
                <th>Risk</th>
                <th>Policy</th>
                <th>Approval</th>
                <th>Execution</th>
                <th className="num">Realized</th>
                <th>When</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {actions.actions.map((action) => (
                <tr key={action.action_id}>
                  <td className="mono" style={{ fontSize: 12 }}>
                    {action.action_type}
                  </td>
                  <td>
                    <Link
                      href={`/findings/${action.finding_id}`}
                      style={{ color: "var(--accent)" }}
                    >
                      <span className="mono">{action.resource_id}</span>
                    </Link>
                  </td>
                  <td>
                    <RiskBadge risk={action.risk} />
                  </td>
                  <td className="faint" style={{ fontSize: 12 }}>
                    {action.policy_decision.replace(/_/g, " ")}
                  </td>
                  <td>
                    <StatusBadge status={action.approval_status} />
                    {action.approved_by ? (
                      <div className="faint">{action.approved_by}</div>
                    ) : null}
                  </td>
                  <td>
                    <StatusBadge status={action.execution_status} />
                    {action.dry_run &&
                    action.execution_status === "COMPLETED" ? (
                      <div className="faint">dry run</div>
                    ) : null}
                  </td>
                  <td className="num">
                    {action.realized_monthly_savings && !action.dry_run ? (
                      <span style={{ color: "var(--save)" }}>
                        {money(action.realized_monthly_savings)}
                      </span>
                    ) : (
                      <span className="faint">-</span>
                    )}
                  </td>
                  <td className="faint">{relativeTime(action.created_at)}</td>
                  <td>
                    <ActionControls
                      actionId={action.action_id}
                      approvalStatus={action.approval_status}
                      executionStatus={action.execution_status}
                      compact
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2>Audit trail</h2>
      <p className="faint" style={{ marginTop: -6, marginBottom: 12 }}>
        Every scan, proposal, approval, execution and rollback, including the
        ones that were refused before anything happened.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Event</th>
              <th>Actor</th>
              <th>Resource</th>
              <th>Outcome</th>
            </tr>
          </thead>
          <tbody>
            {audit.entries.map((entry) => (
              <tr key={entry.audit_id}>
                <td className="faint">{relativeTime(entry.timestamp)}</td>
                <td className="mono" style={{ fontSize: 12 }}>
                  {entry.event}
                </td>
                <td className="muted">
                  {entry.actor}
                  {entry.agent_id ? (
                    <span className="faint"> ({entry.agent_id})</span>
                  ) : null}
                </td>
                <td className="mono faint">{entry.resource_id ?? "-"}</td>
                <td>
                  <StatusBadge status={entry.outcome} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
