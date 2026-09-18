import { Fragment } from "react";
import { api, percent } from "@/lib/api";
import { ErrorState, RiskBadge } from "@/components/ui";

export const dynamic = "force-dynamic";

/**
 * Policy and safety.
 *
 * Read-only on purpose. Policy is version-controlled YAML deployed with the
 * application, not something edited in a web form: a rule that decides whether
 * a production database can be resized unattended belongs in code review, with
 * an author and a diff, not in a text box behind a session cookie.
 */
export default async function SettingsPage() {
  let policies, root;
  try {
    [policies, root] = await Promise.all([api.policies(), api.root()]);
  } catch (error) {
    return <ErrorState error={error} />;
  }

  const ceilings = policies.deployment_ceilings as Record<string, unknown>;
  const denyRules = policies.rules.filter((r) => r.effect === "deny");
  const autoRules = policies.rules.filter(
    (r) => r.effect === "allow" && r.auto_execute,
  );
  const approvalRules = policies.rules.filter(
    (r) => r.effect === "allow" && !r.auto_execute,
  );

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Policy &amp; Safety</h1>
          <p className="subtitle">
            {policies.rules.length} rules &middot; {denyRules.length} protections
            &middot; {autoRules.length} permit unattended execution
          </p>
        </div>
      </div>

      <div
        className={`banner ${
          root.safety.autopilot_enabled && !root.safety.dry_run_default
            ? "banner-warn"
            : "banner-safe"
        }`}
      >
        <div>
          <strong>{root.safety.summary}</strong>
          <div style={{ marginTop: 4 }}>
            Dry run {root.safety.dry_run_default ? "on" : "off"} &middot;
            autopilot {root.safety.autopilot_enabled ? "enabled" : "disabled"}{" "}
            &middot; ceiling {root.safety.autopilot_max_risk.toUpperCase()}.
            These deployment settings override every policy rule: a rule marked
            auto_execute still requires approval unless autopilot is on and the
            action&apos;s risk is at or below the ceiling.
          </div>
        </div>
      </div>

      {policies.validation_problems.length > 0 ? (
        <div className="card" style={{ marginBottom: 18 }}>
          <h2>Policy validation</h2>
          {policies.validation_problems.map((problem, index) => (
            <div key={index} style={{ marginBottom: 8 }}>
              <span
                className={`badge ${
                  problem.severity === "error"
                    ? "badge-critical"
                    : "badge-medium"
                }`}
              >
                {problem.severity}
              </span>{" "}
              <span className="mono">{problem.rule}</span>
              <div className="muted" style={{ fontSize: 13, marginTop: 3 }}>
                {problem.message}
              </div>
            </div>
          ))}
        </div>
      ) : null}

      <div className="card" style={{ marginBottom: 18 }}>
        <h2>Deployment</h2>
        <dl className="kv">
          <dt>Version</dt>
          <dd>{root.version}</dd>
          {Object.entries(root.configuration).map(([key, value]) => (
            <Fragment key={key}>
              <dt>{key.replace(/_/g, " ")}</dt>
              <dd>{String(value ?? "-")}</dd>
            </Fragment>
          ))}
          <dt>Executable actions</dt>
          <dd className="mono" style={{ fontSize: 12 }}>
            {root.executable_actions.join(", ")}
          </dd>
        </dl>
      </div>

      <PolicySection
        title="Protections"
        hint="These deny. A matching deny beats every allow rule regardless of priority."
        rules={denyRules}
      />
      <PolicySection
        title="Permitted unattended"
        hint="Narrow, reversible and low-value-at-risk. Still subject to the deployment ceilings above."
        rules={autoRules}
      />
      <PolicySection
        title="Permitted with approval"
        hint="Allowed, but a human must say yes. Anything matching no rule at all also lands here."
        rules={approvalRules}
      />

      <p className="faint" style={{ marginTop: 18 }}>
        Policy lives in{" "}
        <span className="mono">
          apps/api/cloudwaste/policy/default_policies.yaml
        </span>{" "}
        and is deployed with the application. It is not editable here: a rule
        deciding whether production can be changed unattended belongs in version
        control with an author and a diff.
      </p>
    </>
  );
}

function PolicySection({
  title,
  hint,
  rules,
}: {
  title: string;
  hint: string;
  rules: Awaited<ReturnType<typeof api.policies>>["rules"];
}) {
  if (rules.length === 0) return null;
  return (
    <div style={{ marginBottom: 18 }}>
      <h2>{title}</h2>
      <p className="faint" style={{ marginTop: -6, marginBottom: 10 }}>
        {hint}
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th style={{ width: 40 }}>#</th>
              <th>Rule</th>
              <th>Matches</th>
              <th>Max risk</th>
              <th>Min confidence</th>
              <th>Outcome</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => (
              <tr key={rule.name}>
                <td className="faint mono">{rule.priority}</td>
                <td>
                  <span className="mono" style={{ fontSize: 12 }}>
                    {rule.name}
                  </span>
                  <div className="faint" style={{ maxWidth: 420 }}>
                    {rule.description}
                  </div>
                </td>
                <td className="faint" style={{ fontSize: 12 }}>
                  {[
                    rule.resource_type,
                    rule.environment,
                    rule.action,
                  ]
                    .filter(Boolean)
                    .join(" · ") || "anything"}
                </td>
                <td>
                  {rule.max_risk ? (
                    <RiskBadge risk={rule.max_risk} />
                  ) : (
                    <span className="faint">-</span>
                  )}
                </td>
                <td className="mono faint">
                  {rule.min_confidence !== null
                    ? percent(rule.min_confidence)
                    : "-"}
                </td>
                <td>
                  {rule.effect === "deny" ? (
                    <span className="badge badge-critical">DENY</span>
                  ) : rule.auto_execute ? (
                    <span className="badge badge-medium">AUTO</span>
                  ) : (
                    <span className="badge badge-neutral">APPROVAL</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
