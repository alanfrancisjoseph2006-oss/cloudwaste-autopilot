import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";
import { api } from "@/lib/api";

export const metadata: Metadata = {
  title: "CloudWaste Autopilot",
  description: "Find waste. Understand why. Fix it safely.",
};

export const dynamic = "force-dynamic";

const NAV = [
  { href: "/", label: "Dashboard" },
  { href: "/findings", label: "Findings" },
  { href: "/recommendations", label: "Recommendations" },
  { href: "/actions", label: "Activity" },
  { href: "/agent", label: "Ask" },
  { href: "/settings", label: "Policy & Safety" },
];

/**
 * The safety state is rendered in the sidebar on every page, not tucked into a
 * settings screen. Whether this deployment can currently change anything in AWS
 * is the single most important fact about it, and an operator should never have
 * to go looking for it.
 */
async function SafetyIndicator() {
  try {
    const root = await api.root();
    const armed = !root.safety.dry_run_default && root.safety.autopilot_enabled;
    return (
      <div
        style={{
          marginTop: 18,
          padding: "10px 11px",
          borderRadius: 8,
          border: `1px solid ${armed ? "rgba(251,146,60,0.35)" : "rgba(52,211,153,0.25)"}`,
          background: armed ? "rgba(251,146,60,0.08)" : "rgba(52,211,153,0.06)",
          fontSize: 11,
          lineHeight: 1.45,
        }}
      >
        <div
          style={{
            fontWeight: 650,
            color: armed ? "#fed7aa" : "#a7f3d0",
            marginBottom: 3,
          }}
        >
          {armed ? "AUTOPILOT ARMED" : "SAFE MODE"}
        </div>
        <div style={{ color: "var(--text-faint)" }}>
          {armed
            ? `Executing up to ${root.safety.autopilot_max_risk.toUpperCase()} risk without approval.`
            : "Dry run on or autopilot off. Nothing mutates AWS."}
        </div>
      </div>
    );
  } catch {
    // The API being down must not break navigation on every page.
    return (
      <div
        style={{
          marginTop: 18,
          padding: "10px 11px",
          borderRadius: 8,
          border: "1px solid rgba(248,113,113,0.3)",
          background: "rgba(248,113,113,0.07)",
          fontSize: 11,
          color: "#fecaca",
        }}
      >
        <div style={{ fontWeight: 650, marginBottom: 3 }}>API UNREACHABLE</div>
        <div style={{ color: "var(--text-faint)" }}>
          Start it with <code>uvicorn cloudwaste.main:app --reload</code>
        </div>
      </div>
    );
  }
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          <nav className="sidebar">
            <div className="brand">
              <div className="brand-name">CloudWaste Autopilot</div>
              <div className="brand-tag">Find waste. Understand why. Fix it safely.</div>
            </div>
            {NAV.map((item) => (
              <Link key={item.href} href={item.href} className="nav-link">
                {item.label}
              </Link>
            ))}
            <SafetyIndicator />
          </nav>
          <main className="main">{children}</main>
        </div>
      </body>
    </html>
  );
}
