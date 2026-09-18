import { ErrorState } from "@/components/ui";
import { api } from "@/lib/api";
import { ChatPanel } from "./chat-panel";

export const dynamic = "force-dynamic";

export default async function AgentPage() {
  let tools;
  try {
    tools = await api.agentTools();
  } catch (error) {
    return <ErrorState error={error} />;
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Ask</h1>
          <p className="subtitle">
            {tools.count} tools, all read-only. The agent can investigate and
            propose, but has no tool that changes an AWS resource.
          </p>
        </div>
      </div>

      <ChatPanel />

      <div className="card" style={{ marginTop: 18 }}>
        <h2>Available tools</h2>
        <p className="faint" style={{ marginTop: -6, marginBottom: 12 }}>
          The complete surface the model can reach. `propose_action` creates a
          pending action that a human must approve; there is no approve or
          execute tool.
        </p>
        <div className="grid grid-2">
          {tools.tools.map((tool) => (
            <div key={tool.name}>
              <div className="mono" style={{ color: "var(--accent)", fontSize: 12 }}>
                {tool.name}
              </div>
              <div className="faint" style={{ marginTop: 2 }}>
                {tool.description}
              </div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}
