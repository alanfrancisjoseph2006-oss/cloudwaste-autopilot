"use client";

import { useState } from "react";

const SUGGESTIONS = [
  "What am I spending on AWS?",
  "Where can I save money?",
  "Why did my bill go up?",
  "Which resources are idle?",
];

interface Turn {
  role: "user" | "assistant";
  text: string;
  backend?: string;
  tools?: string[];
}

export function ChatPanel() {
  const [turns, setTurns] = useState<Turn[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);

  async function ask(message: string) {
    if (!message.trim() || busy) return;
    setTurns((prior) => [...prior, { role: "user", text: message }]);
    setInput("");
    setBusy(true);
    try {
      const response = await fetch("/api/agent/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data?.detail ?? `HTTP ${response.status}`);
      }
      setTurns((prior) => [
        ...prior,
        {
          role: "assistant",
          text: data.text,
          backend: data.backend,
          tools: (data.tool_calls ?? []).map((c: { name: string }) => c.name),
        },
      ]);
    } catch (cause) {
      setTurns((prior) => [
        ...prior,
        {
          role: "assistant",
          text: cause instanceof Error ? cause.message : String(cause),
          backend: "error",
        },
      ]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      {turns.length === 0 ? (
        <div style={{ marginBottom: 14 }}>
          <p className="muted" style={{ marginTop: 0 }}>
            Ask about spend, waste, a specific resource, or a change in the bill.
          </p>
          <div className="row" style={{ flexWrap: "wrap" }}>
            {SUGGESTIONS.map((suggestion) => (
              <button
                key={suggestion}
                className="btn"
                onClick={() => ask(suggestion)}
                disabled={busy}
              >
                {suggestion}
              </button>
            ))}
          </div>
        </div>
      ) : null}

      <div style={{ marginBottom: 14 }}>
        {turns.map((turn, index) => (
          <div key={index} style={{ marginBottom: 16 }}>
            {turn.role === "user" ? (
              <div style={{ fontWeight: 600 }}>{turn.text}</div>
            ) : (
              <>
                <div className="prose" style={{ whiteSpace: "pre-wrap" }}>
                  {turn.text}
                </div>
                <div className="faint" style={{ marginTop: 6 }}>
                  {turn.backend}
                  {turn.tools?.length ? ` · ${turn.tools.join(", ")}` : ""}
                </div>
              </>
            )}
          </div>
        ))}
        {busy ? <div className="muted">Thinking...</div> : null}
      </div>

      <form
        onSubmit={(event) => {
          event.preventDefault();
          ask(input);
        }}
        className="row"
      >
        <input
          className="btn"
          style={{ flex: 1, cursor: "text" }}
          placeholder="Ask about this account..."
          value={input}
          onChange={(event) => setInput(event.target.value)}
          disabled={busy}
        />
        <button className="btn btn-primary" type="submit" disabled={busy || !input.trim()}>
          Ask
        </button>
      </form>
    </div>
  );
}
