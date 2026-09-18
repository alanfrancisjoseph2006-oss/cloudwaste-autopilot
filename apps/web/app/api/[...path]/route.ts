/**
 * Proxy from the browser to the CloudWaste API.
 *
 * Client components cannot reach the API directly: it may be on a private
 * network or behind an internal API Gateway, and exposing its URL to the
 * browser would also mean exposing whatever auth sits in front of it. Every
 * mutating call from the UI goes through here instead, which keeps the API
 * address server-side and gives one place to attach the caller's identity.
 *
 * `/api/scan` is a convenience alias for `/api/v1/findings/scan`; everything
 * else forwards path-for-path.
 */

import { NextRequest, NextResponse } from "next/server";

const BASE = process.env.CLOUDWASTE_API_URL ?? "http://127.0.0.1:8000";

const ALIASES: Record<string, string> = {
  scan: "findings/scan",
};

async function forward(request: NextRequest, path: string[]) {
  const joined = path.join("/");
  const target = `${BASE}/api/v1/${ALIASES[joined] ?? joined}${request.nextUrl.search}`;

  let body: string | undefined;
  if (request.method !== "GET" && request.method !== "HEAD") {
    body = await request.text();
  }

  try {
    const response = await fetch(target, {
      method: request.method,
      headers: {
        "Content-Type": "application/json",
        // A real deployment replaces this with the verified identity from the
        // auth layer. Approvals are only as trustworthy as this header.
        "X-User": request.headers.get("x-user") ?? "console@cloudwaste.local",
      },
      body: body && body.length > 0 ? body : undefined,
      cache: "no-store",
    });

    const text = await response.text();
    return new NextResponse(text, {
      status: response.status,
      headers: { "Content-Type": "application/json" },
    });
  } catch (cause) {
    return NextResponse.json(
      {
        detail:
          `Cannot reach the CloudWaste API at ${BASE}. ` +
          `Start it with: uvicorn cloudwaste.main:app --reload`,
        cause: String(cause),
      },
      { status: 502 },
    );
  }
}

type Context = { params: Promise<{ path: string[] }> };

export async function GET(request: NextRequest, context: Context) {
  return forward(request, (await context.params).path);
}

export async function POST(request: NextRequest, context: Context) {
  return forward(request, (await context.params).path);
}

export async function PATCH(request: NextRequest, context: Context) {
  return forward(request, (await context.params).path);
}

export async function DELETE(request: NextRequest, context: Context) {
  return forward(request, (await context.params).path);
}
