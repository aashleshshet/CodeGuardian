import { NextRequest } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const LIMIT = 4_000_000;

async function proxy(request: NextRequest, context: {params: Promise<{path: string[]}>}) {
  const upstream = process.env.API_URL;
  if (!upstream) return Response.json({detail: "The review service is not configured. The operator must connect the backend before sign-in and scanning are available."}, {status: 503});
  const {path} = await context.params;
  if (path.some(segment => segment === ".." || segment.includes("/") || segment.includes("\\"))) return new Response(null, {status: 400});
  const url = new URL(upstream);
  url.pathname = "/" + path.map(encodeURIComponent).join("/");
  url.search = request.nextUrl.search;
  const headers = new Headers();
  for (const key of ["cookie", "content-type", "x-csrf-token", "origin", "x-hub-signature-256", "x-github-delivery", "x-github-event"]) {
    const value = request.headers.get(key); if (value) headers.set(key, value);
  }
  let body: Uint8Array | undefined;
  if (!["GET", "HEAD"].includes(request.method) && request.body) {
    const reader = request.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
    while (true) {
      const {done, value} = await reader.read(); if (done) break;
      size += value.byteLength;
      if (size > LIMIT) {await reader.cancel(); return Response.json({detail: "Upload exceeds the 4 MB web limit. Use the backend API for larger archives."}, {status: 413});}
      chunks.push(value);
    }
    body = new Uint8Array(size); let offset = 0; for (const chunk of chunks) {body.set(chunk, offset); offset += chunk.byteLength;}
  }
  try {
    const result = await fetch(url, {method: request.method, headers, body: body as BodyInit | undefined, redirect: "manual", cache: "no-store", signal: AbortSignal.timeout(55_000)});
    const outgoing = new Headers({"Cache-Control": "no-store"});
    for (const key of ["content-type", "location", "content-disposition", "retry-after", "x-request-id"]) {const value = result.headers.get(key); if (value) outgoing.set(key, value);}
    for (const cookie of result.headers.getSetCookie()) outgoing.append("Set-Cookie", cookie);
    return new Response(result.body, {status: result.status, headers: outgoing});
  } catch { return Response.json({detail: "The API is unavailable. Check your backend deployment and try again."}, {status: 502}); }
}
export { proxy as GET, proxy as POST, proxy as PATCH, proxy as DELETE };
