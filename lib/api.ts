export async function api<T>(path: string, options: RequestInit = {}, csrf?: string): Promise<T> {
  const response = await fetch(`/api/backend${path}`, { ...options, headers: { ...(options.body instanceof FormData ? {} : {"Content-Type": "application/json"}), ...(csrf ? {"X-CSRF-Token": csrf} : {}), ...options.headers }, cache: "no-store" });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(typeof error.detail === "string" ? error.detail : `Request failed (${response.status}). Try again.`);
  }
  return response.json() as Promise<T>;
}

export function download(name: string, content: string, type = "application/json") {
  const url = URL.createObjectURL(new Blob([content], {type}));
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
