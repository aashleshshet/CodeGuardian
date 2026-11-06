export class ApiError extends Error {
  constructor(message: string, readonly status: number) {super(message); this.name = "ApiError";}
}
export async function api<T>(path: string, options: RequestInit = {}, csrf?: string): Promise<T> {
  const response = await fetch(`/api/backend${path}`, {
    ...options,
    headers: {...(options.body instanceof FormData ? {} : {"Content-Type": "application/json"}), ...(csrf ? {"X-CSRF-Token": csrf} : {}), ...options.headers},
    cache: "no-store",
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new ApiError(typeof error.detail === "string" ? error.detail : `Request failed (${response.status}). Please retry.`, response.status);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}
export function download(name: string, content: string, type = "application/json") {
  const url = URL.createObjectURL(new Blob([content], {type}));
  const anchor = document.createElement("a");
  anchor.href = url; anchor.download = name; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
