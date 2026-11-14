import { isBrowserModelAsset } from "./browser-ai-config.ts";

/** Cache.add performs its own native fetch. Cover both it and ordinary fetch. */
export function restrictModelNetwork(scope: {
  fetch: typeof fetch;
  Cache?: { prototype: Pick<Cache, "add" | "addAll" | "put"> };
}): () => void {
  const nativeFetch = scope.fetch.bind(scope);
  let offline = false;
  scope.fetch = (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const method = init?.method ?? (input instanceof Request ? input.method : "GET");
    if (offline || method !== "GET" || init?.body || !isBrowserModelAsset(url)) {
      return Promise.reject(new Error("Browser AI network access is restricted to model loading."));
    }
    return nativeFetch(input, { ...init, credentials: "omit", referrerPolicy: "no-referrer" });
  };
  const prototype = scope.Cache?.prototype;
  if (prototype) {
    prototype.add = async function(input: RequestInfo | URL) {
      const response = await scope.fetch(input);
      if (!response.ok) throw new TypeError("Model asset download failed.");
      await this.put(input, response);
    };
    prototype.addAll = async function(inputs: RequestInfo[]) {
      const responses = await Promise.all(inputs.map(input => scope.fetch(input)));
      if (responses.some(response => !response.ok)) throw new TypeError("Model asset download failed.");
      await Promise.all(inputs.map((input, index) => this.put(input, responses[index])));
    };
  }
  return () => { offline = true; };
}
