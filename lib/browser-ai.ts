import type { WebWorkerMLCEngine } from "@mlc-ai/web-llm";
import { BROWSER_MODEL_ID, browserModelConfig, MODEL_BASE, MODEL_WASM } from "./browser-ai-config.ts";
export { BROWSER_MODEL_LABEL, BROWSER_MODEL_DOWNLOAD } from "./browser-ai-config.ts";

type Message = { role: "system" | "user"; content: string };
type GPU = { requestAdapter(): Promise<{ features: { has(value: string): boolean } } | null> };
export async function browserAIAvailable(): Promise<boolean> {
  if (typeof navigator === "undefined" || !globalThis.isSecureContext) return false;
  try {
    const adapter = await (navigator as Navigator & { gpu?: GPU }).gpu?.requestAdapter();
    return !!adapter?.features.has("shader-f16");
  } catch { return false; }
}

/** Created on demand. Source and questions are never sent to an HTTP API. */
export class BrowserAI {
  private worker?: Worker;
  private engine?: WebWorkerMLCEngine;
  private active?: (error: Error) => void;
  private epoch = 0;

  private async operation<T>(signal: AbortSignal, timeout: number, work: () => Promise<T>): Promise<T> {
    signal.throwIfAborted();
    if (this.active) throw new Error("Browser AI is busy.");
    let timer: ReturnType<typeof setTimeout>;
    let abort: () => void;
    const cancellation = new Promise<never>((_, reject) => {
      this.active = reject;
      abort = () => reject(new DOMException("Cancelled", "AbortError"));
      signal.addEventListener("abort", abort, { once: true });
      timer = setTimeout(() => reject(new Error("Browser AI timed out. Retrieved guidance is still available.")), timeout);
    });
    try { return await Promise.race([work(), cancellation]); }
    catch (error) { this.epoch++; this.worker?.terminate(); this.worker = undefined; this.engine = undefined; throw error; }
    finally { clearTimeout(timer!); signal.removeEventListener("abort", abort!); this.active = undefined; }
  }

  async load(signal: AbortSignal, onProgress: (progress: number) => void): Promise<void> {
    if (this.engine) return;
    const epoch = this.epoch;
    const assertCurrent = () => {
      signal.throwIfAborted();
      if (epoch !== this.epoch) throw new DOMException("Cancelled", "AbortError");
    };
    await this.operation(signal, 600_000, async () => {
      if (!await browserAIAvailable()) throw new Error("This browser cannot run the local model. Use retrieved guidance instead.");
      assertCurrent();
      const { CreateWebWorkerMLCEngine } = await import("@mlc-ai/web-llm");
      assertCurrent();
      this.worker = new Worker(new URL("./browser-ai.worker.ts", import.meta.url));
      this.worker.onerror = () => this.active?.(new Error("The model worker stopped. Retrieved guidance is still available."));
      const engine = await CreateWebWorkerMLCEngine(this.worker, BROWSER_MODEL_ID, {
        appConfig: browserModelConfig, logLevel: "SILENT",
        initProgressCallback: value => { if (!signal.aborted && epoch === this.epoch) onProgress(Math.max(0, Math.min(1, value.progress))); },
      });
      assertCurrent();
      this.engine = engine;
      this.worker.postMessage({ kind: "codeguardian-lock-network" });
    });
  }

  async generate(messages: Message[], citationIds: string[], signal: AbortSignal): Promise<string> {
    const engine = this.engine;
    if (!engine) throw new Error("Enable the browser model first.");
    if (!citationIds.length || messages.length !== 2 || messages.some(m => m.content.length > 14000)) throw new Error("Insufficient or oversized grounding.");
    return this.operation(signal, 90_000, async () => {
      await engine.resetChat();
      signal.throwIfAborted();
      const response = await engine.chat.completions.create({
        messages, temperature: 0, max_tokens: 600,
        response_format: { type: "json_object", schema: JSON.stringify({
          type: "object", additionalProperties: false,
          properties: {
            answer: { type: "string", minLength: 1, maxLength: 1200 },
            citation_ids: { type: "array", items: { type: "string", enum: citationIds }, minItems: 1, maxItems: citationIds.length },
            conditions_to_verify: { type: "array", items: { type: "string", minLength: 1, maxLength: 280 }, minItems: 1, maxItems: 2 },
          }, required: ["answer", "citation_ids", "conditions_to_verify"],
        }) },
      });
      signal.throwIfAborted();
      await engine.resetChat();
      if (response.choices[0]?.finish_reason !== "stop") throw new Error("The model could not finish a grounded answer.");
      return response.choices[0]?.message.content ?? "";
    });
  }

  dispose(): void {
    this.epoch++;
    this.active?.(new DOMException("Cancelled", "AbortError"));
    this.worker?.terminate(); this.worker = undefined; this.engine = undefined;
  }

  async clearCache(): Promise<void> {
    this.dispose();
    // The SDK deletion helper fetches a missing manifest. Deletion must never
    // start a download, including after a cancelled/partial initialization.
    for (const name of await caches.keys()) {
      if (!name.startsWith("webllm/")) continue;
      const cache = await caches.open(name);
      for (const request of await cache.keys()) {
        if (request.url.startsWith(MODEL_BASE) || request.url === MODEL_WASM) await cache.delete(request);
      }
    }
  }
}
