import { WebWorkerMLCEngineHandler } from "@mlc-ai/web-llm";
import { restrictModelNetwork } from "./browser-model-network";

// Model assets are the only permitted fetches. Lock networking before source or
// questions enter this worker; generation has no tools and cannot fetch URLs.
const lockNetwork = restrictModelNetwork(globalThis);
const handler = new WebWorkerMLCEngineHandler();
handler.engine.setLogLevel("SILENT");
self.onmessage = (event: MessageEvent) => {
  if (event.data?.kind === "codeguardian-lock-network") { lockNetwork(); return; }
  handler.onmessage(event);
};
