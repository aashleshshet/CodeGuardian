import type { AppConfig } from "@mlc-ai/web-llm";

export const BROWSER_MODEL_ID = "Qwen2.5-0.5B-Instruct-q4f16_1-MLC";
export const BROWSER_MODEL_LABEL = "Qwen2.5 0.5B";
// Verified artifact sizes: 278 MB weights + 7 MB tokenizer + 5.7 MB WASM.
export const BROWSER_MODEL_DOWNLOAD = "about 300 MB";
export const MODEL_BASE = "https://huggingface.co/mlc-ai/Qwen2.5-0.5B-Instruct-q4f16_1-MLC/resolve/32ff081fe7e4dfe4ffb167b94c66fdf11e02b8ad/";
export const MODEL_WASM = "https://raw.githubusercontent.com/mlc-ai/binary-mlc-llm-libs/146ed9cd4b4062e967b017fd2291f7106b50599f/web-llm-models/v0_2_87/base/Qwen2-0.5B-Instruct-q4f16_1_cs1k-webgpu.wasm";
export const browserModelConfig: AppConfig = {
  cacheBackend: "cache",
  model_list: [{
    model_id: BROWSER_MODEL_ID, model: MODEL_BASE, model_lib: MODEL_WASM,
    overrides: { context_window_size: 4096 }, required_features: ["shader-f16"],
    integrity: {
      config: "sha256-VDnAO99O58/g+Kl6ZYgBiwFE3BKAxxu66ihTzbq4dLk=",
      model_lib: "sha256-KiA6qSgARP1LbSecLIvz7xHp5FBDW5c+9JTl1GHk8t0=",
      tokenizer: { "tokenizer.json": "sha256-wDghF+oynN8JcEETL21zWSS2l5JNb2/DlFcT6WzodTk=" },
      onFailure: "error",
    },
  }],
};

/** Only fixed, versioned model files may be requested. No source-dependent URLs. */
export function isBrowserModelAsset(url: string): boolean {
  if (url === MODEL_WASM) return true;
  if (!url.startsWith(MODEL_BASE)) return false;
  return /^(?:mlc-chat-config\.json|tokenizer\.json|tensor-cache\.json|params_shard_\d+\.bin)$/.test(url.slice(MODEL_BASE.length));
}
