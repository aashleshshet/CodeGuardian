# Finding-scoped RAG security agent

The local `/workspace` review screen includes a **Security agent** for questions about the selected scanner finding. It retrieves application-owned security guidance, optionally asks the configured model to interpret it alongside bounded evidence, and validates the response before returning it with citations. No repository connection is required; authorized ZIP scans work.

On the on-device stack, generation uses the installed Qwen2.5-Coder model through Ollama. The public checker also offers private browser RAG on Vercel, described below. Vercel never gains access to your Mac or Ollama service.

## Use

1. Open `http://localhost:3000/workspace`, sign in with the local access key, and open a completed scan.
2. Select a finding in **Code review** and open its **Security agent** panel.
3. Ask a question or use an evidence, remediation or test prompt. **Use local model** enables generation; switch it off for retrieved guidance only.
4. Expand **Sources used** to inspect the actual excerpts and their MITRE references. Verify the answer against application context.

Only the last three question/answer pairs are displayed, in component memory. Every question is independently scoped to the current finding; the agent does not infer previous conversational references. Selecting another finding or leaving the page clears the conversation. Neither questions nor answers are saved to reports or database records. An audit event records the finding identity only. Cancel stops waiting in the browser; an already-running upstream model request may finish within its timeout.

## Retrieval and generation

```mermaid
flowchart LR
  Q[Question + owned finding] --> R[Bounded local retrieval]
  K[Reviewed CWE documents] --> R
  R --> G{Relevant grounding?}
  G -->|No| A[Explicit abstention]
  G -->|Yes| M{Model enabled?}
  M -->|No| C[Cited retrieved guidance]
  M -->|Yes| L[Redacted evidence + trusted excerpts to Ollama]
  L --> V[Schema / citation / identifier / claim checks]
  V --> O[AI interpretation + sources + review conditions]
```

The corpus is in `backend/knowledge/guidance.json` and `agent-guidance.json`. The index uses BM25 lexical scores, analyzer CWE priority and topic anchors. It returns at most three documents. This is retrieval-augmented generation over a small reviewed corpus, not an embedding search service or whole-repository reasoning engine. Corpus changes are code-reviewed and versioned with the application; repository comments and documentation cannot add trusted documents.

The endpoint is `POST /scans/{scan_id}/findings/{fingerprint}/agent` with `question` (3–3000 characters) and `use_model` (default false). Existing session, origin/CSRF and ownership checks apply. Generation shares the per-user LLM limit; retrieval has its own bounded request limit. The server obtains the finding and source from the owned scan, never from client-supplied evidence.

The model sees at most a 2400-character source excerpt around the finding, bounded metadata, a redacted question, and retrieved guidance. The whole question/source payload is untrusted. It has no tools, repository-write authority, web access or execution capability. Citations must match retrieved IDs; URLs and excerpts come from the server, not model output. The original evidence classification is preserved. Schema and claim guards reject some observable unsupported assertions, but cannot establish semantic correctness. All model output remains an interpretation requiring review.

Invalid, oversized, failed or unsupported model answers produce an error that offers retrieved guidance as the recovery path. Unknown weaknesses and off-topic questions abstain rather than force unrelated guidance. Secret masking is best effort; novel secret formats can be missed. Never use a generated answer as a security clearance.

## Verification

```sh
pytest backend/tests/test_rag_agent.py backend/tests/test_local_ai.py backend/tests/test_api.py -q
pnpm test:e2e
python scripts/local_setup.py smoke
```

Unit tests cover ranked retrieval, unknown-topic abstention, prompt-boundary/redaction contracts, citation validation, unsupported claims and model failure. Browser tests exercise questions, source expansion and finding changes. The local smoke test uses the owned vulnerable fixture, real isolated scanners and the configured local model, then removes its temporary repository.

## Private RAG on the public website

1. Open `/`, paste a supported source file and choose **Check code**.
2. Select a finding and use its **Security agent**. Retrieved guidance and source excerpts work immediately, without a model or network requests.
3. Optionally expand **Private browser AI** and choose **Download & enable AI**. The pinned Qwen2.5 0.5B model downloads about 300 MB of artifacts from Hugging Face and GitHub. It needs a secure context, WebGPU with `shader-f16`, and roughly 1 GB of available GPU memory. Browser/platform support varies.
4. Once ready, **Use browser AI** enables generation. Answers are interpretations requiring review. Disable it for deterministic guidance. Cancel, unload, or remove cached artifacts from the same panel.

The browser uses the same application-owned CWE corpus, bundled at build time. It uses BM25 scores, CWE priority and relevance gates; unsupported questions abstain. This is a reviewed local knowledge base, not live web search. No source is used to construct network queries. The small model is for short finding-scoped explanations, not comprehensive vulnerability discovery.

`lib/browser-ai.ts` lazily loads WebLLM only after consent. The worker permits only fixed versioned model asset GET requests, omits credentials/referrers, and locks fetch access before any source or question is sent to it. The CSP allows WebAssembly and the model artifact hosts; it does not add a cloud inference endpoint. Model config, tokenizer and WASM have integrity checks; model weights use an immutable repository revision. Model generation has a 90-second deadline; initialization has a 10-minute deadline. Cancellation terminates the worker. New questions reset the model chat context, and only the last three UI turns remain in tab memory. Finding changes clear turns and cancel active generation. Model artifacts alone can persist in browser cache, subject to browser eviction.

Prompts contain a bounded, remasked excerpt and one trusted retrieved citation. The question, finding text and source are untrusted data. Structured output, citation allowlists and claim filters reject malformed answers and some unsupported assertions. Failures visibly fall back to cited guidance. These guards cannot prove the semantic accuracy of a generated explanation. Secret masking is best effort; never paste real credentials.

`pnpm test:browser-analysis` covers offline retrieval, redaction, citation/schema checks, asset URL restrictions and cancellation. Public Playwright checks cover no-download default behavior, citation links, abstention, finding reset, mobile layout and WebGPU fallback. Real GPU/model verification is an optional device-dependent smoke check, separate from deterministic CI tests. The installed WebLLM API is documented by [MLC](https://webllm.mlc.ai/docs/user/advanced_usage.html).

Reproduce the optional real GPU smoke after starting a production build (this downloads the model, uses only the example fixture, and removes its cached model afterward):

```sh
CHECKER_TEST_URL=http://127.0.0.1:3002 node scripts/smoke-browser-ai.mjs --download-model
```

Chromium on macOS may need the script’s Metal flags in automated environments. Failure on a machine without compatible WebGPU does not turn into a cloud-model request; the normal UI offers retrieval instead.
