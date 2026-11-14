import {test} from 'node:test';
import assert from 'node:assert/strict';
import {BrowserAI, browserAIAvailable} from '../lib/browser-ai.ts';
import {isBrowserModelAsset, MODEL_BASE, MODEL_WASM} from '../lib/browser-ai-config.ts';
import {restrictModelNetwork} from '../lib/browser-model-network.ts';

test('model downloads accept only fixed versioned artifacts', () => {
  for (const name of ['mlc-chat-config.json','tokenizer.json','tensor-cache.json','params_shard_0.bin']) assert.ok(isBrowserModelAsset(MODEL_BASE+name));
  assert.ok(isBrowserModelAsset(MODEL_WASM));
  for (const url of [MODEL_BASE+'params_shard_0.bin?code=private',MODEL_BASE+'../other',MODEL_BASE+'tokenizer.json#prompt',MODEL_BASE.replace('/resolve/','/other/'), 'https://example.com/code']) assert.equal(isBrowserModelAsset(url), false);
});

test('model loading guards fetch and native cache downloads, then locks both before inference', async () => {
  const calls=[], writes=[];
  class TestCache {
    async add() {assert.fail('unguarded native cache fetch');}
    async addAll() {assert.fail('unguarded native cache fetch');}
    async put(input,response) {writes.push(String(input)); assert.equal(await response.text(),'model');}
  }
  const scope={Cache:TestCache,fetch:async (input,init)=>{calls.push({url:String(input),...init});return new Response('model');}};
  const lock=restrictModelNetwork(scope), cache=new TestCache();
  await cache.add(MODEL_BASE+'tensor-cache.json');
  await cache.addAll([MODEL_BASE+'params_shard_0.bin',MODEL_WASM]);
  assert.equal(writes.length,3);
  assert.ok(calls.every(call=>call.credentials==='omit'&&call.referrerPolicy==='no-referrer'));
  await assert.rejects(scope.fetch(MODEL_BASE+'tokenizer.json',{method:'POST',body:'private'}),/restricted/);
  await assert.rejects(cache.add('https://example.com/private'),/restricted/);
  lock();
  await assert.rejects(scope.fetch(MODEL_WASM),/restricted/);
  await assert.rejects(cache.add(MODEL_WASM),/restricted/);
  await assert.rejects(cache.addAll([MODEL_WASM]),/restricted/);
  assert.equal(calls.length,3);
});

test('unsupported browser abstains before any runtime download', async () => {
  assert.equal(await browserAIAvailable(), false);
  await assert.rejects(new BrowserAI().load(new AbortController().signal,()=>assert.fail('progress without WebGPU')), /cannot run/);
});

test('cancelled load and generation without loaded model fail safely', async () => {
  const client = new BrowserAI();
  const controller = new AbortController(); controller.abort();
  await assert.rejects(client.load(controller.signal,()=>{}), {name:'AbortError'});
  await assert.rejects(client.generate([],[],new AbortController().signal), /Enable/);
  client.dispose(); client.dispose();
});

test('disposing during capability check prevents a late model download', async () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, 'isSecureContext');
  const gpu = Object.getOwnPropertyDescriptor(navigator, 'gpu');
  let resolve;
  Object.defineProperty(globalThis,'isSecureContext',{value:true,configurable:true});
  Object.defineProperty(navigator,'gpu',{value:{requestAdapter:()=>new Promise(r=>{resolve=r;})},configurable:true});
  try {
    const client = new BrowserAI();
    const pending = client.load(new AbortController().signal,()=>assert.fail('late progress'));
    client.dispose(); resolve({features:new Set(['shader-f16'])});
    await assert.rejects(pending,{name:'AbortError'});
  } finally {
    if(original) Object.defineProperty(globalThis,'isSecureContext',original); else delete globalThis.isSecureContext;
    if(gpu) Object.defineProperty(navigator,'gpu',gpu); else delete navigator.gpu;
  }
});

test('cache removal is scoped and never downloads a missing manifest', async () => {
  const original=globalThis.caches;
  const deleted=[];
  const entries=[MODEL_BASE+'params_shard_0.bin',MODEL_BASE+'tensor-cache.json',MODEL_WASM,'https://example.com/unrelated'];
  globalThis.caches={keys:async()=>['webllm/model','other-app'],open:async name=>{
    assert.equal(name,'webllm/model');
    return {keys:async()=>entries.map(url=>({url})),delete:async request=>{deleted.push(request.url);return true;}};
  }};
  try {await new BrowserAI().clearCache();assert.deepEqual(deleted,entries.slice(0,3));}
  finally {globalThis.caches=original;}
});
