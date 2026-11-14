// Optional hardware smoke: explicitly downloads ~300 MB into a test browser profile.
// Uses only the application's synthetic example. Never point this at private source.
import {chromium, expect} from '@playwright/test';
import {mkdir} from 'node:fs/promises';

if (!process.argv.includes('--download-model')) throw new Error('Pass --download-model to consent to the optional model download.');
const url = process.env.CHECKER_TEST_URL || 'http://127.0.0.1:3002';
const browser = await chromium.launchPersistentContext('.cache/browser-ai-smoke-profile', {
  headless: true, viewport: {width:1440,height:1100},
  args: process.platform === 'darwin' ? ['--enable-unsafe-webgpu','--enable-features=WebGPU','--use-angle=metal'] : ['--enable-unsafe-webgpu'],
});
try {
  const page = await browser.newPage();
  const requests = [], errors = [];
  page.on('request', request => requests.push({url:request.url(),body:request.postData() || ''}));
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(url);
  await page.getByRole('button',{name:'Load example',exact:true}).click();
  await page.getByRole('button',{name:'Check code',exact:true}).click();
  const agent = page.getByRole('region',{name:'Private browser security agent'});
  await agent.locator('summary').filter({hasText:'Private browser AI'}).click();
  const enable = agent.getByRole('button',{name:'Download & enable AI',exact:true});
  await expect(enable).toBeVisible({timeout:15000});
  await enable.click();
  await expect(agent.getByText('Model ready',{exact:true})).toBeVisible({timeout:600000});
  const baseline = requests.length;
  const marker = 'browser_only_rag_smoke_marker_241115';
  await agent.getByLabel('Question about this finding').fill(`What should I verify before fixing this ${marker}?`);
  await agent.getByRole('button',{name:'Ask',exact:true}).click();
  await expect(agent.getByText('AI interpretation · review required',{exact:true})).toBeVisible({timeout:120000});
  await agent.locator('summary').filter({hasText:'CWE-79'}).click();
  await expect(agent.getByRole('link',{name:'Read source'})).toHaveAttribute('href','https://cwe.mitre.org/data/definitions/79.html');
  expect(requests.slice(baseline).filter(request => !request.url.startsWith(new URL(url).origin))).toEqual([]);
  expect(requests.some(request => (request.url+request.body).includes(marker))).toBe(false);
  expect(errors).toEqual([]);
  await mkdir('.cache/screenshots',{recursive:true});
  await page.screenshot({path:'.cache/screenshots/browser-ai-smoke.png',fullPage:true});
  await agent.getByRole('button',{name:'Remove cached model',exact:true}).click();
  await expect(agent.getByRole('button',{name:'Download & enable AI',exact:true})).toBeVisible();
  const remaining = await page.evaluate(async () => {
    const keys = [];
    for (const name of await caches.keys()) if (name.startsWith('webllm/')) {
      for (const request of await (await caches.open(name)).keys()) keys.push(request.url);
    }
    return keys;
  });
  expect(remaining).toEqual([]);
  console.log(JSON.stringify({browserGeneration:'passed',citation:'CWE-79',sourceUpload:false,cacheRemoval:'passed',pageErrors:errors.length}));
} finally { await browser.close(); }
