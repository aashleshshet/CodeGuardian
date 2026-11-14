import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";

test("public code checks need no account and keep source on the device", async ({page}) => {
  const requests: {url: string; body: string}[] = [];
  page.on("request", request => requests.push({url: request.url(), body: request.postData() || ""}));
  await page.goto("/");
  await expect(page.getByRole("link", {name: "Continue with GitHub"})).toHaveCount(0);
  await expect(page.getByLabel("Local access key", {exact: true})).toHaveCount(0);
  const source = page.getByLabel("Source code", {exact: true});
  const check = page.getByRole("button", {name: "Check code", exact: true});
  await expect(check).toBeDisabled();
  await page.getByRole("button", {name: "Load example", exact: true}).click();
  await expect(source).not.toHaveValue("");
  await expect(page.getByTestId("checker-results")).toHaveCount(0);
  await check.click();
  const results = page.getByTestId("checker-results");
  await expect(results).toBeVisible();
  await expect(page.getByRole("heading", {name: "Review findings", exact: true})).toBeVisible();
  await expect(page.locator(".monaco-editor").first()).toBeVisible();
  await expect(results).toContainText("Syntax parsed · single-file analysis");
  await expect(page.getByLabel("Evidence trace", {exact:true})).toBeVisible();
  await page.getByRole("button", {name:/Show source at line/}).first().click();
  await expect(results.getByRole("button").first()).toBeVisible();
  const filters = page.getByRole("group", {name: "Filter severity", exact: true});
  await filters.getByRole("button", {name: "High severity", exact: true}).click();
  await expect(filters.getByRole("button", {name: "High severity", exact: true})).toHaveAttribute("aria-pressed", "true");
  await filters.getByRole("button", {name: "Low severity", exact: true}).click();
  await expect(results).toContainText("No findings at this severity.");
  await filters.getByRole("button", {name: "All severities", exact: true}).click();
  await expect(results).not.toContainText("No findings at this severity.");
  await page.evaluate(()=>window.scrollTo(0,0));
  await page.screenshot({path: ".cache/screenshots/checker-results-dark.png", fullPage: true, animations: "disabled"});

  await page.getByRole("button", {name:"Review proposed change", exact:true}).click();
  const exportPatch=page.getByRole("button", {name:"Export reviewed patch", exact:true});
  await expect(exportPatch).toBeDisabled();
  await page.getByLabel("I reviewed this change and will test it before use.").check();
  await expect(exportPatch).toBeEnabled();
  const patchDownload=page.waitForEvent("download");
  await exportPatch.click();
  expect((await patchDownload).suggestedFilename()).toBe("codeguardian.patch");
  const marker = "browser_only_source_marker_241113";
  await page.getByRole("button", {name:"Edit code", exact:true}).click();
  await source.fill(`const ${marker} = 42;`);
  await expect(results).toHaveCount(0);
  await check.click();
  await expect(results).toBeVisible();
  expect(requests.filter(request => new URL(request.url).pathname.startsWith("/api/"))).toEqual([]);
  expect(requests.some(request => request.url.includes(marker) || request.body.includes(marker))).toBe(false);
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain(marker);
  await page.getByRole("button", {name: "Clear code", exact: true}).click();
  await expect(source).toHaveValue("");
  await expect(check).toBeDisabled();
  await expect(results).toHaveCount(0);
});

test("data-flow checks expose evidence and syntax failures stay partial", async ({page}) => {
  await page.goto("/");
  const input=page.getByLabel("Source code",{exact:true});
  await input.fill('import {exec as run} from "node:child_process";\nconst cmd = "cat " + req.query.file;\nrun(cmd);');
  await page.getByRole("button",{name:"Check code",exact:true}).click();
  await expect(page.getByTestId("checker-results")).toContainText("CWE-78");
  await expect(page.getByTestId("checker-results")).toContainText("Input-to-operation flow detected");
  await expect(page.getByLabel("Evidence trace",{exact:true})).toContainText("L2");
  await expect(page.locator(".monaco-editor").first()).toBeVisible();
  await page.getByRole("button",{name:/Show source at line/}).first().scrollIntoViewIfNeeded();
  await page.evaluate(()=>window.scrollTo(0,0));
  await page.screenshot({path:".cache/screenshots/checker-flow.png",fullPage:true,animations:"disabled"});
  await page.setViewportSize({width:390,height:844});
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);
  await page.screenshot({path:".cache/screenshots/checker-flow-mobile.png",fullPage:true,animations:"disabled"});
  await page.getByRole("button",{name:"Edit code",exact:true}).click();
  await input.fill('const input = ; function (');
  await page.getByRole("button",{name:"Check code",exact:true}).click();
  await expect(page.getByTestId("checker-results")).toContainText("Partial analysis — review required");
  await expect(page.getByTestId("checker-results")).not.toContainText("Syntax parsed");
});

test("source-file checks export redacted findings and reject oversized uploads", async ({page}) => {
  await page.goto("/");
  const secret = "synthetic_credential_never_publish_241113";
  const file = page.getByLabel("Upload source file", {exact: true});
  await file.setInputFiles({name: "review.py", mimeType: "text/plain", buffer: Buffer.from(`api_key = "${secret}"\neval(user_input)\n`)});
  await expect(page.getByLabel("Language", {exact: true})).toHaveValue("python");
  await page.getByRole("button", {name: "Check code", exact: true}).click();
  await expect(page.getByTestId("checker-results")).toBeVisible();
  const downloaded = page.waitForEvent("download");
  await page.getByRole("button", {name: "Export report", exact: true}).click();
  const download = await downloaded;
  expect(download.suggestedFilename()).toMatch(/\.json$/);
  const report = await readFile((await download.path())!, "utf8");
  expect(report).not.toContain(secret);
  expect(JSON.parse(report)).toBeTruthy();
  await expect(page.getByTestId("checker-results")).not.toContainText(secret);

  await file.setInputFiles({name: "oversized.py", mimeType: "text/plain", buffer: Buffer.alloc(200 * 1024 + 1, "a")});
  await expect(page.getByRole("alert").filter({hasText:"too large"})).toBeVisible();
  await expect(page.getByLabel("Source code", {exact: true})).not.toHaveValue("a".repeat(200 * 1024 + 1));
});

test("checker adapts across themes and viewport sizes", async ({page}) => {
  await page.goto("/");
  await page.emulateMedia({reducedMotion: "reduce"});
  await expect(page.getByRole("button", {name: "Check code", exact: true})).toBeVisible();
  await page.screenshot({path: ".cache/screenshots/checker-desktop.png", fullPage: true, animations: "disabled"});
  await page.getByRole("button", {name: "Switch to light theme", exact: true}).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(page.getByRole("button", {name: "Switch to light theme", exact: true})).toHaveAttribute("aria-pressed", "true");
  await page.screenshot({path: ".cache/screenshots/checker-light.png", fullPage: true, animations: "disabled"});
  await page.getByRole("button", {name: "Switch to dark theme", exact: true}).click();
  const navigation=page.getByRole("navigation", {name:"Main navigation"});
  await navigation.getByRole("link", {name:"How it works", exact:true}).click();
  await expect(navigation.getByRole("link", {name:"How it works", exact:true})).toHaveAttribute("aria-current", "location");
  await navigation.getByRole("link", {name:"Code checker", exact:true}).click();
  await expect(navigation.getByRole("link", {name:"Code checker", exact:true})).toHaveAttribute("aria-current", "location");
  await page.evaluate(()=>window.scrollTo(0,0));
  for (const [width, height, name] of [[768, 1024, "tablet"], [390, 844, "mobile"]] as const) {
    await page.setViewportSize({width, height});
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await expect(page.getByRole("button", {name: "Check code", exact: true})).toBeVisible();
    await page.screenshot({path: `.cache/screenshots/checker-${name}.png`, fullPage: true, animations: "disabled"});
  }
});
