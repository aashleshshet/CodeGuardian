import { defineConfig, devices } from "@playwright/test";
export default defineConfig({
  testDir: "./tests/e2e", timeout: 90_000, expect: {timeout:20_000}, fullyParallel:false, workers:1, reporter:"list",
  use:{baseURL:"http://127.0.0.1:3001",trace:"retain-on-failure",screenshot:"only-on-failure"},
  projects:[{name:"chromium",use:{...devices["Desktop Chrome"],viewport:{width:1440,height:1000}}}],
  webServer:[
    {command:".venv/bin/python -m uvicorn tests.e2e_app:app --app-dir backend --port 8001 --host 127.0.0.1 --no-access-log",url:"http://127.0.0.1:8001/health",timeout:30_000,env:{PATH:`${process.cwd()}/.venv/bin:${process.env.PATH}`,ENVIRONMENT:"test",DATABASE_URL:"sqlite:///./.cache/e2e-connected.db",TASKS_EAGER:"true",SCANNER_MODE:"trusted-fixture",ENABLED_SCANNERS:"semgrep,bandit",PUBLIC_URL:"http://127.0.0.1:3001",TOKEN_ENCRYPTION_KEY:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}},
    {command:"pnpm exec next dev --webpack --port 3001 --hostname 127.0.0.1",url:"http://127.0.0.1:3001",timeout:120_000,env:{API_URL:"http://127.0.0.1:8001"}},
  ],
});
