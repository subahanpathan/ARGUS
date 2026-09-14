/**
 * One-shot ARGUS browser QA (synthetic demo). Run:
 *   npx --yes playwright@1.49.1 install chromium
 *   node scripts/argus-browser-qa.mjs
 */
import { chromium } from 'playwright';

const BASE = process.env.ARGUS_URL || 'http://localhost:5173';
const results = [];
const log = (ok, name, detail = '') => {
  results.push({ ok, name, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
};

const routes = [
  '/dashboard', '/threats', '/monitoring', '/processes', '/files', '/network',
  '/exposure', '/exposure-window', '/timeline', '/quarantine', '/intelligence',
  '/reports', '/history', '/cyber-cell', '/settings', '/about',
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const consoleErrors = [];
  const pageErrors = [];
  const failedRequests = [];

  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });
  page.on('pageerror', (err) => pageErrors.push(String(err)));
  page.on('response', (res) => {
    if (res.status() >= 400 && res.url().includes('localhost:5173')) {
      failedRequests.push(`${res.status()} ${res.url()}`);
    }
  });

  await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' });
  log(await page.getByTestId('button-demo-mode').isVisible(), 'Login page renders');

  await page.getByTestId('button-demo-mode').click();
  await page.waitForURL('**/dashboard');
  log(page.url().includes('/dashboard'), 'Enter Demo Mode → dashboard');

  const visit = async (href) => {
    const link = page.locator(`a[href="${href}"]`).first();
    await link.click({ force: true });
    await sleep(250);
    const ok = page.url().includes(href.replace(/^\//, '')) || page.url().endsWith(href);
    log(ok, `Route ${href}`, page.url());
  };

  for (const href of routes) {
    await visit(href);
  }

  // Back to dashboard for demo workflow
  await page.locator('a[href="/dashboard"]').first().click({ force: true });
  await sleep(200);

  await page.getByTestId('button-start-demo').click();
  await sleep(400);
  const pauseVisible = await page.getByTestId('button-pause-demo').isVisible().catch(() => false);
  log(pauseVisible, 'Demo running shows Pause');

  await page.getByTestId('button-pause-demo').click();
  await sleep(300);
  const resumeVisible = await page.getByTestId('button-resume-demo').isVisible().catch(() => false);
  const phaseBefore = await page.locator('text=/Sequence \\d+ of 8/').first().textContent().catch(() => '');
  await sleep(2000);
  const phaseAfter = await page.locator('text=/Sequence \\d+ of 8/').first().textContent().catch(() => '');
  log(resumeVisible, 'Pause shows Resume');
  log(phaseBefore === phaseAfter && !!phaseBefore, 'Paused phase does not advance', `${phaseBefore} → ${phaseAfter}`);

  await page.getByTestId('button-resume-demo').click();
  // Let demo complete (~8 * 1.55s from current phase; wait generously)
  await page.getByTestId('text-demo-completed').waitFor({ timeout: 25000 }).catch(() => null);
  const completed = await page.getByTestId('text-demo-completed').isVisible().catch(() => false);
  log(completed, 'Demo reaches Completed');

  // Threats: hashes + investigate
  await page.locator('a[href="/threats"]').first().click({ force: true });
  await sleep(300);
  const hash = await page.getByTestId('text-hash-thr-1').textContent().catch(() => '');
  log(!!hash && hash !== '—', 'Threat hash shown', hash);
  await page.getByTestId('button-investigate-thr-1').click();
  await sleep(400);
  log(page.url().includes('/network') || page.url().includes('/processes') || page.url().includes('/files') || page.url().includes('/timeline'), 'Investigate navigates', page.url());

  // Process tree
  await page.locator('a[href="/processes"]').first().click({ force: true });
  await sleep(300);
  const tree = page.getByTestId('process-tree');
  const treeText = await tree.textContent();
  log(/explorer\.exe/i.test(treeText), 'Tree has explorer.exe');
  log(/outlook\.exe/i.test(treeText), 'Tree has outlook.exe');
  log(/invoice_viewer\.exe/i.test(treeText), 'Tree has invoice_viewer.exe');
  log(/powershell\.exe/i.test(treeText), 'Tree has powershell.exe');
  log(/rundll32\.exe/i.test(treeText), 'Tree has rundll32.exe');
  log(await page.getByTestId('process-contained-banner').isVisible().catch(() => false), 'Process page reflects containment');

  // Quarantine after containment
  await page.locator('a[href="/quarantine"]').first().click({ force: true });
  await sleep(300);
  const q1 = await page.getByTestId('row-quarantine-q-1').isVisible().catch(() => false);
  const q3 = await page.getByTestId('row-quarantine-q-3').isVisible().catch(() => false);
  log(q1 && q3, 'Quarantine inventory includes containment artifacts');

  // Network contained
  await page.locator('a[href="/network"]').first().click({ force: true });
  await sleep(300);
  log(await page.getByTestId('network-contained-banner').isVisible().catch(() => false), 'Network reflects containment');

  // Reports download
  await page.locator('a[href="/reports"]').first().click({ force: true });
  await sleep(300);
  await page.getByTestId('button-generate-report').click();
  await sleep(200);
  const [download] = await Promise.all([
    page.waitForEvent('download', { timeout: 5000 }).catch(() => null),
    page.getByTestId('button-download-report').click(),
  ]);
  log(!!download, 'Download Report triggers local file', download ? await download.suggestedFilename() : 'none');

  // Cyber Cell consents
  await page.locator('a[href="/cyber-cell"]').first().click({ force: true });
  await sleep(300);
  const submit = page.getByTestId('button-submit-cell');
  log(await submit.isDisabled(), 'Submit disabled before consents');
  await page.getByTestId('button-consent-share').click();
  await page.getByTestId('button-consent-synthetic').click();
  log(!(await submit.isDisabled()), 'Submit enabled after both consents');
  await submit.click();
  await sleep(300);
  log(await page.getByText('Submission recorded locally').isVisible().catch(() => false), 'Cyber Cell local-only success');

  // Logout
  await page.getByTestId('button-logout').click();
  await sleep(400);
  log(page.url().includes('/login'), 'Logout returns to login');
  log(await page.getByText('Signed out').isVisible().catch(() => false), 'Logout toast visible on login');

  // Re-enter — incident state preserved (threats/quarantine) but session cleared
  await page.getByTestId('button-demo-mode').click();
  await page.waitForURL('**/dashboard');
  await page.locator('a[href="/quarantine"]').first().click({ force: true });
  await sleep(300);
  const preserved = await page.getByTestId('row-quarantine-q-1').isVisible().catch(() => false);
  log(preserved, 'Incident quarantine state preserved across logout');

  console.log('\n--- Browser diagnostics ---');
  console.log('consoleErrors:', consoleErrors.length ? consoleErrors : 'none');
  console.log('pageErrors:', pageErrors.length ? pageErrors : 'none');
  console.log('failedRequests:', failedRequests.length ? failedRequests : 'none');

  const failed = results.filter((r) => !r.ok);
  console.log(`\nSummary: ${results.length - failed.length}/${results.length} passed`);
  await browser.close();
  process.exit(failed.length ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
