import { chromium } from 'playwright';

const BASE = 'http://localhost:5173';
const browser = await chromium.launch({ headless: true, downloadsPath: 'D:/Mini/scratch/dl' });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
const pageErrors = [];
page.on('pageerror', (e) => pageErrors.push(String(e)));
page.on('console', (m) => { if (m.type() === 'error') pageErrors.push('console: ' + m.text()); });

await page.goto(`${BASE}/login`, { waitUntil: 'domcontentloaded' });
await page.waitForTimeout(1500);
console.log('landed URL:', page.url());
// Fill access key
await page.getByTestId('input-access-key').fill('ARGUS-DEV-2026');
await page.getByTestId('button-activate').click();
await page.waitForTimeout(8000);
console.log('after activate URL:', page.url());
console.log('testids now:', JSON.stringify(await page.evaluate(() => Array.from(document.querySelectorAll('[data-testid]')).map((e) => e.getAttribute('data-testid')).slice(0, 30))));

// If download card appears, click continue to web dashboard
const cont = page.getByTestId('button-open-web-workspace');
if (await cont.isVisible().catch(() => false)) {
  await cont.click();
  await page.waitForTimeout(2500);
  console.log('after continue URL:', page.url());
}

const routes = ['/dashboard', '/threats', '/monitoring', '/processes', '/files', '/network',
  '/exposure', '/exposure-window', '/timeline', '/quarantine', '/intelligence',
  '/reports', '/history', '/cyber-cell', '/settings', '/about', '/auto-remediation', '/detections', '/lab'];

// Collect button click results: for each route, click each button[data-testid] and record error
const report = [];
for (const href of routes) {
  await page.goto(`${BASE}${href}`, { waitUntil: 'domcontentloaded' }).catch(() => {});
  await page.waitForTimeout(1200);
  const btns = await page.evaluate(() => Array.from(document.querySelectorAll('button[data-testid], a[data-testid]')).map((e) => e.getAttribute('data-testid')));
  report.push({ route: href, url: page.url(), btns });
}
for (const r of report) {
  console.log(`ROUTE ${r.route} -> url ${r.url} buttons: ${JSON.stringify(r.btns)}`);
}
console.log('\nPAGE ERRORS:');
console.log(JSON.stringify(pageErrors.slice(0, 20), null, 2));
await browser.close();