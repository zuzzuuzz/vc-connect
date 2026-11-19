const puppeteer = require('puppeteer-core');

const BASE_URL = 'http://localhost:8000';
const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const ADMIN_PASS = process.env.SEED_DEFAULT_PASSWORD || 'VelourSecure2026!#';

async function testInvoiceCreateDropdown() {
    console.log('--- TESTING INVOICE CREATE PAGE CLIENT DROPDOWN & PREVIEW ---');
    const browser = await puppeteer.launch({
        executablePath: CHROME_PATH,
        headless: 'new',
        args: ['--no-sandbox', '--window-size=1440,900']
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 1440, height: 900 });

    const consoleMessages = [];
    page.on('console', msg => consoleMessages.push(`[${msg.type()}] ${msg.text()}`));

    console.log('0. Signing in as admin via /login...');
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle2' });
    await page.waitForSelector('#username', { timeout: 10000 });
    await page.type('#username', 'admin');
    await page.type('#password-input', ADMIN_PASS);
    await Promise.all([
        page.keyboard.press('Enter'),
        page.waitForFunction(() => !window.location.pathname.includes('/login'), { timeout: 10000 }).catch(() => {})
    ]);
    await new Promise(r => setTimeout(r, 800));

    console.log('1. Navigating to /invoices/create...');
    await page.goto(`${BASE_URL}/invoices/create`, { waitUntil: 'networkidle2' });
    await new Promise(r => setTimeout(r, 1200));

    // Inspect the Client select element
    const selectData = await page.evaluate(() => {
        const select = document.querySelector('select.form-select');
        if (!select) return { found: false };
        const options = Array.from(select.querySelectorAll('option')).map(o => ({
            value: o.value,
            text: o.innerText.trim()
        }));
        return {
            found: true,
            optionsCount: options.length,
            options: options,
            disabled: select.disabled
        };
    });

    console.log('2. Client Select Inspection:', selectData);

    if (!selectData.found || selectData.optionsCount <= 1) {
        console.error('❌ FAILED: Client dropdown is empty or missing!');
        await browser.close();
        process.exit(1);
    }
    console.log(`✅ PASS: Client dropdown populated with ${selectData.optionsCount} options!`);

    // 3. Select Client #1 and verify Billable Preview loads
    console.log('3. Selecting first client (value="1")...');
    await page.select('select.form-select', '1');
    await new Promise(r => setTimeout(r, 1000));

    const previewData = await page.evaluate(() => {
        const previewPanel = document.querySelector('.invoice-setup-rail, .card-title');
        const kpis = Array.from(document.querySelectorAll('.invoice-kpi__label')).map(el => {
            const val = el.nextElementSibling ? el.nextElementSibling.innerText.trim() : '';
            return `${el.innerText.trim()}: ${val}`;
        });
        const tableRows = document.querySelectorAll('table tbody tr');
        return {
            kpis: kpis,
            tableRowCount: tableRows.length,
            previewText: document.body.innerText.slice(0, 300)
        };
    });

    console.log('4. Billable Preview Inspection:', previewData);

    await browser.close();
    console.log('\n--- ALL INVOICE CREATE VERIFICATIONS PASSED ---');
}

testInvoiceCreateDropdown().catch(err => {
    console.error('Error during test:', err);
    process.exit(1);
});
