/**
 * VelourCare Ortho Cloud — Phase 2 End-to-End Security, Multi-Tenant Isolation,
 * Financial Integrity, Scale & Browser Profile-Mixing Verification Suite.
 *
 * Self-contained: spawns server.js on an isolated test port (default 8099,
 * override with TEST_PORT / BASE_URL) with PERSIST_STATE=false so tests run
 * against a clean boot without mutating repo runtime data.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const puppeteer = require('puppeteer-core');

const TEST_PORT = Number(process.env.TEST_PORT || 8099);
const BASE_HOST = '127.0.0.1';
const BASE_URL = process.env.BASE_URL || `http://localhost:${TEST_PORT}`;
const CHROME_PATH = process.env.CHROME_PATH || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const SEED_PASSWORD = process.env.SEED_DEFAULT_PASSWORD || 'VelourSecure2026!#';

function rawRequest(urlPath, method = 'GET', headers = {}, body = null) {
    return new Promise((resolve) => {
        let payload = null;
        if (body !== null && body !== undefined) {
            payload = Buffer.isBuffer(body) ? body : (typeof body === 'string' ? Buffer.from(body) : Buffer.from(JSON.stringify(body)));
        }
        const reqHeaders = {
            'Accept': 'application/json',
            ...(payload && !Buffer.isBuffer(body) && typeof body === 'object' ? { 'Content-Type': 'application/json' } : {}),
            ...(payload ? { 'Content-Length': payload.length } : {}),
            ...headers
        };
        const req = http.request({
            hostname: BASE_HOST,
            port: TEST_PORT,
            path: urlPath,
            method,
            headers: reqHeaders
        }, res => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => {
                const buf = Buffer.concat(chunks);
                const text = buf.toString('utf8');
                let data = null;
                try { data = JSON.parse(text); } catch (e) {}
                resolve({ status: res.statusCode, headers: res.headers, body: text, buffer: buf, data });
            });
        });
        req.on('error', err => resolve({ status: 'ERR', error: err.message, headers: {}, body: '', data: null }));
        if (payload) req.write(payload);
        req.end();
    });
}

function multipartUpload(urlPath, fieldName, filename, fileBytes, contentType, headers = {}) {
    const boundary = '----VelourPhase2Boundary' + Date.now();
    const head = Buffer.from(
        `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="${fieldName}"; filename="${filename}"\r\n` +
        `Content-Type: ${contentType}\r\n\r\n`
    );
    const tail = Buffer.from(`\r\n--${boundary}--\r\n`);
    const body = Buffer.concat([head, Buffer.isBuffer(fileBytes) ? fileBytes : Buffer.from(fileBytes), tail]);
    return rawRequest(urlPath, 'POST', {
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        ...headers
    }, body);
}

function parseSetCookies(setCookieHeader = []) {
    const map = {};
    const list = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
    for (const raw of list) {
        if (!raw) continue;
        const [pair] = raw.split(';');
        const eq = pair.indexOf('=');
        if (eq > 0) {
            map[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
        }
    }
    return map;
}

async function login(username, password = SEED_PASSWORD) {
    const res = await rawRequest('/api/auth/login', 'POST', {}, { username, password });
    const cookies = parseSetCookies(res.headers['set-cookie']);
    const token = res.data?.data?.token || null;
    const user = res.data?.data?.user || null;
    return {
        status: res.status,
        user,
        token,
        cookies,
        bearer: token ? { 'Authorization': `Bearer ${token}` } : {},
        cookieHeader: Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ')
    };
}

async function waitForServer(timeoutMs = 15000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const res = await rawRequest('/api/health', 'GET');
        if (res.status === 200) return true;
        await new Promise(r => setTimeout(r, 250));
    }
    throw new Error(`Test server did not become ready on port ${TEST_PORT}`);
}

async function runSuite() {
    const uploadsDir = path.join(__dirname, '..', 'uploads');
    const uploadsBefore = new Set(fs.existsSync(uploadsDir) ? fs.readdirSync(uploadsDir) : []);
    let serverProc = null;

    if (!process.env.USE_EXISTING_SERVER) {
        serverProc = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
            env: { ...process.env, PORT: String(TEST_PORT), PERSIST_STATE: 'false' },
            stdio: ['ignore', 'pipe', 'pipe']
        });
    }

    const failures = [];
    let passed = 0;
    let total = 0;
    function check(name, cond, detail = '') {
        total++;
        if (cond) {
            passed++;
            console.log(`  PASS: ${name}`);
        } else {
            const msg = `${name}${detail ? ` -> ${detail}` : ''}`;
            failures.push(msg);
            console.error(`  FAIL: ${msg}`);
        }
    }

    try {
        await waitForServer();
        console.log(`\n=== PHASE 2 SECURITY, ISOLATION & E2E VERIFICATION (${BASE_URL}) ===\n`);

        // Authenticate isolated accounts
        const admin = await login('admin');
        const docA = await login('doctor');
        const docB = await login('doctor_b');
        const assocA = await login('doctor_associate');
        const planner = await login('planner');
        const lab = await login('lab');
        const accounts = await login('accounts');
        const unassigned = await login('new_user');

        check('0.1 All test accounts authenticated', !!(admin.token && docA.token && docB.token && assocA.token && planner.token && lab.token && accounts.token && unassigned.token));

        // ------------------------------------------------------------------
        // 1. SECRETS, CORS, HEADERS & BUILD EXPOSURE
        // ------------------------------------------------------------------
        console.log('\n--- 1. SECRETS, CORS, HEADERS & BUILD EXPOSURE ---');
        const indexRes = await rawRequest('/', 'GET', { 'Accept': 'text/html' });
        check('1.1 index.html has no hardcoded password VelourSecure2026!#', !indexRes.body.includes('VelourSecure2026!#'));
        check('1.2 index.html has no #role-switcher or demoProfiles', !indexRes.body.includes('role-switcher') && !indexRes.body.includes('demoProfiles'));
        check('1.3 index.html has no hardcoded 1.20 mm IPR overlay', !indexRes.body.includes('1.20 mm') && !indexRes.body.includes('velourcare-ipr-section'));

        const backdoor = await rawRequest('/api/cases', 'GET', { 'Authorization': 'Bearer velourcare-jwt-bearer-1' });
        check('1.4 Backdoor token velourcare-jwt-bearer-1 rejected (401)', backdoor.status === 401, `got ${backdoor.status}`);

        const corsEvil = await rawRequest('/api/cases', 'GET', { 'Origin': 'https://evil.example', ...docA.bearer });
        check('1.5 Unlisted CORS origin not reflected', corsEvil.headers['access-control-allow-origin'] !== 'https://evil.example', `ACAO=${corsEvil.headers['access-control-allow-origin']}`);

        const csp = indexRes.headers['content-security-policy'] || '';
        const scriptSrcMatch = csp.match(/script-src\s+([^;]+)/i);
        const defaultSrcMatch = csp.match(/default-src\s+([^;]+)/i);
        const scriptPart = (scriptSrcMatch ? scriptSrcMatch[1] : (defaultSrcMatch ? defaultSrcMatch[1] : ''));
        check('1.6 CSP script-src/default-src omits unsafe-inline & unsafe-eval', !!csp && !scriptPart.includes('unsafe-inline') && !scriptPart.includes('unsafe-eval'), `CSP=${csp}`);
        check('1.7 CSP sets frame-ancestors and object-src none', /frame-ancestors\s+'(none|self)'/i.test(csp) && /object-src\s+'none'/i.test(csp), `CSP=${csp}`);

        const health = await rawRequest('/api/health', 'GET');
        check('1.8 /api/health hides memory, uptime, and database counts', health.status === 200 && !health.data?.memory && health.data?.uptime === undefined && !health.data?.database, JSON.stringify(health.data));

        const unauthMatrix = await rawRequest('/api/permission-matrix', 'GET');
        check('1.9 /api/permission-matrix requires auth (401)', unauthMatrix.status === 401, `got ${unauthMatrix.status}`);

        // ------------------------------------------------------------------
        // 2. MULTI-TENANT ISOLATION, NON-/api BYPASS & PROFILE MIXING
        // ------------------------------------------------------------------
        console.log('\n--- 2. MULTI-TENANT ISOLATION, NON-/api BYPASS & PROFILE MIXING ---');
        const bypassPatients = await rawRequest('/patients', 'GET', { 'Accept': 'application/json' });
        const bypassRole = await rawRequest('/users/2/update-role', 'POST', {}, { role: 'super-admin' });
        const bypassConfig = await rawRequest('/admin/portal-config', 'POST', {}, { hacked: true });
        const bypassChangeClient = await rawRequest('/cases/4/change-client', 'PATCH', {}, { client_id: 1 });
        check('2.1 Unauthenticated GET /patients blocked (401/404)', bypassPatients.status === 401 || bypassPatients.status === 404, `got ${bypassPatients.status}`);
        check('2.2 Unauthenticated POST /users/2/update-role blocked (401/404)', bypassRole.status === 401 || bypassRole.status === 404, `got ${bypassRole.status}`);
        check('2.3 Unauthenticated POST /admin/portal-config blocked (401/404)', bypassConfig.status === 401 || bypassConfig.status === 404, `got ${bypassConfig.status}`);
        check('2.4 Unauthenticated PATCH /cases/4/change-client blocked (401/404)', bypassChangeClient.status === 401 || bypassChangeClient.status === 404, `got ${bypassChangeClient.status}`);

        // Cross-tenant Doctor A -> Clinic B (Case #4 / #6, Patient #4, Client #2)
        const docAPatients = await rawRequest('/api/patients', 'GET', docA.bearer);
        const docAPatientNames = (docAPatients.data?.data || []).map(p => p.name);
        check('2.5 GET /api/patients isolates Clinic A from Clinic B', docAPatients.status === 200 && !docAPatientNames.includes('Tariq Mansoor') && !docAPatientNames.includes('Yusuf Al-Hashemi'), `patients=${JSON.stringify(docAPatientNames)}`);

        const checksBola = [
            ['2.6 GET /api/patients/4 (Clinic B)', await rawRequest('/api/patients/4', 'GET', docA.bearer), [403, 404]],
            ['2.7 PUT /api/patients/4 (Clinic B)', await rawRequest('/api/patients/4', 'PUT', docA.bearer, { name: 'Tampered' }), [403, 404]],
            ['2.8 PATCH /api/cases/4/change-client', await rawRequest('/api/cases/4/change-client', 'PATCH', docA.bearer, { client_id: 1 }), [403, 404]],
            ['2.9 PATCH /api/cases/4/status', await rawRequest('/api/cases/4/status', 'PATCH', docA.bearer, { status: 'completed' }), [403, 404]],
            ['2.10 GET /api/cases/4/comments', await rawRequest('/api/cases/4/comments', 'GET', docA.bearer), [403, 404]],
            ['2.11 POST /api/cases/4/comments', await rawRequest('/api/cases/4/comments', 'POST', docA.bearer, { content: 'cross-tenant note' }), [403, 404]],
            ['2.12 GET /api/cases/4/step-files', await rawRequest('/api/cases/4/step-files', 'GET', docA.bearer), [403, 404]],
            ['2.13 GET /api/cases/4/treatment-plans', await rawRequest('/api/cases/4/treatment-plans', 'GET', docA.bearer), [403, 404]],
            ['2.14 GET /api/cases/4/treatment-plans/1/document', await rawRequest('/api/cases/4/treatment-plans/1/document', 'GET', docA.bearer), [403, 404]],
            ['2.15 GET /api/clients/2 (Clinic B)', await rawRequest('/api/clients/2', 'GET', docA.bearer), [403, 404]],
            ['2.16 GET /api/clients/2/billable-preview', await rawRequest('/api/clients/2/billable-preview', 'GET', docA.bearer), [403, 404]],
            ['2.17 GET /simulation/4 as Doctor A', await rawRequest('/simulation/4', 'GET', { ...docA.bearer, 'Accept': 'text/html' }), [401, 403, 404]]
        ];
        for (const [label, res, allowed] of checksBola) {
            check(label, allowed.includes(res.status), `got ${res.status}`);
        }

        // File download isolation: Doctor B uploads valid ZIP to Case #4
        const validZipBytes = Buffer.from([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x41, 0x42, 0x43]);
        const docBUpload = await multipartUpload('/api/cases/4/attachments', 'attachment', 'clinic-b-scan.zip', validZipBytes, 'application/zip', docB.bearer);
        const uploadedUrl = docBUpload.data?.data?.file_url || '';
        const uploadedName = uploadedUrl ? path.basename(uploadedUrl) : '';
        check('2.18 Doctor B can upload valid .zip to own Case #4', docBUpload.status === 200 && !!uploadedName, `status=${docBUpload.status}`);

        if (uploadedName) {
            const docAGetUpload = await rawRequest(`/uploads/${uploadedName}`, 'GET', docA.bearer);
            check('2.19 Doctor A blocked from downloading Clinic B file via /uploads/', docAGetUpload.status === 403 || docAGetUpload.status === 404, `got ${docAGetUpload.status}`);

            const noCaseToken = await rawRequest(`/api/files/signed-download-token?filename=${encodeURIComponent(uploadedName)}`, 'GET', docA.bearer);
            check('2.20 signed-download-token requires case_id (400)', noCaseToken.status === 400, `got ${noCaseToken.status}`);

            const mismatchToken = await rawRequest(`/api/files/signed-download-token?filename=${encodeURIComponent(uploadedName)}&case_id=1`, 'GET', docA.bearer);
            check('2.21 signed-download-token rejects mismatched filename/case_id (403/404)', mismatchToken.status === 403 || mismatchToken.status === 404, `got ${mismatchToken.status}`);

            const docBTokenRes = await rawRequest(`/api/files/signed-download-token?filename=${encodeURIComponent(uploadedName)}&case_id=4`, 'GET', docB.bearer);
            const sigTok = docBTokenRes.data?.token;
            check('2.22 Doctor B can mint signed download token for own case file', docBTokenRes.status === 200 && !!sigTok, `status=${docBTokenRes.status}`);
            if (sigTok) {
                const dl1 = await rawRequest(`/api/files/signed-download?token=${encodeURIComponent(sigTok)}`, 'GET');
                const dl2 = await rawRequest(`/api/files/signed-download?token=${encodeURIComponent(sigTok)}`, 'GET');
                check('2.23 Signed download succeeds once with Content-Disposition: attachment', dl1.status === 200 && /attachment/i.test(dl1.headers['content-disposition'] || ''), `status=${dl1.status}, cd=${dl1.headers['content-disposition']}`);
                check('2.24 Signed download token is single-use (second attempt 403)', dl2.status === 403, `got ${dl2.status}`);
            }
        } else {
            check('2.19-2.24 Skipped file download isolation checks (upload failed)', false);
        }

        // Server-side db.currentUser profile mixing check
        const docA2 = await login('doctor');
        const docB2 = await login('doctor_b');
        await rawRequest('/api/cases', 'GET', docB2.bearer);
        await rawRequest('/api/auth/logout', 'POST', docB2.bearer);
        const docAProfile = await rawRequest('/api/profile', 'GET', docA2.bearer);
        check('2.25 Concurrent sessions never mix profiles or crash on peer logout', docAProfile.status === 200 && docAProfile.data?.data?.id === 2 && docAProfile.data?.data?.username === 'doctor', `status=${docAProfile.status}, id=${docAProfile.data?.data?.id}`);

        // Associate Doctor (see_only_own_uploads)
        await rawRequest('/api/profile', 'PUT', assocA.bearer, { see_only_own_uploads: false, client_id: 2, client: { id: 2 } });
        const assocAfter = await rawRequest('/api/auth/user', 'GET', assocA.bearer);
        check('2.26 Associate cannot self-clear see_only_own_uploads or change clinic via /api/profile', assocAfter.data?.see_only_own_uploads === true && assocAfter.data?.client_id === 1, JSON.stringify({ own: assocAfter.data?.see_only_own_uploads, cid: assocAfter.data?.client_id }));
        const assocEditOther = await rawRequest('/api/cases/1', 'PUT', assocA.bearer, { chief_complaint: 'Unauthorized edit' });
        const assocApproveOther = await rawRequest('/api/cases/1/treatment-plans/1/approve', 'POST', assocA.bearer, {});
        check('2.27 Associate blocked from editing clinic colleague case (403/404)', assocEditOther.status === 403 || assocEditOther.status === 404, `got ${assocEditOther.status}`);
        check('2.28 Associate blocked from approving clinic colleague plan (403/404)', assocApproveOther.status === 403 || assocApproveOther.status === 404, `got ${assocApproveOther.status}`);

        // ------------------------------------------------------------------
        // 3. AUTH, PRIVILEGE ESCALATION, PASSWORD & CSRF HYGIENE
        // ------------------------------------------------------------------
        console.log('\n--- 3. AUTH, PRIVILEGE ESCALATION, PASSWORD & CSRF HYGIENE ---');
        const privEscalations = [
            ['3.1 Doctor blocked from POST /api/users', await rawRequest('/api/users', 'POST', docA.bearer, { username: 'hacker', role: 'super-admin' })],
            ['3.2 Doctor blocked from PUT /api/users/2', await rawRequest('/api/users/2', 'PUT', docA.bearer, { is_super_admin: true, role_slug: 'super-admin' })],
            ['3.3 Doctor blocked from POST /api/users/2/update-role', await rawRequest('/api/users/2/update-role', 'POST', docA.bearer, { role: 'super-admin' })],
            ['3.4 Doctor blocked from DELETE /api/users/1', await rawRequest('/api/users/1', 'DELETE', docA.bearer)],
            ['3.5 Doctor blocked from POST /api/permissions/2/user', await rawRequest('/api/permissions/2/user', 'POST', docA.bearer, { permissions: [1, 2, 12] })],
            ['3.6 Doctor blocked from POST /api/roles', await rawRequest('/api/roles', 'POST', docA.bearer, { name: 'evil-admin' })],
            ['3.7 Doctor blocked from POST /api/admin/portal-config', await rawRequest('/api/admin/portal-config', 'POST', docA.bearer, { clients: [] })]
        ];
        for (const [label, res] of privEscalations) {
            check(label, res.status === 403, `got ${res.status}`);
        }

        const docAPermsRes = await rawRequest('/api/permissions/current-user', 'GET', docA.bearer);
        const flatPerms = Object.values(docAPermsRes.data?.data || {}).flat().map(p => p.name);
        check('3.8 /api/permissions/current-user returns only user role perms (no admin perms)', !flatPerms.includes('manage_users_permissions') && !flatPerms.includes('delete_cases'), `perms=${flatPerms.length}`);

        const adminUsers = await rawRequest('/api/users', 'GET', admin.bearer);
        const docACases = await rawRequest('/api/cases', 'GET', docA.bearer);
        const hasLeakedSecrets = [
            docA.user,
            (await rawRequest('/api/auth/verify', 'GET', docA.bearer)).data?.data?.user,
            (await rawRequest('/api/auth/user', 'GET', docA.bearer)).data,
            ...(adminUsers.data?.data || []),
            ...(docACases.data?.additional?.discussion_members || [])
        ].some(u => u && (u.password_hash !== undefined || u.password_salt !== undefined));
        check('3.9 password_hash and password_salt NEVER serialized in API responses', !hasLeakedSecrets);

        // Password change & session revocation using disposable created planner user
        const createPlanner = await rawRequest('/api/users', 'POST', admin.bearer, {
            first_name: 'Temp', last_name: 'Planner', username: 'temp_planner_p2', email: 'temp_planner_p2@velourcare.com', role: 'planner', password: 'TempUser2026!#'
        });
        check('3.10 Admin POST /api/users with role:planner succeeds (201, no 500 filter crash)', createPlanner.status === 201 || createPlanner.status === 200, `got ${createPlanner.status}`);
        const tempSess1 = await login('temp_planner_p2', 'TempUser2026!#');
        const tempSess2 = await login('temp_planner_p2', 'TempUser2026!#');
        const badPwdNoCur = await rawRequest('/api/auth/user/change-password', 'POST', tempSess1.bearer, { new_password: 'NewStrong2026!#' });
        const badPwdWeak = await rawRequest('/api/auth/user/change-password', 'POST', tempSess1.bearer, { current_password: 'TempUser2026!#', new_password: '123' });
        check('3.11 change-password rejects missing current_password (400/422)', badPwdNoCur.status === 400 || badPwdNoCur.status === 422, `got ${badPwdNoCur.status}`);
        check('3.12 change-password rejects weak password (422)', badPwdWeak.status === 422, `got ${badPwdWeak.status}`);
        const okPwdChange = await rawRequest('/api/auth/user/change-password', 'POST', tempSess1.bearer, { current_password: 'TempUser2026!#', new_password: 'RotatedUser2026!#' });
        const otherSessionAfter = await rawRequest('/api/cases', 'GET', tempSess2.bearer);
        check('3.13 Password change revokes other active sessions (401)', okPwdChange.status === 200 && otherSessionAfter.status === 401, `change=${okPwdChange.status}, peer=${otherSessionAfter.status}`);

        // Cookie CSRF verification
        const csrfMissing = await rawRequest('/api/cases/1/comments', 'POST', { 'Cookie': `laravel_session=${docA.cookies['laravel_session']}; XSRF-TOKEN=${docA.cookies['XSRF-TOKEN']}` }, { content: 'csrf test' });
        const csrfValid = await rawRequest('/api/cases/1/comments', 'POST', {
            'Cookie': `laravel_session=${docA.cookies['laravel_session']}; XSRF-TOKEN=${docA.cookies['XSRF-TOKEN']}`,
            'X-XSRF-TOKEN': decodeURIComponent(docA.cookies['XSRF-TOKEN'] || '')
        }, { content: 'valid csrf comment' });
        check('3.14 Cookie-auth mutating request without X-XSRF-TOKEN rejected (403)', csrfMissing.status === 403, `got ${csrfMissing.status}`);
        check('3.15 Cookie-auth mutating request with valid X-XSRF-TOKEN succeeds (201)', csrfValid.status === 201, `got ${csrfValid.status}`);

        // ------------------------------------------------------------------
        // 4. STORED XSS & FILE UPLOAD HARDENING
        // ------------------------------------------------------------------
        console.log('\n--- 4. STORED XSS & FILE UPLOAD HARDENING ---');
        const xssPayload = '<script>alert(1)</script><img src=x onerror="alert(2)">Clinical note';
        const xssCase = await rawRequest('/api/cases/store-in-pipeline', 'POST', docA.bearer, { patient_name: xssPayload, chief_complaint: xssPayload });
        const xssCaseId = xssCase.data?.data?.id || 1;
        const xssComment = await rawRequest('/api/cases/1/comments', 'POST', docA.bearer, { content: xssPayload });
        const xssPatient = await rawRequest(`/api/patients/${xssCaseId}`, 'PUT', docA.bearer, { name: xssPayload });
        const safeStr = s => typeof s === 'string' && !/<script/i.test(s) && !/onerror\s*=/i.test(s);
        check('4.1 Stored XSS sanitized on case creation', safeStr(xssCase.data?.data?.patient_name) && safeStr(xssCase.data?.data?.chief_complaint));
        check('4.2 Stored XSS sanitized on case comments', safeStr(xssComment.data?.data?.content));
        check('4.3 Stored XSS sanitized on patient update', safeStr(xssPatient.data?.data?.name));

        const beforeFakeZip = new Set(fs.existsSync(uploadsDir) ? fs.readdirSync(uploadsDir) : []);
        const fakeZip = await multipartUpload('/api/cases/1/attachments', 'attachment', 'evil.zip', '<html><script>alert(1)</script></html>', 'application/zip', docA.bearer);
        const unauthUpload = await multipartUpload('/api/cases/1/attachments', 'attachment', 'unauth.zip', validZipBytes, 'application/zip', accounts.bearer);
        const afterFakeZip = new Set(fs.existsSync(uploadsDir) ? fs.readdirSync(uploadsDir) : []);
        const leakedUploadFiles = [...afterFakeZip].filter(f => !beforeFakeZip.has(f));
        check('4.4 Fake .zip with HTML content rejected via magic-byte check (400)', fakeZip.status === 400, `got ${fakeZip.status}`);
        check('4.5 Unauthorized role (accounts) upload rejected before disk write (403)', unauthUpload.status === 403 && leakedUploadFiles.length === 0, `status=${unauthUpload.status}, files=${leakedUploadFiles.length}`);

        const legacyHtml = await rawRequest('/uploads/1794398777831-868713125-malicious-payload.html', 'GET', docA.bearer);
        check('4.6 Legacy malicious HTML payload removed from uploads/ (404)', legacyHtml.status === 404, `got ${legacyHtml.status}`);

        // ------------------------------------------------------------------
        // 5. INVOICING TAMPERING & RACE CONDITIONS
        // ------------------------------------------------------------------
        console.log('\n--- 5. INVOICING TAMPERING & RACE CONDITIONS ---');
        const tamperPrice = await rawRequest('/api/invoices/generate', 'POST', admin.bearer, {
            client_id: 1,
            items: [{ description: 'VelourCare Aligner Step Model 3D Print', quantity: 2, unit_price: 0.01 }],
            discount_percent: 0
        });
        const tamperedItem = tamperPrice.data?.data?.items?.[0];
        check('5.1 Server ignores client unit_price and enforces catalog price (35.00)', tamperPrice.status === 200 && tamperedItem?.unit_price === 35 && tamperedItem?.unit_amount === 35 && tamperedItem?.total_amount === 70 && tamperPrice.data?.data?.subtotal === 70, JSON.stringify(tamperPrice.data?.data));

        const unknownItem = await rawRequest('/api/invoices/generate', 'POST', admin.bearer, {
            client_id: 1, items: [{ description: 'Arbitrary Made Up Item', quantity: 1, unit_price: 1 }]
        });
        const badDiscount = await rawRequest('/api/invoices/generate', 'POST', admin.bearer, {
            client_id: 1, items: [{ description: 'VelourCare Aligner Step Model 3D Print', quantity: 1 }], discount_percent: 150
        });
        const emptyItems = await rawRequest('/api/invoices/generate', 'POST', admin.bearer, { client_id: 1, items: [] });
        check('5.2 Unknown invoice catalog item rejected (400)', unknownItem.status === 400, `got ${unknownItem.status}`);
        check('5.3 Discount > 100% rejected (400)', badDiscount.status === 400, `got ${badDiscount.status}`);
        check('5.4 Empty items array rejected (400)', emptyItems.status === 400, `got ${emptyItems.status}`);

        // Race: double-click approve treatment plan on Case #1
        const invBeforeApprove = (await rawRequest('/api/invoices?per_page=100', 'GET', admin.bearer)).data?.total || 0;
        const [app1, app2] = await Promise.all([
            rawRequest('/api/cases/1/treatment-plans/1/approve', 'POST', docA.bearer, {}),
            rawRequest('/api/cases/1/treatment-plans/1/approve', 'POST', docA.bearer, {})
        ]);
        const appStatuses = [app1.status, app2.status].sort();
        const invAfterApprove = (await rawRequest('/api/invoices?per_page=100', 'GET', admin.bearer)).data?.total || 0;
        check('5.5 Concurrent double-click approve yields 200 + 409 and creates only 1 invoice', appStatuses[0] === 200 && appStatuses[1] === 409 && invAfterApprove === invBeforeApprove + 1, `statuses=${appStatuses}, before=${invBeforeApprove}, after=${invAfterApprove}`);

        // Race: double-click generate invoice with Idempotency-Key
        const idemKey = 'idem-gen-' + Date.now();
        const [gen1, gen2] = await Promise.all([
            rawRequest('/api/invoices/generate', 'POST', { ...accounts.bearer, 'Idempotency-Key': idemKey }, {
                client_id: 1, items: [{ description: 'VelourCare Aligner Step Model 3D Print', quantity: 1 }]
            }),
            rawRequest('/api/invoices/generate', 'POST', { ...accounts.bearer, 'Idempotency-Key': idemKey }, {
                client_id: 1, items: [{ description: 'VelourCare Aligner Step Model 3D Print', quantity: 1 }]
            })
        ]);
        check('5.6 Concurrent generate with Idempotency-Key returns same single invoice', gen1.status === 200 && gen2.status === 200 && gen1.data?.data?.id === gen2.data?.data?.id, `id1=${gen1.data?.data?.id}, id2=${gen2.data?.data?.id}`);

        // Race: double-click record-payment + zero payment check
        const raceInv = gen1.data?.data;
        if (raceInv) {
            const zeroPay = await rawRequest(`/api/invoices/${raceInv.id}/record-payment`, 'POST', accounts.bearer, { amount: 0 });
            const invAfterZero = (await rawRequest(`/api/invoices/${raceInv.id}`, 'GET', accounts.bearer)).data?.data;
            check('5.7 Zero payment amount rejected (400) and status remains unpaid', zeroPay.status === 400 && invAfterZero?.payment_status === 'unpaid', `status=${zeroPay.status}, payStatus=${invAfterZero?.payment_status}`);

            const [pay1, pay2] = await Promise.all([
                rawRequest(`/api/invoices/${raceInv.id}/record-payment`, 'POST', accounts.bearer, { amount: raceInv.total, reference: 'RACE-REF-1' }),
                rawRequest(`/api/invoices/${raceInv.id}/record-payment`, 'POST', accounts.bearer, { amount: raceInv.total, reference: 'RACE-REF-2' })
            ]);
            const payStatuses = [pay1.status, pay2.status].sort();
            const invPaid = (await rawRequest(`/api/invoices/${raceInv.id}`, 'GET', accounts.bearer)).data?.data;
            check('5.8 Concurrent double-click full payment succeeds once (200 + 409) without overpaying', payStatuses[0] === 200 && payStatuses[1] === 409 && invPaid?.amount_paid === raceInv.total && invPaid?.balance_due === 0, `statuses=${payStatuses}, paid=${invPaid?.amount_paid}, total=${raceInv.total}`);
        } else {
            check('5.7-5.8 Skipped payment race checks (invoice creation failed)', false);
        }

        // Invoice mark-paid & cancel lifecycle + RBAC
        const invToMark = (await rawRequest('/api/invoices/generate', 'POST', accounts.bearer, {
            client_id: 1, items: [{ description: 'VelourCare Aligner Step Model 3D Print', quantity: 1 }]
        })).data?.data;
        const invToCancel = (await rawRequest('/api/invoices/generate', 'POST', accounts.bearer, {
            client_id: 1, items: [{ description: 'VelourCare Aligner Step Model 3D Print', quantity: 1 }]
        })).data?.data;
        const docMarkPaid = invToMark ? await rawRequest(`/api/invoices/${invToMark.id}/mark-paid`, 'POST', docA.bearer, {}) : { status: 0 };
        const accMarkPaid = invToMark ? await rawRequest(`/api/invoices/${invToMark.id}/mark-paid`, 'POST', accounts.bearer, {}) : { status: 0 };
        const accCancel = invToCancel ? await rawRequest(`/api/invoices/${invToCancel.id}/cancel`, 'POST', accounts.bearer, {}) : { status: 0 };
        check('5.9 mark-paid & cancel enforce RBAC (Doctor 403) and mutate state cleanly (Accounts 200)', docMarkPaid.status === 403 && accMarkPaid.status === 200 && accMarkPaid.data?.data?.payment_status === 'paid' && accCancel.status === 200 && accCancel.data?.data?.document_status === 'cancelled', `doc=${docMarkPaid.status}, mark=${accMarkPaid.status}, cancel=${accCancel.status}`);

        // ------------------------------------------------------------------
        // 6. WORKFLOW, DATES, PAGINATION & SCALE
        // ------------------------------------------------------------------
        console.log('\n--- 6. WORKFLOW, DATES, PAGINATION & SCALE ---');
        const emptyCase = await rawRequest('/api/cases/store-in-pipeline', 'POST', docA.bearer, {});
        check('6.1 Empty case creation payload rejected (400)', emptyCase.status === 400, `got ${emptyCase.status}`);

        const createdCaseRes = await rawRequest('/api/cases/store-in-pipeline', 'POST', docA.bearer, {
            patient_name: 'Amira Al-Mansoori', patient_age: 29, patient_gender: 'Female', chief_complaint: 'Mild crowding'
        });
        const newCase = createdCaseRes.data?.data;
        const today = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Dubai' }).format(new Date());
        const dateFilterRes = await rawRequest(`/api/cases?period_start=${today}&period_end=${today}`, 'GET', docA.bearer);
        const foundInDateFilter = (dateFilterRes.data?.data || []).some(c => c.id === newCase?.id);
        check('6.2 Newly created case appears in clinic-timezone date filter', createdCaseRes.status === 200 && foundInDateFilter, `id=${newCase?.id}, found=${foundInDateFilter}`);

        if (newCase) {
            const upNew = await multipartUpload(`/api/cases/${newCase.id}/attachments`, 'attachment', 'amira-scan.zip', validZipBytes, 'application/zip', docA.bearer);
            const getNew = await rawRequest(`/api/cases/${newCase.id}`, 'GET', docA.bearer);
            const hasUploadedAttachment = (getNew.data?.data?.attachments || []).some(a => a.name === 'amira-scan.zip');
            check('6.3 Uploaded attachment persists on GET /api/cases/:id', upNew.status === 200 && hasUploadedAttachment, `count=${getNew.data?.data?.attachments?.length}`);

            const postEdit = await rawRequest(`/api/cases/${newCase.id}`, 'POST', docA.bearer, { chief_complaint: 'Updated via POST' });
            const postConflict = await rawRequest(`/api/cases/${newCase.id}`, 'POST', docA.bearer, { version: 1, chief_complaint: 'Stale write' });
            check('6.4 POST /api/cases/:id applies edits and enforces optimistic locking (409)', postEdit.status === 200 && postEdit.data?.data?.chief_complaint === 'Updated via POST' && postConflict.status === 409, `edit=${postEdit.status}, cc=${postEdit.data?.data?.chief_complaint}, conflict=${postConflict.status}`);
        } else {
            check('6.3-6.4 Skipped new case persistence checks', false);
        }

        const pagPatients = await rawRequest('/api/patients?page=1&per_page=2', 'GET', admin.bearer);
        const pagInvoices = await rawRequest('/api/invoices?page=1&per_page=2', 'GET', admin.bearer);
        const pagClients = await rawRequest('/api/clients?page=1&per_page=2', 'GET', admin.bearer);
        const pagUsers = await rawRequest('/api/users?page=1&per_page=2', 'GET', admin.bearer);
        const capCases = await rawRequest('/api/cases?per_page=99999', 'GET', admin.bearer);
        check('6.5 /api/patients respects pagination slice (1..2)', pagPatients.status === 200 && (pagPatients.data?.data || []).length > 0 && (pagPatients.data?.data || []).length <= 2, `status=${pagPatients.status}, len=${pagPatients.data?.data?.length}`);
        check('6.6 /api/invoices respects pagination slice (1..2)', pagInvoices.status === 200 && (pagInvoices.data?.data || []).length > 0 && (pagInvoices.data?.data || []).length <= 2, `status=${pagInvoices.status}, len=${pagInvoices.data?.data?.length}`);
        check('6.7 /api/clients respects pagination slice (1..2)', pagClients.status === 200 && (pagClients.data?.data || []).length > 0 && (pagClients.data?.data || []).length <= 2, `status=${pagClients.status}, len=${pagClients.data?.data?.length}`);
        check('6.8 /api/users respects pagination slice (1..2)', pagUsers.status === 200 && (pagUsers.data?.data || []).length > 0 && (pagUsers.data?.data || []).length <= 2, `status=${pagUsers.status}, len=${pagUsers.data?.data?.length}`);
        check('6.9 /api/cases caps per_page <= 100', (capCases.data?.per_page || 99999) <= 100, `per_page=${capCases.data?.per_page}`);

        // 6.10 SQLite schema pragmas, foreign-key indexes, and cross-reopen persistence
        const { createDatabase } = require('../db');
        const tmpDbPath = path.join(__dirname, '..', 'data', `test_reopen_${Date.now()}.sqlite`);
        let sqliteOk = false;
        let sqliteDetail = '';
        try {
            const db1 = createDatabase(tmpDbPath);
            const fkOn = db1.sqlite.prepare('PRAGMA foreign_keys').get().foreign_keys === 1;
            const idxRows = db1.sqlite.prepare("SELECT name FROM sqlite_master WHERE type='index'").all().map(r => r.name);
            const requiredIdx = ['idx_cases_client_id', 'idx_cases_doctor_id', 'idx_invoices_client_id', 'idx_invoices_case_id', 'idx_invoice_payments_invoice_id'];
            const hasAllIdx = requiredIdx.every(name => idxRows.includes(name));
            db1.sqlite.prepare("INSERT INTO cases (case_id, patient_name, client_id, client_name, created_at, updated_at) VALUES ('PERSIST-01', 'Persistence Check', 1, 'Wright Orthodontics Clinic', '2026-11-19 10:00', '2026-11-19 10:00')").run();
            db1.sqlite.close();

            const db2 = createDatabase(tmpDbPath);
            const persisted = db2.sqlite.prepare("SELECT patient_name FROM cases WHERE case_id = 'PERSIST-01'").get();
            db2.sqlite.close();
            sqliteOk = fkOn && hasAllIdx && persisted && persisted.patient_name === 'Persistence Check';
            sqliteDetail = `fk=${fkOn}, idx=${hasAllIdx}, persisted=${!!persisted}`;
        } finally {
            for (const suffix of ['', '-wal', '-shm']) {
                try { if (fs.existsSync(tmpDbPath + suffix)) fs.unlinkSync(tmpDbPath + suffix); } catch (e) {}
            }
        }
        check('6.10 SQLite enforces foreign keys, indexes, and persists across reopen', sqliteOk, sqliteDetail);

        // ------------------------------------------------------------------
        // 7. LIVE HEADLESS BROWSER E2E (Doctor A -> Logout -> Doctor B)
        // ------------------------------------------------------------------
        console.log('\n--- 7. LIVE HEADLESS BROWSER E2E (DOCTOR A -> LOGOUT -> DOCTOR B) ---');
        const browser = await puppeteer.launch({
            executablePath: CHROME_PATH,
            headless: 'new',
            args: ['--no-sandbox', '--disable-setuid-sandbox', '--window-size=1440,900']
        });
        try {
            const page = await browser.newPage();
            await page.setViewport({ width: 1440, height: 900 });
            const consoleErrors = [];
            const cspErrors = [];
            page.on('console', msg => {
                if (msg.type() === 'error') {
                    const txt = msg.text();
                    consoleErrors.push(txt);
                    if (/Content Security Policy/i.test(txt)) cspErrors.push(txt);
                }
            });

            async function uiLogin(username, password) {
                await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle2' });
                await page.waitForSelector('#username', { timeout: 10000 });
                await page.evaluate(() => {
                    const u = document.querySelector('#username');
                    const p = document.querySelector('#password-input');
                    if (u) u.value = '';
                    if (p) p.value = '';
                });
                await page.type('#username', username);
                await page.type('#password-input', password);
                await Promise.all([
                    page.keyboard.press('Enter'),
                    page.waitForFunction(() => !window.location.pathname.includes('/login'), { timeout: 10000 }).catch(() => {})
                ]);
                await new Promise(r => setTimeout(r, 800));
            }

            // Login as Doctor A
            await uiLogin('doctor', SEED_PASSWORD);
            await page.goto(`${BASE_URL}/cases`, { waitUntil: 'networkidle2' });
            await page.waitForSelector('table tbody tr', { timeout: 10000 }).catch(() => {});
            await new Promise(r => setTimeout(r, 600));
            const docACasesText = await page.evaluate(() => document.body.innerText);
            check('7.1 Browser Doctor A sees Clinic A cases (Fatima Al-Nuaimi) and zero Clinic B cases', docACasesText.includes('Fatima Al-Nuaimi') && !docACasesText.includes('Tariq Mansoor'));

            // Open Case 1 View -> confirm no hardcoded IPR overlay injected
            await page.goto(`${BASE_URL}/cases/1/view`, { waitUntil: 'networkidle2' });
            await new Promise(r => setTimeout(r, 600));
            const hasInjectedIpr = await page.evaluate(() => !!document.getElementById('velourcare-ipr-section'));
            check('7.2 Browser /cases/1/view does NOT inject hardcoded IPR overlay', !hasInjectedIpr);

            // Plant sensitive draft PHI in localStorage, then logout
            await page.evaluate(() => {
                localStorage.setItem('case.draft', JSON.stringify({ patient_name: 'CLINIC_A_DRAFT_PHI' }));
            });
            await page.goto(`${BASE_URL}/logout`, { waitUntil: 'networkidle2' });
            await new Promise(r => setTimeout(r, 1000));
            const storageAfterLogout = await page.evaluate(() => ({
                path: window.location.pathname,
                draft: localStorage.getItem('case.draft'),
                user: localStorage.getItem('auth.user'),
                token: localStorage.getItem('auth.token'),
                perms: localStorage.getItem('auth.permissions')
            }));
            check('7.3 Browser logout purges case.draft, auth.user, auth.token, auth.permissions',
                storageAfterLogout.draft === null && storageAfterLogout.user === null && storageAfterLogout.token === null && storageAfterLogout.perms === null,
                JSON.stringify(storageAfterLogout)
            );

            // Login as Doctor B in the SAME browser page/context
            await uiLogin('doctor_b', SEED_PASSWORD);
            await page.goto(`${BASE_URL}/cases`, { waitUntil: 'networkidle2' });
            await page.waitForSelector('table tbody tr', { timeout: 10000 }).catch(() => {});
            await new Promise(r => setTimeout(r, 600));
            const docBCasesText = await page.evaluate(() => document.body.innerText);
            const storageAfterDocB = await page.evaluate(() => JSON.stringify(localStorage) + JSON.stringify(sessionStorage));
            check('7.4 Browser Doctor B sees Clinic B cases (Tariq Mansoor) and ZERO Clinic A PHI',
                docBCasesText.includes('Tariq Mansoor') &&
                !docBCasesText.includes('Fatima Al-Nuaimi') &&
                !docBCasesText.includes('Marcus Vance') &&
                !docBCasesText.includes('CLINIC_A_DRAFT_PHI') &&
                !storageAfterDocB.includes('CLINIC_A_DRAFT_PHI'),
                `hasTariq=${docBCasesText.includes('Tariq Mansoor')}, hasFatima=${docBCasesText.includes('Fatima Al-Nuaimi')}`
            );

            check('7.5 Zero CSP script violations in browser console', cspErrors.length === 0, cspErrors.join(' | '));
        } finally {
            await browser.close();
        }
    } finally {
        if (serverProc && !serverProc.killed) {
            serverProc.kill('SIGTERM');
        }
        // Clean up any temp files created inside uploads/ during this run
        if (fs.existsSync(uploadsDir)) {
            for (const f of fs.readdirSync(uploadsDir)) {
                if (!uploadsBefore.has(f)) {
                    try { fs.unlinkSync(path.join(uploadsDir, f)); } catch (e) {}
                }
            }
        }
    }

    console.log('\n======================================================================');
    console.log(`PHASE 2 SUITE RESULT: ${passed} / ${total} PASSED, ${failures.length} FAILED`);
    console.log('======================================================================');
    if (failures.length > 0) {
        console.log('Failed checks:');
        failures.forEach(f => console.log('  - ' + f));
    }
    process.exit(failures.length === 0 ? 0 : 1);
}

runSuite().catch(err => {
    console.error('Suite crashed:', err);
    process.exit(1);
});
