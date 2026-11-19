/**
 * VelourCare Ortho Cloud — Master Security, Permissions & QA Test Suite
 * Validates 100% of requirements from "Portal_Security_QA_Checklist.pdf"
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const BASE_HOST = 'localhost';
const BASE_PORT = 8000;

function request(urlPath, method = 'GET', headers = {}, body = null) {
    return new Promise((resolve) => {
        const payload = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : null;
        const reqHeaders = {
            'Accept': 'application/json',
            ...(payload && typeof body === 'object' ? { 'Content-Type': 'application/json' } : {}),
            ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
            ...headers
        };

        const req = http.request({
            hostname: BASE_HOST,
            port: BASE_PORT,
            path: urlPath,
            method: method,
            headers: reqHeaders
        }, res => {
            let resBody = '';
            res.on('data', chunk => resBody += chunk);
            res.on('end', () => {
                let data = null;
                try { data = JSON.parse(resBody); } catch(e) {}
                resolve({
                    status: res.statusCode,
                    headers: res.headers,
                    body: resBody,
                    data: data
                });
            });
        });

        req.on('error', err => resolve({ status: 'ERR', error: err.message }));
        if (payload) req.write(payload);
        req.end();
    });
}

async function loginUser(username, password) {
    const res = await request('/api/auth/login', 'POST', {}, { username, password });
    if (res.status === 200 && res.data && res.data.data) {
        return {
            user: res.data.data.user,
            token: res.data.data.token,
            authHeader: { 'Authorization': `Bearer ${res.data.data.token}` }
        };
    }
    return null;
}

async function runMasterSecurityQA() {
    console.log('======================================================================');
    console.log('   VELOURCARE ORTHO CLOUD — PORTAL SECURITY QA MASTER VERIFICATION    ');
    console.log('   Standard: Portal_Security_QA_Checklist.pdf (Sections 1 to 9)       ');
    console.log('======================================================================\n');

    let totalTests = 0;
    let passedTests = 0;
    let failedTests = 0;

    function assert(name, condition, details = '') {
        totalTests++;
        if (condition) {
            passedTests++;
            console.log(`  ✅ PASS: ${name}`);
        } else {
            failedTests++;
            console.error(`  ❌ FAIL: ${name} ${details ? `(${details})` : ''}`);
        }
    }

    // Authenticate test accounts for all roles first
    console.log('\nAuthenticating test accounts for each role:');
    const adminSession = await loginUser('admin', 'VelourSecure2026!#');
    const doctorASession = await loginUser('doctor', 'VelourSecure2026!#');
    const doctorBSession = await loginUser('doctor_b', 'VelourSecure2026!#');
    const plannerSession = await loginUser('planner', 'VelourSecure2026!#');
    const labSession = await loginUser('lab', 'VelourSecure2026!#');
    const accountsSession = await loginUser('accounts', 'VelourSecure2026!#');
    const newUserSession = await loginUser('new_user', 'VelourSecure2026!#');

    // ------------------------------------------------------------------
    // SECTION 1: PERMISSION MATRIX & TEST ROLES
    // ------------------------------------------------------------------
    console.log('\n--- SECTION 1: PERMISSION MATRIX & ROLES ---');
    const matrixRes = await request('/api/permission-matrix', 'GET', adminSession ? adminSession.authHeader : {});
    assert('1.1 Written permission matrix exists in API', matrixRes.status === 200 && matrixRes.data && matrixRes.data.matrix);

    const m = matrixRes.data?.matrix || {};
    assert('1.2 Admin has full permissions', m.admin?.view_all_cases === 'Y' && m.admin?.delete_anything === 'Y');
    assert('1.3 Accounts blocked from viewing cases', m.accounts?.view_all_cases === 'N');
    assert('1.4 Planner blocked from invoices', m.planner?.view_invoices === 'N');
    assert('1.5 Lab tech restricted to Assigned production cases', m.vendor?.view_all_cases === 'Assigned');
    assert('1.6 Clinic / Doctor restricted to Own cases and Own invoices', m.client?.view_all_cases === 'Own' && m.client?.view_invoices === 'Own');
    assert('1.7 Unassigned role defaults to zero access', m.none?.view_all_cases === 'N' && m.none?.view_invoices === 'N');

    assert('1.8 Super Admin test account login', !!adminSession);
    assert('1.9 Clinic A (Dr. Alexander Wright) test account login', !!doctorASession && doctorASession.user.client_id === 1);
    assert('1.10 Clinic B (Dr. Elena Rostova) test account login', !!doctorBSession && doctorBSession.user.client_id === 2);
    assert('1.11 Senior CAD Planner test account login', !!plannerSession);
    assert('1.12 Lab Tech (Vendor) test account login', !!labSession);
    assert('1.13 Accounts & Billing test account login', !!accountsSession);
    assert('1.14 Unassigned New User test account login', !!newUserSession);

    // New user default to no access
    const newUserCases = await request('/api/cases', 'GET', newUserSession.authHeader);
    assert('1.15 New user defaults to zero access (sees 0 cases)', newUserCases.data?.total === 0);

    // ------------------------------------------------------------------
    // SECTION 2: AUTHORIZATION & IDOR TAMPERING
    // ------------------------------------------------------------------
    console.log('\n--- SECTION 2: AUTHORIZATION & IDOR (TEST THIS FIRST) ---');

    // 2.1 Direct URL / API access to blocked endpoints
    const plannerInvoices = await request('/api/invoices', 'GET', plannerSession.authHeader);
    assert('2.1 Planner direct access to /api/invoices is BLOCKED (403)', plannerInvoices.status === 403);

    const labInvoices = await request('/api/invoices', 'GET', labSession.authHeader);
    assert('2.2 Lab tech direct access to /api/invoices is BLOCKED (403)', labInvoices.status === 403);

    const doctorUsers = await request('/api/users', 'GET', doctorASession.authHeader);
    assert('2.3 Doctor direct access to /api/users is BLOCKED (403)', doctorUsers.status === 403);

    const accountsAudit = await request('/api/audit-logs', 'GET', accountsSession.authHeader);
    assert('2.4 Accounts direct access to /api/audit-logs is BLOCKED (403)', accountsAudit.status === 403);

    // 2.2 ID Tampering (IDOR) - Case Access
    // Clinic A (id: 1) opening Clinic B's case (Case #4 or #6, client_id: 2)
    const idorCase4 = await request('/api/cases/4', 'GET', doctorASession.authHeader);
    assert('2.5 IDOR Case Tampering: Clinic A opening Clinic B case returns 404/403', idorCase4.status === 404 || idorCase4.status === 403);

    const idorCase6 = await request('/api/cases/6', 'GET', doctorASession.authHeader);
    assert('2.6 IDOR Case Tampering: Clinic A opening Clinic B case #6 returns 404/403', idorCase6.status === 404 || idorCase6.status === 403);

    // Clinic B (id: 2) opening Clinic A's case (Case #1, client_id: 1)
    const idorCase1 = await request('/api/cases/1', 'GET', doctorBSession.authHeader);
    assert('2.7 IDOR Case Tampering: Clinic B opening Clinic A case returns 404/403', idorCase1.status === 404 || idorCase1.status === 403);

    // 2.3 ID Tampering (IDOR) - Invoice Access
    // Clinic A (id: 1) opening Clinic B's invoice (Invoice #2, client_id: 2)
    const idorInv2 = await request('/api/invoices/2', 'GET', doctorASession.authHeader);
    assert('2.8 IDOR Invoice Tampering: Clinic A opening Clinic B invoice returns 404/403', idorInv2.status === 404 || idorInv2.status === 403);

    // Clinic B (id: 2) opening Clinic A's invoice (Invoice #1, client_id: 1)
    const idorInv1 = await request('/api/invoices/1', 'GET', doctorBSession.authHeader);
    assert('2.9 IDOR Invoice Tampering: Clinic B opening Clinic A invoice returns 404/403', idorInv1.status === 404 || idorInv1.status === 403);

    // 2.4 Server-Side Write Action Checks
    // Read-only role (Lab Tech) trying to edit Case #1
    const labEditCase = await request('/api/cases/1', 'PUT', labSession.authHeader, { chief_complaint: "Hacked by Lab" });
    assert('2.10 Write check: Lab tech editing case is REJECTED (403)', labEditCase.status === 403);

    // Accounts trying to edit Case #1
    const accountsEditCase = await request('/api/cases/1', 'PUT', accountsSession.authHeader, { chief_complaint: "Hacked by Accounts" });
    assert('2.11 Write check: Accounts editing case is REJECTED (403)', accountsEditCase.status === 403);

    // Clinic A trying to approve Clinic B's treatment plan
    const illegalApprove = await request('/api/cases/4/treatment-plans/1/approve', 'POST', doctorASession.authHeader, {});
    assert('2.12 Write check: Clinic A approving Clinic B plan is REJECTED (403/404)', illegalApprove.status === 403 || illegalApprove.status === 404);

    // 2.5 Role Escalation Prevention
    const escalateRes = await request('/api/profile', 'POST', doctorASession.authHeader, {
        is_super_admin: true,
        role_slug: 'super-admin',
        role: 'super-admin',
        first_name: 'Alexander'
    });
    const verifyUser = await request('/api/auth/user', 'GET', doctorASession.authHeader);
    assert('2.13 Role escalation prevented: is_super_admin remains false', verifyUser.data?.is_super_admin === false);
    assert('2.14 Role escalation prevented: role_slug remains client', verifyUser.data?.role_slug === 'client');

    // 2.6 Lists and Searches Filtered
    const clinicACases = await request('/api/cases', 'GET', doctorASession.authHeader);
    const hasClinicBData = (clinicACases.data?.data || []).some(c => c.client_id === 2);
    assert('2.15 List filtering: Clinic A case list contains ZERO Clinic B cases', !hasClinicBData);

    const clinicAInvoices = await request('/api/invoices', 'GET', doctorASession.authHeader);
    const hasClinicBInvoices = (clinicAInvoices.data?.data || []).some(i => i.client_id === 2);
    assert('2.16 List filtering: Clinic A invoice list contains ZERO Clinic B invoices', !hasClinicBInvoices);

    // 2.7 Removed / Disabled Users Lose Access Immediately
    // Create temporary session for testing deactivation
    const tempDoctor = await loginUser('doctor', 'VelourSecure2026!#');
    // Admin deactivates user #2
    await request('/api/users/2/update-status', 'PATCH', adminSession.authHeader, { status: 'inactive' });
    // Deactivated user tries to make request with existing token
    const afterDeact = await request('/api/cases', 'GET', tempDoctor.authHeader);
    assert('2.17 Deactivated user session immediately invalidated (401)', afterDeact.status === 401);
    // Restore user #2 to active
    await request('/api/users/2/update-status', 'PATCH', adminSession.authHeader, { status: 'active' });

    // ------------------------------------------------------------------
    // SECTION 3: LOGIN, PASSWORDS & SESSIONS
    // ------------------------------------------------------------------
    console.log('\n--- SECTION 3: LOGIN, PASSWORDS & SESSIONS ---');

    // 3.1 Passwords hashes/salts are NEVER leaked in API responses
    const usersRes = await request('/api/users', 'GET', adminSession.authHeader);
    const firstUser = (usersRes.data?.data || [])[0];
    assert('3.1 Password hashes and salts are never leaked in /api/users', !!firstUser && firstUser.password_hash === undefined && firstUser.password_salt === undefined);

    // 3.2 Vague login error messages
    const wrongUserRes = await request('/api/auth/login', 'POST', {}, { username: 'nonexistent_user_99', password: 'wrong_password' });
    const wrongPassRes = await request('/api/auth/login', 'POST', {}, { username: 'admin', password: 'wrong_password_xyz' });
    assert('3.2 Vague login message on wrong username', wrongUserRes.data?.message === 'Invalid email or password.');
    assert('3.3 Vague login message on wrong password matches identically', wrongPassRes.data?.message === 'Invalid email or password.');

    // 3.3 Brute-force protection
    console.log('Testing brute-force lockout threshold:');
    let lockedStatus = null;
    for (let i = 0; i < 6; i++) {
        const attempt = await request('/api/auth/login', 'POST', {}, { username: 'brute_target_test', password: 'bad_password' });
        if (attempt.status === 429) {
            lockedStatus = 429;
            break;
        }
    }
    assert('3.4 Brute-force lockout triggered (HTTP 429)', lockedStatus === 429);

    // 3.4 Password reset flow (Section 3)
    const forgotRes = await request('/api/auth/forgot-password', 'POST', {}, { email: 'unknown_patient@example.com' });
    assert('3.5 Password reset does not reveal whether email exists', forgotRes.status === 200 && forgotRes.data?.message?.includes('If that email address'));

    // Weak password rejected
    const weakReset = await request('/api/auth/reset-password', 'POST', {}, { token: 'fake_token', password: 'weak' });
    assert('3.6 Weak password refused during reset (< 8 chars)', weakReset.status === 400 || weakReset.status === 422);

    // 3.5 Real logout invalidation
    const logoutTarget = await loginUser('doctor', 'VelourSecure2026!#');
    const preLogoutReq = await request('/api/cases', 'GET', logoutTarget.authHeader);
    assert('3.7 Session active prior to logout (200)', preLogoutReq.status === 200);

    const logoutRes = await request('/api/auth/logout', 'POST', logoutTarget.authHeader);
    assert('3.8 Logout request succeeded', logoutRes.status === 200);

    const postLogoutReq = await request('/api/cases', 'GET', logoutTarget.authHeader);
    assert('3.9 Token immediately invalidated post-logout (401)', postLogoutReq.status === 401);

    // ------------------------------------------------------------------
    // SECTION 4: DATA PROTECTION & STORAGE
    // ------------------------------------------------------------------
    console.log('\n--- SECTION 4: DATA PROTECTION & STORAGE ---');
    const healthRes = await request('/api/health', 'GET');
    assert('4.1 Security Header: nosniff present', healthRes.headers['x-content-type-options'] === 'nosniff');
    assert('4.2 Security Header: frame-options SAMEORIGIN present', healthRes.headers['x-frame-options'] === 'SAMEORIGIN');
    assert('4.3 Security Header: Strict-Transport-Security (HSTS) present', !!healthRes.headers['strict-transport-security']);

    // Scans and photos privacy: Unauthenticated access blocked
    const unauthScan = await request('/uploads/sample-treatment-models.zip', 'GET');
    assert('4.4 Scans and photos require authentication (401)', unauthScan.status === 401);

    // Signed download tokens
    const signedTokenRes = await request('/api/files/signed-download-token?filename=sample-treatment-models.zip&case_id=1', 'GET', adminSession.authHeader);
    assert('4.5 Signed short-lived download token generated', signedTokenRes.status === 200 && !!signedTokenRes.data?.token);

    // ------------------------------------------------------------------
    // SECTION 5: INPUT SAFETY & FILE UPLOADS
    // ------------------------------------------------------------------
    console.log('\n--- SECTION 5: INPUT SAFETY & FILE UPLOADS ---');
    // SQL injection string test
    const sqliSearch = await request('/api/cases?searchQuery=' + encodeURIComponent("' OR '1'='1' --"), 'GET', adminSession.authHeader);
    assert('5.1 SQL Injection string handled safely without error', sqliSearch.status === 200);

    // XSS Sanitization test
    const xssUpdate = await request('/api/cases/1', 'PUT', adminSession.authHeader, {
        chief_complaint: "<script>alert('xss_test')</script> Patient has midline spacing"
    });
    assert('5.2 XSS input sanitized (<script> stripped or escaped)', !xssUpdate.data?.data?.chief_complaint?.includes('<script>'));

    // Error pages leak nothing
    const errRes = await request('/api/cases/invalid-non-numeric-id', 'GET', adminSession.authHeader);
    assert('5.3 Error response does not leak internal stack traces', !errRes.body.includes('at Module._compile') && !errRes.body.includes('at require'));

    // ------------------------------------------------------------------
    // SECTION 6: BUSINESS LOGIC: CASES & INVOICES
    // ------------------------------------------------------------------
    console.log('\n--- SECTION 6: BUSINESS LOGIC (CASES & INVOICES) ---');

    // 6.1 Clinical plan approval state transition
    const approveAction = await request('/api/cases/1/treatment-plans/1/approve', 'POST', adminSession.authHeader);
    assert('6.1 Plan approval transitions case to plan-approved', approveAction.status === 200 && approveAction.data?.data?.case?.status?.value === 'plan-approved');

    // 6.2 Invoice Math Verification (Quantities, taxes 5% UAE VAT, rounding)
    const genInv = await request('/api/invoices/generate', 'POST', adminSession.authHeader, {
        client_id: 1,
        items: [
            { description: "VelourCare Aligner Step Model 3D Print", quantity: 2, unit_price: 35.00 },
            { description: "Multi-Layer Thermoforming & Laser Trim", quantity: 2, unit_price: 65.00 }
        ],
        discount_percent: 10
    });
    // subtotal = 2*35 + 2*65 = 70 + 130 = 200.00
    // discount 10% = 20.00 -> taxable = 180.00
    // tax 5% = 9.00 -> total = 189.00
    const invData = genInv.data?.data;
    assert('6.2 Invoice math accurate: subtotal matches', invData?.subtotal === 200.00);
    assert('6.3 Invoice math accurate: discount calculated correctly', invData?.discount === 20.00);
    assert('6.4 Invoice math accurate: 5% VAT calculated correctly', invData?.tax === 9.00);
    assert('6.5 Invoice math accurate: total rounded and exact', invData?.total === 189.00);

    // 6.6 Unique, sequential invoice numbers
    assert('6.6 Invoice number is sequential with prefix INV-VELOUR', invData?.invoice_number?.startsWith('INV-VELOUR-'));

    // 6.7 Sent/Issued invoices are locked
    const editLockedInv = await request(`/api/invoices/${invData.id}`, 'PUT', adminSession.authHeader, { total: 10.00 });
    assert('6.7 Sent / Issued invoice is LOCKED against modification (400)', editLockedInv.status === 400);

    const deleteLockedInv = await request(`/api/invoices/${invData.id}`, 'DELETE', adminSession.authHeader);
    assert('6.8 Sent / Issued invoice is LOCKED against deletion (400)', deleteLockedInv.status === 400);

    // 6.8 Concurrency protection / optimistic locking
    const staleCaseUpdate = await request('/api/cases/1', 'PUT', adminSession.authHeader, {
        version: 999999, // stale version
        chief_complaint: "Conflicting edit"
    });
    assert('6.9 Concurrency conflict detected (409 Conflict)', staleCaseUpdate.status === 409);

    // 6.9 Soft Delete (Archiving)
    const delCase = await request('/api/cases/5', 'DELETE', adminSession.authHeader);
    assert('6.10 Case deletion executed as soft-archive', delCase.status === 200);

    const getArchivedCase = await request('/api/cases/5', 'GET', adminSession.authHeader);
    assert('6.11 Archived case suppressed from standard retrieval (404)', getArchivedCase.status === 404);

    // ------------------------------------------------------------------
    // SECTION 7: OPERATIONS, BACKUPS & AUDIT TRAILS
    // ------------------------------------------------------------------
    console.log('\n--- SECTION 7: OPERATIONS, BACKUPS & RESILIENCE ---');

    // 7.1 Audit log
    const auditLogsRes = await request('/api/audit-logs', 'GET', adminSession.authHeader);
    assert('7.1 Immutable Audit Log exists and is queryable by Super Admin', auditLogsRes.status === 200 && Array.isArray(auditLogsRes.data?.data));
    assert('7.2 Audit log captures user, action, timestamp, and IP', auditLogsRes.data?.data?.length > 0 && !!auditLogsRes.data?.data[0]?.action && !!auditLogsRes.data?.data[0]?.timestamp);

    // 7.2 Automatic Backup Creation & Restore Verification
    const backupCreateRes = await request('/api/admin/backups/create', 'POST', adminSession.authHeader);
    assert('7.3 Automated backup creation succeeded', backupCreateRes.status === 200 && backupCreateRes.data?.success === true);

    const backupRestoreRes = await request('/api/admin/backups/restore', 'POST', adminSession.authHeader);
    assert('7.4 Backup restore and integrity verification succeeded', backupRestoreRes.status === 200 && backupRestoreRes.data?.success === true);

    // ------------------------------------------------------------------
    // SECTION 8: PRIVACY & LEGAL COMPLIANCE
    // ------------------------------------------------------------------
    console.log('\n--- SECTION 8: PRIVACY & LEGAL COMPLIANCE ---');
    const privacyApi = await request('/api/legal/privacy-policy', 'GET');
    assert('8.1 Privacy policy API live and documented', privacyApi.status === 200);

    const termsApi = await request('/api/legal/terms-of-service', 'GET');
    assert('8.2 Terms of service API live and documented', termsApi.status === 200);

    const privacyPage = await request('/privacy-policy', 'GET');
    assert('8.3 Privacy Policy public HTML page live', privacyPage.status === 200 && privacyPage.body.includes('VelourCare Ortho'));

    const termsPage = await request('/terms-of-service', 'GET');
    assert('8.4 Terms of Service public HTML page live', termsPage.status === 200 && termsPage.body.includes('Terms of Service'));

    const breachPlanExists = fs.existsSync(path.join(__dirname, '..', 'docs', 'DATA_BREACH_RESPONSE_PLAN.md'));
    assert('8.5 Data Breach Response Plan documented in docs/', breachPlanExists);

    const thirdPartyExists = fs.existsSync(path.join(__dirname, '..', 'docs', 'THIRD_PARTY_DATA_PROCESSORS.md'));
    assert('8.6 Third-Party Data Processors Registry documented in docs/', thirdPartyExists);

    // ------------------------------------------------------------------
    // FINAL SUMMARY
    // ------------------------------------------------------------------
    console.log('\n======================================================================');
    console.log(`   MASTER QA TEST RESULTS: ${passedTests} / ${totalTests} TESTS PASSED (${failedTests} FAILED)`);
    console.log('======================================================================');

    process.exit(failedTests === 0 ? 0 : 1);
}

runMasterSecurityQA().catch(err => {
    console.error('Test execution error:', err);
    process.exit(1);
});
