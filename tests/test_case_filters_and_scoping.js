const http = require('http');

function request(options, data) {
    return new Promise((resolve, reject) => {
        const req = http.request(options, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                let parsed = body;
                try { parsed = JSON.parse(body); } catch(e) {}
                resolve({ status: res.statusCode, headers: res.headers, body: parsed });
            });
        });
        req.on('error', reject);
        if (data) {
            req.write(typeof data === 'string' ? data : JSON.stringify(data));
        }
        req.end();
    });
}

async function login(username, password) {
    const res = await request({
        hostname: 'localhost',
        port: 8000,
        path: '/api/auth/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    }, { username, password });
    return (res.body.data && res.body.data.token) || res.body.token;
}

async function runTests() {
    console.log("=== TESTING CASE FILTERS & PERSONAL UPLOAD SCOPING ===");

    // 1. Log in as Dr. Alexander Wright (Clinic A Head Doctor)
    const tokenWright = await login('doctor', 'VelourSecure2026!#');
    // 2. Log in as Dr. Emily Watson (Clinic A Associate with see_only_own_uploads: true)
    const tokenWatson = await login('doctor_associate', 'VelourSecure2026!#');
    // 3. Log in as Super Admin
    const tokenAdmin = await login('admin', 'VelourSecure2026!#');

    console.log("\n--- TEST 1: Clinic A Head Doctor (sees all Clinic A cases) ---");
    let res = await request({
        hostname: 'localhost',
        port: 8000,
        path: '/api/cases',
        method: 'GET',
        headers: { 'Authorization': `Bearer ${tokenWright}` }
    });
    console.log(`Total accessible cases for Clinic A: ${res.body.total}`);
    console.log(`Patient names:`, res.body.data.map(c => `${c.case_id} (${c.patient_name}) by ${c.doctor_name}`));
    if (res.body.total === 4) {
        console.log("✅ PASS: Dr. Wright sees all 4 cases of Clinic 1");
    } else {
        console.error("❌ FAIL: Expected 4 cases for Clinic 1");
    }

    console.log("\n--- TEST 2: Status Capsule Counts ---");
    const capsules = res.body.additional.status_capsule_counts;
    console.log("Capsules:", capsules.map(c => `${c.label}: ${c.count}`));
    const allCount = capsules.find(c => c.value === null).count;
    if (allCount === 4) {
        console.log("✅ PASS: Status capsule 'All Cases' matches base accessible cases (4)");
    } else {
        console.error("❌ FAIL: Status capsule count mismatch");
    }

    console.log("\n--- TEST 3: Status Filter (Review Treatment Plan) ---");
    res = await request({
        hostname: 'localhost',
        port: 8000,
        path: '/api/cases?filters[status]=review-treatment-plan',
        method: 'GET',
        headers: { 'Authorization': `Bearer ${tokenWright}` }
    });
    console.log(`Filtered cases count: ${res.body.total}`);
    const filteredCapsules = res.body.additional.status_capsule_counts;
    const allCountStill4 = filteredCapsules.find(c => c.value === null).count === 4;
    if (res.body.total === 1 && res.body.data[0].case_id === 'VELOUR-0001' && allCountStill4) {
        console.log("✅ PASS: Status filter correctly returns 1 case AND status capsules remain accurate (not wiped to 0)");
    } else {
        console.error("❌ FAIL: Status filter or capsule count preservation failed");
    }

    console.log("\n--- TEST 4: Search All Filter (search[all]=fatima) ---");
    res = await request({
        hostname: 'localhost',
        port: 8000,
        path: '/api/cases?search[all]=fatima',
        method: 'GET',
        headers: { 'Authorization': `Bearer ${tokenWright}` }
    });
    if (res.body.total === 1 && res.body.data[0].patient_name === 'Fatima Al-Nuaimi') {
        console.log("✅ PASS: search[all]=fatima found Fatima Al-Nuaimi");
    } else {
        console.error("❌ FAIL: search[all] failed");
    }

    console.log("\n--- TEST 5: Search Specific Patient Name (search[patient_name]=marcus) ---");
    res = await request({
        hostname: 'localhost',
        port: 8000,
        path: '/api/cases?search[patient_name]=marcus',
        method: 'GET',
        headers: { 'Authorization': `Bearer ${tokenWright}` }
    });
    if (res.body.total === 1 && res.body.data[0].patient_name === 'Marcus Vance') {
        console.log("✅ PASS: search[patient_name]=marcus found Marcus Vance");
    } else {
        console.error("❌ FAIL: search[patient_name] failed");
    }

    console.log("\n--- TEST 6: Category Filter (filters[category]=Refinements) ---");
    res = await request({
        hostname: 'localhost',
        port: 8000,
        path: '/api/cases?filters[category]=Refinements',
        method: 'GET',
        headers: { 'Authorization': `Bearer ${tokenWright}` }
    });
    if (res.body.total === 1 && res.body.data[0].case_id === 'REF1-VELOUR-0003') {
        console.log("✅ PASS: Category filter for Refinements returned REF1-VELOUR-0003");
    } else {
        console.error("❌ FAIL: Category filter failed");
    }

    console.log("\n--- TEST 7: Sorting by Patient Name DESC ---");
    res = await request({
        hostname: 'localhost',
        port: 8000,
        path: '/api/cases?sort[field]=patient_name&sort[direction]=desc',
        method: 'GET',
        headers: { 'Authorization': `Bearer ${tokenWright}` }
    });
    const names = res.body.data.map(c => c.patient_name);
    console.log("Sorted names DESC:", names);
    if (names[0] === 'Zainab Rashid' && names[names.length - 1] === 'Elena Rostova') {
        console.log("✅ PASS: Sorting by patient_name desc worked accurately");
    } else {
        console.error("❌ FAIL: Sorting failed");
    }

    console.log("\n--- TEST 8: Personal Scoping via User Profile (Dr. Emily Watson, see_only_own_uploads: true) ---");
    res = await request({
        hostname: 'localhost',
        port: 8000,
        path: '/api/cases',
        method: 'GET',
        headers: { 'Authorization': `Bearer ${tokenWatson}` }
    });
    console.log(`Dr. Watson sees total cases: ${res.body.total}`);
    console.log(`Dr. Watson cases:`, res.body.data.map(c => `${c.case_id} (${c.patient_name}) by ${c.doctor_name}`));
    if (res.body.total === 1 && res.body.data[0].case_id === 'VELOUR-0004' && res.body.data[0].doctor_name === 'Dr. Emily Watson') {
        console.log("✅ PASS: Dr. Emily Watson only sees her own uploaded case (VELOUR-0004), isolated from Dr. Wright's cases");
    } else {
        console.error("❌ FAIL: Personal scoping failed for Dr. Watson");
    }

    console.log("\n--- TEST 9: IDOR protection for personal uploads (Dr. Watson trying to view Dr. Wright's case /api/cases/1) ---");
    res = await request({
        hostname: 'localhost',
        port: 8000,
        path: '/api/cases/1',
        method: 'GET',
        headers: { 'Authorization': `Bearer ${tokenWatson}` }
    });
    if (res.status === 404) {
        console.log("✅ PASS: Dr. Watson is BLOCKED (404) from opening Dr. Wright's case #1");
    } else {
        console.error(`❌ FAIL: Expected 404 for Dr. Watson opening case #1, got ${res.status}`);
    }

    console.log("\n--- TEST 10: On-demand 'My Cases Only' filter (Dr. Wright with filters[my_cases_only]=true) ---");
    res = await request({
        hostname: 'localhost',
        port: 8000,
        path: '/api/cases?filters[my_cases_only]=true',
        method: 'GET',
        headers: { 'Authorization': `Bearer ${tokenWright}` }
    });
    console.log(`Dr. Wright's own cases count: ${res.body.total}`);
    console.log(`Dr. Wright's own cases:`, res.body.data.map(c => `${c.case_id} by ${c.doctor_name}`));
    const includesWatson = res.body.data.some(c => c.doctor_name.includes('Watson'));
    if (res.body.total === 3 && !includesWatson) {
        console.log("✅ PASS: On-demand 'my_cases_only' filter filtered out Dr. Watson's case for Dr. Wright");
    } else {
        console.error("❌ FAIL: On-demand my_cases_only filter failed");
    }

    console.log("\n--- TEST 11: Case Creation stamps uploader info ---");
    res = await request({
        hostname: 'localhost',
        port: 8000,
        path: '/api/cases/store-in-pipeline',
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${tokenWatson}`,
            'Content-Type': 'application/json'
        }
    }, {
        patient_name: "Test Patient Uploaded By Watson",
        patient_age: 30,
        patient_gender: "Female",
        category: "New Case"
    });
    console.log("Created Case:", res.body.data.case_id, "Doctor:", res.body.data.doctor_name, "Uploader ID:", res.body.data.uploader_id);
    if (res.body.success && res.body.data.uploader_id === 8 && res.body.data.doctor_name.includes('Watson')) {
        console.log("✅ PASS: New case stamped with uploader_id: 8 and Dr. Watson's details");
    } else {
        console.error("❌ FAIL: Case creation did not stamp uploader info properly");
    }

    console.log("\n=== ALL 11 FILTER & PERSONAL SCOPING TESTS COMPLETED ===");
}

runTests().catch(err => {
    console.error("Test execution failed:", err);
    process.exit(1);
});
