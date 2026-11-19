const http = require('http');

let authToken = null;

function loginAdmin() {
    return new Promise((resolve) => {
        const payload = JSON.stringify({
            username: 'admin',
            password: process.env.SEED_DEFAULT_PASSWORD || 'VelourSecure2026!#'
        });
        const req = http.request({
            hostname: 'localhost',
            port: 8000,
            path: '/api/auth/login',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload)
            }
        }, res => {
            let body = '';
            res.on('data', c => body += c);
            res.on('end', () => {
                let data = null;
                try { data = JSON.parse(body); } catch (e) {}
                resolve(data?.data?.token || null);
            });
        });
        req.on('error', () => resolve(null));
        req.write(payload);
        req.end();
    });
}

function uploadFile(filename, content, contentType = 'text/plain') {
    return new Promise((resolve) => {
        const boundary = '----WebKitFormBoundaryUploadSecurityQA';
        const fileHeader = Buffer.from(
            `--${boundary}\r\n` +
            `Content-Disposition: form-data; name="zip_file"; filename="${filename}"\r\n` +
            `Content-Type: ${contentType}\r\n\r\n`
        );
        const fileBody = Buffer.isBuffer(content) ? content : Buffer.from(content);
        const footer = Buffer.from(`\r\n--${boundary}--\r\n`);
        const payload = Buffer.concat([fileHeader, fileBody, footer]);

        const req = http.request({
            hostname: 'localhost',
            port: 8000,
            path: '/api/cases/1/step-files',
            method: 'POST',
            headers: {
                'Content-Type': `multipart/form-data; boundary=${boundary}`,
                'Content-Length': payload.length,
                'Authorization': `Bearer ${authToken}`
            }
        }, res => {
            let resBody = '';
            res.on('data', c => resBody += c);
            res.on('end', () => {
                let data = null;
                try { data = JSON.parse(resBody); } catch(e) {}
                resolve({ status: res.statusCode, body: resBody, data });
            });
        });

        req.on('error', err => resolve({ status: 'ERR', error: err.message }));
        req.write(payload);
        req.end();
    });
}

function reqFile(path, headers = {}) {
    return new Promise((resolve) => {
        const req = http.request({
            hostname: 'localhost',
            port: 8000,
            path: path,
            method: 'GET',
            headers
        }, res => {
            resolve({ status: res.statusCode, headers: res.headers });
        });
        req.on('error', err => resolve({ status: 'ERR', error: err.message }));
        req.end();
    });
}

async function run() {
    console.log('--- TEST: FILE UPLOAD HARDENING & PHI PROTECTION ---');
    let failed = 0;

    authToken = await loginAdmin();
    if (!authToken) {
        console.error('❌ Failed to authenticate admin');
        process.exit(1);
    }

    // 1. Uploading executable / HTML file must be rejected
    const badUpload = await uploadFile('malicious-payload.html', '<h1>Hacked</h1><script>alert(1)</script>', 'text/html');
    console.log(`1. Upload HTML file: Status ${badUpload.status}`);
    if (badUpload.status === 200 || badUpload.status === 201) {
        console.error('   ❌ Expected 400 Bad Request, got:', badUpload.status);
        failed++;
    } else {
        console.log('   ✅ PASS (Disallowed extension rejected)');
    }

    // 2. Uploading valid orthodontic archive (real ZIP magic bytes) must succeed
    const zipBytes = Buffer.concat([Buffer.from([0x50, 0x4B, 0x03, 0x04]), Buffer.from('MOCK_ZIP_CONTENT_BYTES_VALID')]);
    const goodUpload = await uploadFile('patient-steps.zip', zipBytes, 'application/zip');
    console.log(`2. Upload valid .zip file: Status ${goodUpload.status}`);
    if (goodUpload.status !== 200 && goodUpload.status !== 201) {
        console.error('   ❌ Expected 200/201, got:', goodUpload.status);
        failed++;
    } else {
        console.log('   ✅ PASS (Valid medical file accepted)');
    }

    // 3. Unauthenticated access to sensitive patient zip in /uploads/
    const unauthZip = await reqFile('/uploads/sample-treatment-models.zip');
    console.log(`3. Unauthenticated GET /uploads/sample-treatment-models.zip: Status ${unauthZip.status}`);
    if (unauthZip.status === 200) {
        console.error('   ❌ Expected 401 Unauthorized for sensitive patient scans, got 200!');
        failed++;
    } else {
        console.log('   ✅ PASS (Unauthenticated access blocked)');
    }

    console.log(`\nResult: ${failed === 0 ? 'ALL PASSED' : failed + ' TESTS FAILED'}`);
    process.exit(failed === 0 ? 0 : 1);
}

run().catch(e => {
    console.error(e);
    process.exit(1);
});
