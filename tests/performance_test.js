const http = require('http');

let authToken = null;

function req(path, headers = {}, method = 'GET', body = null) {
    return new Promise((resolve) => {
        const payload = body ? JSON.stringify(body) : null;
        const r = http.request({
            hostname: 'localhost',
            port: 8000,
            path: path,
            method,
            headers: {
                ...(authToken ? { 'Authorization': `Bearer ${authToken}` } : {}),
                ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
                ...headers
            }
        }, res => {
            let resBody = '';
            res.on('data', c => resBody += c);
            res.on('end', () => {
                let data = null;
                try { data = JSON.parse(resBody); } catch (e) {}
                resolve({
                    status: res.statusCode,
                    headers: res.headers,
                    length: Buffer.byteLength(resBody),
                    data
                });
            });
        });
        r.on('error', err => resolve({ status: 'ERR', error: err.message }));
        if (payload) r.write(payload);
        r.end();
    });
}

async function run() {
    console.log('--- TEST: PERFORMANCE, COMPRESSION & CACHING ---');
    let failed = 0;

    const loginRes = await req('/api/auth/login', {}, 'POST', {
        username: 'admin',
        password: process.env.SEED_DEFAULT_PASSWORD || 'VelourSecure2026!#'
    });
    authToken = loginRes.data?.data?.token || null;
    if (!authToken) {
        console.error('❌ Failed to authenticate admin');
        process.exit(1);
    }

    // 1. Static asset compression
    const assetRes = await req('/assets/index-5EUXN9UG.js', { 'Accept-Encoding': 'gzip, deflate' });
    console.log(`1. GET /assets/index-5EUXN9UG.js (Accept-Encoding: gzip): Status ${assetRes.status}`);
    const encoding = assetRes.headers['content-encoding'];
    console.log(`   Content-Encoding: ${encoding}`);
    if (!encoding || !encoding.includes('gzip')) {
        console.error('   ❌ Expected Content-Encoding: gzip, got:', encoding);
        failed++;
    } else {
        console.log('   ✅ PASS (Gzip compression active)');
    }

    // 2. Static asset caching headers (immutable / 1 year)
    const cacheCtrl = assetRes.headers['cache-control'] || '';
    console.log(`2. Static Asset Cache-Control: "${cacheCtrl}"`);
    if (!cacheCtrl.includes('max-age') || !cacheCtrl.includes('31536000')) {
        console.error('   ❌ Expected Cache-Control with max-age=31536000/immutable, got:', cacheCtrl);
        failed++;
    } else {
        console.log('   ✅ PASS (Long-term immutable caching enabled for hashed assets)');
    }

    // 3. API no-store caching headers
    const apiRes = await req('/api/cases');
    const apiCacheCtrl = apiRes.headers['cache-control'] || '';
    console.log(`3. API Route Cache-Control: "${apiCacheCtrl}"`);
    if (!apiCacheCtrl.includes('no-store')) {
        console.error('   ❌ Expected Cache-Control: no-store on /api/cases, got:', apiCacheCtrl);
        failed++;
    } else {
        console.log('   ✅ PASS (Sensitive medical APIs prevent browser/proxy caching)');
    }

    console.log(`\nResult: ${failed === 0 ? 'ALL PASSED' : failed + ' TESTS FAILED'}`);
    process.exit(failed === 0 ? 0 : 1);
}

run().catch(e => {
    console.error(e);
    process.exit(1);
});
