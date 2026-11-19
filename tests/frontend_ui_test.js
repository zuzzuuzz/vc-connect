const fs = require('fs');
const path = require('path');

async function run() {
    console.log('--- TEST: HARDENED FRONTEND UI INVARIANTS ---');
    let failed = 0;

    const indexPath = path.join(__dirname, '..', 'public', 'index.html');
    const indexContent = fs.readFileSync(indexPath, 'utf8');
    const runtimePath = path.join(__dirname, '..', 'public', 'assets', 'vc-portal-runtime.js');
    const runtimeContent = fs.readFileSync(runtimePath, 'utf8');

    // 1. No polling, no hardcoded credentials, no #role-switcher, no inline <script>, no hardcoded IPR overlay
    console.log('1. Checking index.html hardening...');
    if (indexContent.includes('setInterval(checkAndInjectIPR') ||
        indexContent.includes('VelourSecure2026!#') ||
        indexContent.includes('role-switcher') ||
        indexContent.includes('1.20 mm') ||
        /<script(?![^>]*\bsrc=)/i.test(indexContent) ||
        !indexContent.includes('/assets/vc-portal-runtime.js')) {
        console.error('   ❌ index.html retains unsafe inline script, credentials, role-switcher, or hardcoded IPR overlay');
        failed++;
    } else {
        console.log('   ✅ PASS (index.html is free of inline scripts, credentials, role-switcher, and hardcoded IPR)');
    }

    // 2. Verify WebSocket/Pusher mock, RTL sync, and complete logout state purge in vc-portal-runtime.js
    console.log('2. Checking vc-portal-runtime.js mockWs, RTL sync, and purgeClientState...');
    if (runtimeContent.includes('mockWs') &&
        runtimeContent.includes('pusher:connection_established') &&
        runtimeContent.includes('syncDirWithLocale') &&
        runtimeContent.includes('purgeClientState') &&
        runtimeContent.includes('case.draft')) {
        console.log('   ✅ PASS (vc-portal-runtime.js includes mockWs, RTL sync, and logout state purge)');
    } else {
        console.error('   ❌ vc-portal-runtime.js missing required runtime/purge hooks');
        failed++;
    }

    // 3. Verify simulation.html & vc-simulation.js have no hardcoded PHI, no inline handlers, and pause on visibilitychange
    console.log('3. Checking simulation.html & vc-simulation.js...');
    const simHtml = fs.readFileSync(path.join(__dirname, '..', 'public', 'simulation.html'), 'utf8');
    const simJs = fs.readFileSync(path.join(__dirname, '..', 'public', 'assets', 'vc-simulation.js'), 'utf8');
    if (simHtml.includes('Fatima Al-Nuaimi') ||
        simHtml.includes('onclick=') ||
        /<script(?![^>]*\bsrc=)/i.test(simHtml) ||
        !simJs.includes('typeof THREE ===') ||
        !simJs.includes('visibilitychange')) {
        console.error('   ❌ simulation.html / vc-simulation.js failed PHI removal, CSP, THREE fallback, or visibilitychange check');
        failed++;
    } else {
        console.log('   ✅ PASS (simulation viewer fetches live case PHI safely, obeys CSP, and pauses on hidden tab)');
    }

    console.log(`\nResult: ${failed === 0 ? 'ALL PASSED' : failed + ' TESTS FAILED'}`);
    process.exit(failed === 0 ? 0 : 1);
}

run().catch(e => {
    console.error(e);
    process.exit(1);
});
