const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const compression = require('compression');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const {
    ALL_PERMISSION_NAMES,
    PERMISSION_MATRIX,
    hashPasswordAsync,
    verifyPasswordAsync,
    serializeUser,
    createDatabase
} = require('./db');

const app = express();
const PORT = Number(process.env.PORT) || 8000;
const db = createDatabase();

// ==========================================
// HELPERS: TIMEZONE, SANITIZATION & CATALOG
// ==========================================
const CLINIC_TZ = 'Asia/Dubai';

function formatClinicDate(date = new Date()) {
    return new Intl.DateTimeFormat('en-CA', {
        timeZone: CLINIC_TZ,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
    }).format(date);
}

function formatClinicDateTime(date = new Date()) {
    const parts = new Intl.DateTimeFormat('en-CA', {
        timeZone: CLINIC_TZ,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
    }).formatToParts(date);
    const get = (t) => (parts.find(p => p.type === t) || {}).value || '00';
    const hh = get('hour') === '24' ? '00' : get('hour');
    return `${get('year')}-${get('month')}-${get('day')} ${hh}:${get('minute')}`;
}

function sanitizeText(str) {
    if (typeof str !== 'string') return str;
    return str
        .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')
        .replace(/<[^>]*>/g, '')
        .replace(/\bon[a-z]+\s*=/gi, '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

function sanitizeRichHtml(str) {
    if (typeof str !== 'string') return str;
    let out = str
        .replace(/<(script|iframe|object|embed|svg|style|link|meta|base|form)[^>]*>[\s\S]*?<\/\1>/gi, '')
        .replace(/<(script|iframe|object|embed|svg|style|link|meta|base|form)[^>]*\/?>/gi, '')
        .replace(/\son[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '')
        .replace(/\s(?:href|src|action|formaction)\s*=\s*(?:"\s*(?:javascript|vbscript|data\s*:\s*text\/html)[^"]*"|'\s*(?:javascript|vbscript|data\s*:\s*text\/html)[^']*')/gi, '');
    const ALLOWED_TAGS = new Set(['p', 'br', 'strong', 'b', 'em', 'i', 'u', 'ul', 'ol', 'li', 'span']);
    out = out.replace(/<\/?([a-zA-Z0-9-]+)([^>]*)>/g, (full, tag) => {
        const lower = tag.toLowerCase();
        if (!ALLOWED_TAGS.has(lower)) return '';
        return full.startsWith('</') ? `</${lower}>` : (lower === 'br' ? '<br>' : `<${lower}>`);
    });
    return out;
}

function isStrongPassword(password) {
    return typeof password === 'string' &&
        password.length >= 8 &&
        password.length <= 128 &&
        /[A-Z]/.test(password) &&
        /[a-z]/.test(password) &&
        /[0-9]/.test(password);
}

function paginateParams(query, { defaultPerPage = 20, maxPerPage = 100 } = {}) {
    const page = Math.max(1, parseInt(query?.page, 10) || 1);
    const rawPer = parseInt(query?.per_page, 10);
    const perPage = Math.min(maxPerPage, Math.max(1, Number.isFinite(rawPer) ? rawPer : defaultPerPage));
    const offset = (page - 1) * perPage;
    return { page, perPage, offset };
}

function escapeLike(str) {
    return String(str).replace(/[!%_]/g, m => '!' + m);
}

// Authoritative Server-Side Billing Catalog (values in AED minor units: fils)
const BILLABLE_CATALOG = {
    '3d-print': { label: 'VelourCare Aligner Step Model 3D Print', unitFils: 3500 },
    'thermoforming': { label: 'Multi-Layer Thermoforming & Laser Trim', unitFils: 6500 },
    'laser-marking': { label: 'Laser Tooth Number & Patient ID Marking', unitFils: 1000 },
    'digital-setup': { label: 'Digital Treatment Setup & 3D Staging Fee', unitFils: 65000 },
    'retainers': { label: 'VelourCare Dual Arch Clear Retainers (3 Sets)', unitFils: 125000 },
    'treatment-planning': { label: 'Digital Treatment Planning Service', unitFils: 150000 },
    'manufacturing': { label: 'Clear Aligner Manufacturing Package', unitFils: 300000 },
    'full-aligner-package': { label: 'VelourCare Clear Aligner Full Treatment Package', unitFils: 450000 }
};

function resolveCatalogItem(item) {
    if (!item || typeof item !== 'object') return null;
    if (item.service_code && BILLABLE_CATALOG[item.service_code]) {
        return BILLABLE_CATALOG[item.service_code];
    }
    const desc = String(item.description || '').toLowerCase();
    if (!desc) return null;
    if (desc.includes('3d print') || desc.includes('model printing') || desc.includes('step model')) return BILLABLE_CATALOG['3d-print'];
    if (desc.includes('thermoforming')) return BILLABLE_CATALOG['thermoforming'];
    if (desc.includes('laser tooth') || desc.includes('laser marking')) return BILLABLE_CATALOG['laser-marking'];
    if (desc.includes('digital treatment setup') || desc.includes('staging fee')) return BILLABLE_CATALOG['digital-setup'];
    if (desc.includes('retainer')) return BILLABLE_CATALOG['retainers'];
    if (desc.includes('treatment planning')) return BILLABLE_CATALOG['treatment-planning'];
    if (desc.includes('manufacturing')) return BILLABLE_CATALOG['manufacturing'];
    if (desc.includes('full treatment') || desc.includes('clear aligner')) return BILLABLE_CATALOG['full-aligner-package'];
    return null;
}

function calculateInvoiceTotalsServerSide(rawItems, discountPercent = 0, taxRate = 0.05) {
    if (!Array.isArray(rawItems) || rawItems.length === 0) {
        return { error: 'At least one valid catalog line item is required.' };
    }
    const discPct = Number(discountPercent ?? 0);
    if (!Number.isFinite(discPct) || discPct < 0 || discPct > 50) {
        return { error: 'Discount percentage must be between 0% and 50%.' };
    }

    let subtotalFils = 0;
    const calculatedItems = [];
    for (const raw of rawItems) {
        const catalog = resolveCatalogItem(raw);
        if (!catalog) {
            return { error: `Unknown or unpriced billing item: '${sanitizeText(String(raw?.description || raw?.service_code || ''))}'` };
        }
        const qty = Number(raw.quantity ?? 1);
        if (!Number.isInteger(qty) || qty < 1 || qty > 1000) {
            return { error: 'Item quantity must be an integer between 1 and 1000.' };
        }
        const unitFils = catalog.unitFils;
        const lineFils = unitFils * qty;
        subtotalFils += lineFils;
        const unitAmount = unitFils / 100;
        const lineAmount = lineFils / 100;
        calculatedItems.push({
            description: sanitizeText(String(raw.description || catalog.label)),
            quantity: qty,
            unit_price: unitAmount,
            unit_amount: unitAmount,
            total: lineAmount,
            total_amount: lineAmount
        });
    }

    const discountFils = Math.round(subtotalFils * (discPct / 100));
    const taxableFils = Math.max(0, subtotalFils - discountFils);
    const taxFils = Math.round(taxableFils * taxRate);
    const totalFils = taxableFils + taxFils;

    return {
        items: calculatedItems,
        subtotalFils,
        discountFils,
        taxFils,
        totalFils
    };
}

// ==========================================
// FILE STORAGE, EXTENSION & MAGIC BYTE VALIDATION
// ==========================================
const uploadDir = path.join(__dirname, 'uploads');
const publicPath = path.join(__dirname, 'public');
const publicUploads = path.join(publicPath, 'uploads');
const publicAssets = path.join(publicPath, 'assets');

if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const DANGEROUS_EXTS = ['.exe', '.html', '.htm', '.js', '.mjs', '.cjs', '.php', '.sh', '.bat', '.cmd', '.vbs', '.py', '.msi', '.dll', '.com', '.svg', '.ps1'];
const ALLOWED_UPLOAD_EXTS = ['.stl', '.ply', '.obj', '.pdf', '.png', '.jpg', '.jpeg', '.zip', '.o3c'];

function sanitizeFileName(name) {
    const base = path.basename(String(name || 'file')).replace(/[^a-zA-Z0-9._-]/g, '_');
    return base.replace(/\.\.+/g, '.') || 'asset.bin';
}

function validateUploadedMagicBytes(filePath, ext) {
    try {
        const fd = fs.openSync(filePath, 'r');
        const buf = Buffer.alloc(64);
        const bytesRead = fs.readSync(fd, buf, 0, 64, 0);
        fs.closeSync(fd);
        if (bytesRead === 0) return false;
        const head = buf.subarray(0, bytesRead);
        const textHead = head.toString('utf8').trimStart().toLowerCase();

        // Reject active executable / HTML / script payloads regardless of extension
        if (
            head.subarray(0, 2).toString('ascii') === 'MZ' ||
            (head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46) ||
            textHead.startsWith('<html') ||
            textHead.startsWith('<!doctype') ||
            textHead.startsWith('<script') ||
            textHead.startsWith('<svg') ||
            textHead.startsWith('<?php') ||
            textHead.startsWith('#!')
        ) {
            return false;
        }

        if (ext === '.pdf') {
            return head.subarray(0, 5).toString('ascii') === '%PDF-';
        }
        if (ext === '.zip' || ext === '.o3c') {
            return head[0] === 0x50 && head[1] === 0x4b && (
                (head[2] === 0x03 && head[3] === 0x04) ||
                (head[2] === 0x05 && head[3] === 0x06) ||
                (head[2] === 0x07 && head[3] === 0x08)
            );
        }
        if (ext === '.png') {
            const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
            return bytesRead >= 8 && sig.every((b, idx) => head[idx] === b);
        }
        if (ext === '.jpg' || ext === '.jpeg') {
            return bytesRead >= 3 && head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff;
        }
        // .stl, .ply, .obj (ASCII or binary mesh) already cleared executable/HTML signatures above
        return true;
    } catch (e) {
        return false;
    }
}

function cleanupUploadedFiles(req) {
    const files = [];
    if (req.file) files.push(req.file);
    if (Array.isArray(req.files)) files.push(...req.files);
    for (const f of files) {
        if (f && f.path && fs.existsSync(f.path)) {
            try { fs.unlinkSync(f.path); } catch (e) {}
        }
    }
}

function validateRequestFiles(req, res) {
    const files = [];
    if (req.file) files.push(req.file);
    if (Array.isArray(req.files)) files.push(...req.files);
    for (const f of files) {
        const ext = path.extname(f.originalname || '').toLowerCase();
        if (!validateUploadedMagicBytes(f.path, ext)) {
            cleanupUploadedFiles(req);
            res.status(400).json({
                success: false,
                message: `File '${sanitizeText(f.originalname)}' failed binary content validation for '${ext}'.`
            });
            return false;
        }
    }
    return true;
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const safeName = sanitizeFileName(file.originalname);
        const randomHex = crypto.randomBytes(16).toString('hex');
        cb(null, `${Date.now()}-${randomHex}-${safeName}`);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 50 * 1024 * 1024, files: 10 },
    fileFilter: (req, file, cb) => {
        const original = String(file.originalname || '').toLowerCase();
        const parts = original.split('.');
        if (parts.length > 2) {
            for (let i = 1; i < parts.length; i++) {
                const subExt = '.' + parts[i];
                if (DANGEROUS_EXTS.includes(subExt)) {
                    const err = new Error(`File contains prohibited extension '${subExt}'.`);
                    err.code = 'INVALID_FILE_TYPE';
                    return cb(err, false);
                }
            }
        }
        const ext = path.extname(original).toLowerCase();
        if (DANGEROUS_EXTS.includes(ext) || !ALLOWED_UPLOAD_EXTS.includes(ext)) {
            const err = new Error(`File extension '${ext}' is not permitted.`);
            err.code = 'INVALID_FILE_TYPE';
            return cb(err, false);
        }
        cb(null, true);
    }
});

// ==========================================
// GLOBAL MIDDLEWARE: COMPRESSION, HEADERS, CORS, RATE LIMIT
// ==========================================
app.use(compression());

const ALLOWED_ORIGINS = new Set([
    `http://localhost:${PORT}`,
    `http://127.0.0.1:${PORT}`,
    'http://localhost:8000',
    'http://127.0.0.1:8000',
    ...(process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean) : [])
]);

app.use((req, res, next) => {
    const sanitizedUrl = req.url.replace(/([?&](?:password|token|email|patient_name|name)=)[^&]+/gi, '$1[REDACTED_PHI]');
    console.log(`[${new Date().toISOString()}] ${req.method} ${sanitizedUrl}`);

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    // shortcut: style-src retains unsafe-inline for precompiled Vue/Bootstrap bundle inline styles, remove when Vue source adopts nonces
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self' ws: wss:;"
    );

    if (process.env.NODE_ENV === 'production' && process.env.PUBLIC_HOST && req.headers['x-forwarded-proto'] && req.headers['x-forwarded-proto'] !== 'https') {
        return res.redirect(301, `https://${process.env.PUBLIC_HOST}${req.url}`);
    }

    if (req.path.startsWith('/api/') || req.path.startsWith('/sanctum/') || req.path.startsWith('/uploads/') || req.path.startsWith('/simulation')) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    }
    next();
});

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.has(origin)) {
            return callback(null, true);
        }
        return callback(null, false);
    },
    credentials: true
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(cookieParser());

// shortcut: in-process rate limiter, upgrade to Redis when running multiple Node replicas
const rateLimitBuckets = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX) || 300;
const RATE_LIMIT_AUTH_MAX = Number(process.env.RATE_LIMIT_AUTH_MAX) || 30;

function checkRateLimit(key, limit) {
    const now = Date.now();
    const rec = rateLimitBuckets.get(key);
    if (!rec || now >= rec.resetAt) {
        if (rateLimitBuckets.size > 10000) rateLimitBuckets.clear();
        rateLimitBuckets.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
        return true;
    }
    rec.count += 1;
    return rec.count <= limit;
}

app.use('/api', (req, res, next) => {
    const isSensitiveAuth = req.path === '/auth/forgot-password' || req.path === '/auth/reset-password' || req.path === '/auth/accept-invitation';
    const limit = isSensitiveAuth ? RATE_LIMIT_AUTH_MAX : RATE_LIMIT_MAX;
    const key = `${req.ip}:${isSensitiveAuth ? 'auth' : 'api'}`;
    if (!checkRateLimit(key, limit)) {
        return res.status(429).json({ success: false, message: 'Too many requests. Please slow down and try again shortly.' });
    }
    next();
});

// ==========================================
// SECURITY STATE, RBAC & AUTH MIDDLEWARE
// ==========================================
const failedLoginAttempts = new Map();
const passwordResetTokens = new Map();
const invitationTokens = new Map();
const signedFileTokens = new Map();

const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;
const MAX_FAILED_ATTEMPTS = 5;
const SESSION_IDLE_TIMEOUT_MS = 30 * 60 * 1000;
const SESSION_ABSOLUTE_TIMEOUT_MS = 12 * 60 * 60 * 1000;

setInterval(() => {
    const now = Date.now();
    try { db.pruneExpired(now); } catch (e) {}
    for (const [k, rec] of failedLoginAttempts.entries()) {
        if (rec.lockedUntil && now >= rec.lockedUntil) failedLoginAttempts.delete(k);
    }
    for (const [k, rec] of passwordResetTokens.entries()) {
        if (now >= rec.expiresAt) passwordResetTokens.delete(k);
    }
    for (const [k, rec] of invitationTokens.entries()) {
        if (now >= rec.expiresAt) invitationTokens.delete(k);
    }
    for (const [k, rec] of signedFileTokens.entries()) {
        if (now >= rec.expiresAt) signedFileTokens.delete(k);
    }
    for (const [k, rec] of rateLimitBuckets.entries()) {
        if (now >= rec.resetAt) rateLimitBuckets.delete(k);
    }
}, 60 * 1000).unref();

function checkBruteForce(identifier) {
    const rec = failedLoginAttempts.get(identifier);
    if (!rec) return { locked: false };
    if (Date.now() < rec.lockedUntil) {
        return { locked: true, remainingMinutes: Math.ceil((rec.lockedUntil - Date.now()) / 60000) };
    }
    if (rec.lockedUntil > 0 && Date.now() >= rec.lockedUntil) {
        failedLoginAttempts.delete(identifier);
    }
    return { locked: false };
}

function recordFailedLogin(identifier) {
    const rec = failedLoginAttempts.get(identifier) || { count: 0, lockedUntil: 0 };
    rec.count += 1;
    if (rec.count >= MAX_FAILED_ATTEMPTS) {
        rec.lockedUntil = Date.now() + LOGIN_LOCKOUT_MS;
    }
    failedLoginAttempts.set(identifier, rec);
}

function resetFailedLogin(identifier) {
    failedLoginAttempts.delete(identifier);
}

function getUserRole(user) {
    if (!user) return 'none';
    if (user.is_super_admin || user.role_slug === 'super-admin') return 'super-admin';
    return user.role_slug || 'none';
}

function isOwnUpload(user, caseRecord) {
    if (!user || !caseRecord) return false;
    const uid = Number(user.id);
    return Number(caseRecord.created_by) === uid ||
        Number(caseRecord.uploader_id) === uid ||
        Number(caseRecord.doctor_id) === uid;
}

function canUser(user, action, resource = null) {
    if (!user) return false;
    const role = getUserRole(user);
    if (role === 'super-admin' || role === 'admin') return true;

    const actionAliases = {
        'create_cases': ['create_edit_case', 'create_cases'],
        'create_edit_case': ['create_cases', 'create_edit_case'],
        'view_cases': ['view_all_cases', 'view_cases'],
        'view_all_cases': ['view_cases', 'view_all_cases'],
        'edit_treatment_plans': ['approve_treatment_plan', 'edit_treatment_plans'],
        'approve_treatment_plan': ['edit_treatment_plans', 'approve_treatment_plan'],
        'view_invoices': ['view_invoices'],
        'create_invoices': ['create_edit_invoices', 'create_invoices'],
        'create_edit_invoices': ['create_invoices', 'create_edit_invoices']
    };
    const checkActions = actionAliases[action] || [action];
    const matrix = PERMISSION_MATRIX[role] || PERMISSION_MATRIX['none'];

    let perm = null;
    for (const act of checkActions) {
        if (matrix[act]) {
            perm = matrix[act];
            break;
        }
    }
    if (!perm && Array.isArray(user.permissions) && checkActions.some(act => user.permissions.includes(act))) {
        perm = 'Y';
    }
    if (!perm || perm === 'N') return false;
    if (perm === 'Y') return true;

    if (perm === 'Own' || perm === 'Own_create' || perm === 'Own_approve') {
        if (!resource) return true;
        const userClientId = Number(user.client_id || (user.client && user.client.id));
        const resClientId = Number(resource.client_id || (resource.client && resource.client.id));
        if (!userClientId || !resClientId || userClientId !== resClientId) return false;
        if (user.see_only_own_uploads || user.role_slug === 'associate-doctor') {
            return isOwnUpload(user, resource);
        }
        return true;
    }

    if (perm === 'Assigned') {
        if (!resource) return true;
        const statusVal = (typeof resource.status === 'object' && resource.status) ? (resource.status.value || resource.status.name) : (resource.status_value || resource.status);
        return statusVal === 'in-manufacturing' || statusVal === 'plan-step-files-ready' || Number(resource.vendor_id) === Number(user.id);
    }

    if (perm === 'Y_invoices') {
        return action === 'export_data';
    }

    return false;
}

function canAccessCase(user, caseRow, action = 'view_all_cases') {
    if (!user || !caseRow || caseRow.is_archived) return false;
    const role = getUserRole(user);
    if (role === 'accounts' || role === 'none') return false;
    return canUser(user, action, caseRow);
}

function canAccessClient(user, clientId) {
    if (!user) return false;
    const role = getUserRole(user);
    if (role === 'super-admin' || role === 'admin' || role === 'planner' || role === 'accounts') return true;
    if (role === 'client') {
        return Number(user.client_id) === Number(clientId);
    }
    return false;
}

function canAccessInvoice(user, inv) {
    if (!user || !inv) return false;
    const role = getUserRole(user);
    if (role === 'super-admin' || role === 'admin' || role === 'accounts') return true;
    if (role === 'client') {
        return Number(user.client_id) === Number(inv.client_id);
    }
    return false;
}

function resolveAuthUser(req) {
    let token = null;
    let method = null;
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.slice(7).trim();
        method = 'bearer';
    } else if (req.cookies && req.cookies['laravel_session']) {
        token = req.cookies['laravel_session'];
        method = 'cookie';
    }
    if (!token) return null;

    const sess = db.sqlite.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
    if (!sess) return null;

    const now = Date.now();
    if (now >= sess.expires_at || (now - sess.last_active_at) > SESSION_IDLE_TIMEOUT_MS) {
        db.sqlite.prepare('DELETE FROM sessions WHERE token = ?').run(token);
        return null;
    }

    const userRow = db.sqlite.prepare('SELECT * FROM users WHERE id = ?').get(sess.user_id);
    if (!userRow || ['inactive', 'disabled', 'suspended'].includes(userRow.status_value)) {
        db.sqlite.prepare('DELETE FROM sessions WHERE token = ?').run(token);
        return null;
    }

    db.sqlite.prepare('UPDATE sessions SET last_active_at = ? WHERE token = ?').run(now, token);
    req.authMethod = method;
    req.authToken = token;
    return db.mapUserRow(userRow);
}

const PUBLIC_API_ROUTES = [
    '/api/auth/login',
    '/api/auth/forgot-password',
    '/api/auth/reset-password',
    '/api/auth/accept-invitation',
    '/api/sanctum/csrf-cookie',
    '/api/files/signed-download',
    '/api/health',
    '/api/legal/privacy-policy',
    '/api/legal/terms-of-service',
    '/api/legal/third-party-processors'
];

const CSRF_EXEMPT_PATHS = new Set([
    '/api/auth/login',
    '/api/auth/forgot-password',
    '/api/auth/reset-password',
    '/api/auth/accept-invitation',
    '/api/auth/logout'
]);

function isPublicApiPath(reqPath) {
    return PUBLIC_API_ROUTES.some(p => reqPath === p || reqPath.startsWith(p + '?')) ||
        reqPath.startsWith('/api/auth/portal/') ||
        reqPath.startsWith('/api/public/client-branding/') ||
        reqPath.startsWith('/api/public/');
}

app.use((req, res, next) => {
    req.user = resolveAuthUser(req);
    if (req.path.startsWith('/api/') && !isPublicApiPath(req.path) && !req.user) {
        return res.status(401).json({ message: 'Unauthenticated.' });
    }
    next();
});

// Double-submit CSRF enforcement for cookie-authenticated mutations
app.use((req, res, next) => {
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
    if (req.authMethod !== 'cookie') return next();
    if (CSRF_EXEMPT_PATHS.has(req.path) || req.path.startsWith('/api/auth/portal/')) return next();

    const cookieToken = req.cookies && req.cookies['XSRF-TOKEN'];
    let headerToken = req.headers['x-xsrf-token'];
    if (typeof headerToken === 'string') {
        try { headerToken = decodeURIComponent(headerToken); } catch (e) {}
    }
    if (!cookieToken || !headerToken || typeof cookieToken !== 'string' || typeof headerToken !== 'string') {
        return res.status(403).json({ success: false, message: 'Invalid or missing CSRF token.' });
    }
    const a = Buffer.from(cookieToken, 'utf8');
    const b = Buffer.from(headerToken, 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return res.status(403).json({ success: false, message: 'Invalid or missing CSRF token.' });
    }
    next();
});

// Route-level helper middlewares (executed BEFORE Multer)
function requireAuth(req, res, next) {
    if (!req.user) return res.status(401).json({ message: 'Unauthenticated.' });
    next();
}

function requirePermission(action, message = 'Forbidden: You do not have permission to perform this action.') {
    return (req, res, next) => {
        if (!req.user) return res.status(401).json({ message: 'Unauthenticated.' });
        if (!canUser(req.user, action)) {
            return res.status(403).json({ success: false, message });
        }
        next();
    };
}

function loadCaseParam(paramName = 'id') {
    return (req, res, next) => {
        const raw = String(req.params[paramName] || '').trim();
        let row = null;
        if (/^\d+$/.test(raw)) {
            row = db.sqlite.prepare('SELECT * FROM cases WHERE id = ? AND is_archived = 0').get(Number(raw));
        }
        if (!row) {
            row = db.sqlite.prepare('SELECT * FROM cases WHERE case_id = ? AND is_archived = 0').get(raw);
        }
        if (!row) {
            return res.status(404).json({ message: `Case #${raw} not found.` });
        }
        req.caseRow = db.mapCaseRow(row);
        next();
    };
}

function requireCaseAccess(action = 'view_all_cases', paramName = 'id') {
    return [
        requireAuth,
        loadCaseParam(paramName),
        (req, res, next) => {
            const role = getUserRole(req.user);
            if (role === 'accounts' || role === 'none') {
                return res.status(403).json({ success: false, message: 'Forbidden: You do not have access to clinical patient cases.' });
            }
            if (!canAccessCase(req.user, req.caseRow, action)) {
                const isSameTenant = role === 'client' && Number(req.user.client_id) === Number(req.caseRow.client_id);
                if (role === 'client' && !isSameTenant) {
                    db.insertAuditLog({
                        user: req.user, action: 'IDOR_CASE_TAMPERING_BLOCKED',
                        resourceType: 'case', resourceId: req.caseRow.id,
                        details: `Blocked attempt by clinic ${req.user.client_id} on clinic ${req.caseRow.client_id} case`,
                        ip: req.ip
                    });
                    return res.status(404).json({ message: `Case #${req.params[paramName]} not found.` });
                }
                if (role === 'client' && req.user.see_only_own_uploads) {
                    return res.status(404).json({ message: `Case #${req.params[paramName]} not found.` });
                }
                return res.status(403).json({ success: false, message: 'Forbidden: Insufficient permissions for this case action.' });
            }
            next();
        }
    ];
}

function buildCaseScopeSql(user, { alias = '', applyMyCasesOnly = false } = {}) {
    const pfx = alias ? `${alias}.` : '';
    const clauses = [`${pfx}is_archived = 0`];
    const params = [];
    const role = getUserRole(user);

    if (role === 'accounts' || role === 'none') {
        return { empty: true, sql: '1=0', params: [] };
    }
    if (role === 'client') {
        const clientId = Number(user.client_id || (user.client && user.client.id) || 0);
        if (!clientId) return { empty: true, sql: '1=0', params: [] };
        clauses.push(`${pfx}client_id = ?`);
        params.push(clientId);

        if (user.see_only_own_uploads || user.role_slug === 'associate-doctor' || applyMyCasesOnly) {
            const uid = Number(user.id);
            clauses.push(`(${pfx}created_by = ? OR ${pfx}uploader_id = ? OR ${pfx}doctor_id = ?)`);
            params.push(uid, uid, uid);
        }
    } else if (role === 'vendor') {
        clauses.push(`(${pfx}status_value IN ('in-manufacturing', 'plan-step-files-ready') OR ${pfx}vendor_id = ?)`);
        params.push(Number(user.id));
    }

    return { empty: false, sql: clauses.join(' AND '), params };
}

// ==========================================
// PUBLIC PAGES & AUTHENTICATED 3D VIEWER
// ==========================================
app.get(['/simulation/:caseId', '/simulation', '/simulation.html'], (req, res) => {
    if (!req.user) {
        return res.status(401).json({ message: 'Unauthenticated. Clinical simulation requires an authorized session.' });
    }
    const role = getUserRole(req.user);
    if (role === 'accounts' || role === 'none') {
        return res.status(403).json({ message: 'Forbidden: Clinical simulation is restricted to authorized clinical staff.' });
    }
    if (req.params.caseId) {
        const raw = String(req.params.caseId).trim();
        let row = /^\d+$/.test(raw)
            ? db.sqlite.prepare('SELECT * FROM cases WHERE id = ? AND is_archived = 0').get(Number(raw))
            : db.sqlite.prepare('SELECT * FROM cases WHERE LOWER(case_id) = LOWER(?) AND is_archived = 0').get(raw);
        if (!row) return res.status(404).json({ message: 'Case not found.' });
        const mapped = db.mapCaseRow(row);
        if (!canAccessCase(req.user, mapped, 'view_all_cases')) {
            return res.status(404).json({ message: 'Case not found.' });
        }
    }
    res.sendFile(path.join(publicPath, 'simulation.html'));
});

app.get(['/privacy-policy', '/privacy-policy.html'], (req, res) => {
    res.sendFile(path.join(publicPath, 'privacy-policy.html'));
});

app.get(['/terms-of-service', '/terms-of-service.html'], (req, res) => {
    res.sendFile(path.join(publicPath, 'terms-of-service.html'));
});

// ==========================================
// 1. CSRF COOKIE & AUTHENTICATION
// ==========================================
app.get(['/sanctum/csrf-cookie', '/api/sanctum/csrf-cookie'], (req, res) => {
    const existingXsrf = req.cookies && req.cookies['XSRF-TOKEN'];
    const token = existingXsrf || crypto.randomBytes(32).toString('hex');
    const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
    res.cookie('XSRF-TOKEN', token, {
        httpOnly: false,
        sameSite: 'lax',
        secure: isSecure,
        path: '/'
    });
    res.status(204).end();
});

app.get('/api/public/client-branding/:tenantSlug', (req, res) => {
    const slug = String(req.params.tenantSlug || '').toLowerCase().trim();
    const clients = db.sqlite.prepare('SELECT * FROM clients').all().map(db.mapClientRow);
    const client = clients.find(c =>
        (c.case_id_prefix && c.case_id_prefix.toLowerCase() === slug) ||
        (c.login_uri && c.login_uri.toLowerCase() === slug) ||
        (c.name && c.name.toLowerCase().replace(/[^a-z0-9]+/g, '-') === slug) ||
        String(c.id) === slug
    );
    if (!client) {
        return res.json({
            data: {
                branding: {
                    companyName: 'VC Connect',
                    authImage: '/assets/login-page-logo-BDn48l5g.jpeg',
                    logoUrl: '/assets/vc-connect-square-v2.png'
                }
            }
        });
    }
    res.json({
        data: {
            branding: {
                companyName: client.company_name || client.name,
                authImage: client.login_image_url || '/assets/login-page-logo-BDn48l5g.jpeg',
                logoUrl: client.logo_url || '/assets/vc-connect-square-v2.png'
            }
        }
    });
});

app.post(['/api/auth/login', '/api/auth/portal/:tenantSlug/login'], async (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password || typeof password !== 'string') {
        return res.status(401).json({
            success: false,
            message: 'Invalid email or password.',
            errors: { username: ['Invalid email or password.'] }
        });
    }

    const cleanUsername = String(username).trim().toLowerCase();
    const bruteKey = `${req.ip}:${cleanUsername}`;
    const brute = checkBruteForce(bruteKey);
    if (brute.locked) {
        return res.status(429).json({
            success: false,
            message: `Account temporarily locked due to repeated failed attempts. Please try again in ${brute.remainingMinutes} minutes.`,
            errors: { username: [`Account temporarily locked due to repeated failed attempts. Please try again in ${brute.remainingMinutes} minutes.`] }
        });
    }

    const aliasMap = {
        'unassigned@velourcare.com': 'new_user',
        'new_user@velourcare.com': 'new_user',
        'unassigned': 'new_user',
        'vendor@velourcare.com': 'lab',
        'doctor.wright@velourcare.com': 'doctor',
        'doctor.rostova@velourcare.com': 'doctor_b'
    };
    const lookupName = aliasMap[cleanUsername] || cleanUsername;
    const userRow = db.sqlite.prepare('SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ? LIMIT 1').get(lookupName, lookupName);
    let user = userRow ? db.mapUserRow(userRow) : null;

    const tenantSlug = req.params.tenantSlug ? String(req.params.tenantSlug).trim().toLowerCase() : null;
    if (user && tenantSlug && !user.is_super_admin && user.role_slug !== 'admin') {
        const clientUri = user.assigned_role_modal?.login_uri?.toLowerCase();
        const clientPrefix = user.client?.case_id_prefix?.toLowerCase();
        const clientId = String(user.client_id || '');
        if (clientUri !== tenantSlug && clientPrefix !== tenantSlug && clientId !== tenantSlug) {
            user = null;
        }
    }

    const isValid = user && await verifyPasswordAsync(password, user.password_hash, user.password_salt);
    if (!user || !isValid) {
        recordFailedLogin(bruteKey);
        db.insertAuditLog({
            user: null, action: 'LOGIN_FAILED',
            details: `Failed login attempt for identifier: ${sanitizeText(cleanUsername)}${tenantSlug ? ' on portal ' + sanitizeText(tenantSlug) : ''}`,
            ip: req.ip
        });
        return res.status(401).json({
            success: false,
            message: 'Invalid email or password.',
            errors: { username: ['Invalid email or password.'] }
        });
    }

    const statusVal = typeof user.status === 'object' ? user.status.value : user.status;
    if (['inactive', 'disabled', 'suspended'].includes(String(statusVal).toLowerCase())) {
        return res.status(403).json({
            success: false,
            message: 'Your account is disabled. Please contact your administrator.',
            errors: { username: ['Your account is disabled. Please contact your administrator.'] }
        });
    }

    resetFailedLogin(bruteKey);
    const now = Date.now();
    const sessionToken = 'velourcare-sess-' + crypto.randomBytes(32).toString('hex');
    const xsrfToken = crypto.randomBytes(32).toString('hex');

    db.sqlite.prepare(`
        INSERT INTO sessions (token, user_id, created_at, last_active_at, expires_at, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
    `).run(sessionToken, user.id, now, now, now + SESSION_ABSOLUTE_TIMEOUT_MS, req.ip || '127.0.0.1');

    const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
    res.cookie('XSRF-TOKEN', xsrfToken, { httpOnly: false, sameSite: 'lax', secure: isSecure, path: '/' });
    res.cookie('laravel_session', sessionToken, { httpOnly: true, sameSite: 'lax', secure: isSecure, path: '/' });

    db.insertAuditLog({
        user, action: 'LOGIN_SUCCESS',
        details: `User logged in${tenantSlug ? ' on portal ' + sanitizeText(tenantSlug) : ''}`,
        ip: req.ip
    });

    const statusStr = (user.status && typeof user.status === 'object')
        ? (user.status.label || (user.status.value === 'inactive' ? 'Inactive' : 'Active'))
        : (user.status || 'Active');

    res.json({
        success: true,
        message: 'Welcome to VelourCare Ortho Cloud',
        data: {
            user: {
                ...serializeUser(user),
                status: statusStr
            },
            token: sessionToken
        }
    });
});

app.get('/api/auth/verify', (req, res) => {
    if (!req.user) return res.status(401).json({ message: 'Unauthenticated.' });
    const statusStr = (req.user.status && typeof req.user.status === 'object')
        ? (req.user.status.label || (req.user.status.value === 'inactive' ? 'Inactive' : 'Active'))
        : (req.user.status || 'Active');
    res.json({
        data: {
            user: {
                ...serializeUser(req.user),
                status: statusStr
            }
        }
    });
});

app.get('/api/auth/user', requireAuth, (req, res) => {
    res.json(serializeUser(req.user));
});

app.post('/api/auth/logout', (req, res) => {
    const tokens = new Set();
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) tokens.add(authHeader.slice(7).trim());
    if (req.cookies && req.cookies['laravel_session']) tokens.add(req.cookies['laravel_session']);

    for (const t of tokens) {
        db.sqlite.prepare('DELETE FROM sessions WHERE token = ?').run(t);
    }
    if (req.user) {
        db.insertAuditLog({ user: req.user, action: 'LOGOUT', details: 'User logged out', ip: req.ip });
    }
    const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
    res.clearCookie('XSRF-TOKEN', { path: '/', sameSite: 'lax', secure: isSecure });
    res.clearCookie('laravel_session', { path: '/', sameSite: 'lax', secure: isSecure });
    res.json({ success: true, message: 'Logged out successfully' });
});

app.post(['/api/auth/forgot-password', '/api/auth/portal/:tenantSlug/forgot-password'], (req, res) => {
    const { email } = req.body || {};
    if (email && typeof email === 'string') {
        const cleanEmail = email.trim().toLowerCase();
        const userRow = db.sqlite.prepare('SELECT * FROM users WHERE LOWER(email) = ? LIMIT 1').get(cleanEmail);
        if (userRow) {
            const user = db.mapUserRow(userRow);
            const resetToken = crypto.randomBytes(32).toString('hex');
            passwordResetTokens.set(resetToken, {
                userId: user.id,
                email: cleanEmail,
                expiresAt: Date.now() + 15 * 60 * 1000
            });
            db.insertAuditLog({ user, action: 'PASSWORD_RESET_REQUESTED', details: `Password reset requested`, ip: req.ip });
        }
    }
    res.json({
        success: true,
        message: 'If that email address is in our system, a password reset link has been generated.'
    });
});

app.post(['/api/auth/reset-password', '/api/auth/portal/:tenantSlug/reset-password'], async (req, res) => {
    const { token, password, password_confirmation } = req.body || {};
    if (!token || !passwordResetTokens.has(token)) {
        return res.status(400).json({ success: false, message: 'Invalid or expired password reset link.' });
    }
    const tokenData = passwordResetTokens.get(token);
    if (Date.now() > tokenData.expiresAt) {
        passwordResetTokens.delete(token);
        return res.status(400).json({ success: false, message: 'Reset link has expired. Please request a new one.' });
    }
    if (password_confirmation !== undefined && password !== password_confirmation) {
        return res.status(422).json({ success: false, message: 'Password confirmation does not match.' });
    }
    if (!isStrongPassword(password)) {
        return res.status(422).json({ success: false, message: 'Password must be at least 8 characters long and contain uppercase, lowercase, and numeric characters.' });
    }

    const userRow = db.sqlite.prepare('SELECT * FROM users WHERE id = ?').get(tokenData.userId);
    if (!userRow) return res.status(404).json({ success: false, message: 'User not found.' });

    const { hash, salt } = await hashPasswordAsync(password);
    db.runTransaction(() => {
        db.sqlite.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?').run(hash, salt, userRow.id);
        db.sqlite.prepare('DELETE FROM sessions WHERE user_id = ?').run(userRow.id);
    });
    passwordResetTokens.delete(token);

    db.insertAuditLog({ user: db.mapUserRow(userRow), action: 'PASSWORD_RESET_SUCCESS', details: 'Password reset via token and sessions revoked', ip: req.ip });
    res.json({ success: true, message: 'Password has been reset successfully. You may now log in.' });
});

app.post(['/api/auth/accept-invitation', '/api/auth/portal/:tenantSlug/accept-invitation'], async (req, res) => {
    const { token, password, password_confirmation } = req.body || {};
    if (!token || !invitationTokens.has(token)) {
        return res.status(400).json({ success: false, message: 'Invalid or expired invitation token.' });
    }
    const inv = invitationTokens.get(token);
    if (Date.now() > inv.expiresAt) {
        invitationTokens.delete(token);
        return res.status(400).json({ success: false, message: 'Invitation token has expired.' });
    }
    if (password_confirmation !== undefined && password !== password_confirmation) {
        return res.status(422).json({ success: false, message: 'Password confirmation does not match.' });
    }
    if (!isStrongPassword(password)) {
        return res.status(422).json({ success: false, message: 'Password must be at least 8 characters long with uppercase, lowercase, and numeric characters.' });
    }
    const { hash, salt } = await hashPasswordAsync(password);
    db.sqlite.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?').run(hash, salt, inv.userId);
    invitationTokens.delete(token);
    res.json({ success: true, message: 'Your invitation has been accepted successfully! You may now sign in.' });
});

app.post('/api/auth/user/change-password', requireAuth, async (req, res) => {
    const { current_password, new_password } = req.body || {};
    if (!current_password || typeof current_password !== 'string') {
        return res.status(400).json({ success: false, message: 'Current password is required.' });
    }
    const valid = await verifyPasswordAsync(current_password, req.user.password_hash, req.user.password_salt);
    if (!valid) {
        return res.status(400).json({ success: false, message: 'Current password does not match.' });
    }
    if (!isStrongPassword(new_password)) {
        return res.status(422).json({ success: false, message: 'New password must be at least 8 characters and include uppercase, lowercase, and numbers.' });
    }

    const { hash, salt } = await hashPasswordAsync(new_password);
    db.runTransaction(() => {
        db.sqlite.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?').run(hash, salt, req.user.id);
        db.sqlite.prepare('DELETE FROM sessions WHERE user_id = ? AND token != ?').run(req.user.id, req.authToken || '');
    });
    db.insertAuditLog({ user: req.user, action: 'PASSWORD_CHANGED', details: 'User changed password; other sessions revoked', ip: req.ip });
    res.json({ success: true, message: 'Password updated successfully' });
});

app.all('/api/auth/user/locale', requireAuth, (req, res) => {
    res.json({ success: true, message: 'Locale updated successfully' });
});

// ==========================================
// PROFILE ENDPOINTS (STRICTLY req.user)
// ==========================================
function buildProfilePayload(user) {
    return {
        id: user.id,
        name: user.name,
        username: user.username,
        email: user.email,
        phone: user.phone,
        role: user.role_slug,
        role_slug: user.role_slug,
        client_id: user.client_id,
        see_only_own_uploads: Boolean(user.see_only_own_uploads),
        status: user.status,
        profile_pic_url: user.profile_pic_url,
        company_name: user.client?.name || 'VelourCare Orthodontics HQ',
        timezone: 'Asia/Dubai (UTC+4)'
    };
}

app.get('/api/profile', requireAuth, (req, res) => {
    res.json({ data: buildProfilePayload(req.user) });
});

app.all('/api/profile', requireAuth, (req, res) => {
    const body = req.body || {};
    const updates = {};
    if (typeof body.first_name === 'string') updates.first_name = sanitizeText(body.first_name.trim()).slice(0, 80);
    if (typeof body.last_name === 'string') updates.last_name = sanitizeText(body.last_name.trim()).slice(0, 80);
    if (typeof body.name === 'string') updates.name = sanitizeText(body.name.trim()).slice(0, 120);
    if (typeof body.phone === 'string') updates.phone = sanitizeText(body.phone.trim()).slice(0, 40);
    if (typeof body.gender === 'string' && ['male', 'female', 'other'].includes(body.gender.toLowerCase())) {
        updates.gender = body.gender.toLowerCase();
    }

    const first = updates.first_name ?? req.user.first_name;
    const last = updates.last_name ?? req.user.last_name;
    const fullName = updates.name || ((first || '') + ' ' + (last || '')).trim() || req.user.name;

    db.sqlite.prepare(`
        UPDATE users SET name = ?, full_name = ?, first_name = ?, last_name = ?, phone = ?, gender = ? WHERE id = ?
    `).run(fullName, fullName, first, last, updates.phone ?? req.user.phone, updates.gender ?? req.user.gender, req.user.id);

    const refreshed = db.mapUserRow(db.sqlite.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id));
    db.insertAuditLog({ user: refreshed, action: 'PROFILE_UPDATED', details: 'User updated personal profile details', ip: req.ip });
    res.json({ success: true, message: 'Profile updated successfully', data: serializeUser(refreshed) });
});

// ==========================================
// 2. PERMISSIONS & ROLES
// ==========================================
const ALL_PERMS_META = ALL_PERMISSION_NAMES.map((name, idx) => {
    const group = name.includes('user') ? 'users' :
        name.includes('sub_client') ? 'sub-clients' :
        name.includes('client') && !name.includes('api') ? 'clients' :
        name.includes('vendor') ? 'vendors' :
        name.includes('case') ? 'cases' :
        name.includes('treatment') ? 'treatment-plans' :
        name.includes('invoice') ? 'invoices' :
        name.includes('role') ? 'roles' :
        name.includes('bank') ? 'banking' : 'settings';
    return {
        id: idx + 1,
        name,
        display_name: name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
        group
    };
});

function groupPermissions(list) {
    const grouped = {};
    for (const p of list) {
        if (!grouped[p.group]) grouped[p.group] = [];
        grouped[p.group].push(p);
    }
    return grouped;
}

app.get('/api/permissions/current-user', requireAuth, (req, res) => {
    const role = getUserRole(req.user);
    if (role === 'super-admin' || role === 'admin') {
        return res.json({ data: groupPermissions(ALL_PERMS_META) });
    }
    const matrix = PERMISSION_MATRIX[role] || PERMISSION_MATRIX['none'];
    const roleDefaultAllowed = new Set();
    if (matrix.view_all_cases !== 'N') roleDefaultAllowed.add('view_cases').add('view_case_activities').add('view_treatment_plans');
    if (matrix.create_edit_case !== 'N') roleDefaultAllowed.add('create_cases');
    if (matrix.approve_treatment_plan !== 'N') roleDefaultAllowed.add('edit_treatment_plans').add('view_treatment_plan_reviews');
    if (matrix.view_invoices !== 'N') roleDefaultAllowed.add('view_invoices');
    if (matrix.create_edit_invoices !== 'N') roleDefaultAllowed.add('create_invoices');
    if (matrix.export_data !== 'N') roleDefaultAllowed.add('export_invoices');

    const userPermsSet = new Set(Array.isArray(req.user.permissions) ? req.user.permissions : []);
    const effective = ALL_PERMS_META.filter(p => roleDefaultAllowed.has(p.name) || (userPermsSet.has(p.name) && role !== 'none' && !p.name.includes('manage_') && !p.name.includes('delete_')));
    res.json({ data: groupPermissions(effective) });
});

app.get('/api/permissions', requirePermission('manage_users_roles'), (req, res) => {
    res.json({ data: groupPermissions(ALL_PERMS_META) });
});

app.get('/api/permissions/:id/role', requirePermission('manage_users_roles'), (req, res) => {
    const roleRow = db.sqlite.prepare('SELECT * FROM roles WHERE id = ?').get(parseInt(req.params.id, 10));
    if (!roleRow) return res.status(404).json({ message: 'Role not found' });
    const permNames = db.parseJson(roleRow.permissions_json, []);
    const perms = ALL_PERMS_META.filter(p => permNames.includes(p.name));
    res.json({ data: perms, permissions: perms });
});

app.post('/api/permissions/:id/role', requirePermission('manage_users_roles'), (req, res) => {
    const roleId = parseInt(req.params.id, 10);
    const roleRow = db.sqlite.prepare('SELECT * FROM roles WHERE id = ?').get(roleId);
    if (!roleRow) return res.status(404).json({ message: 'Role not found' });
    const permIds = Array.isArray(req.body?.permissions) ? req.body.permissions : [];
    const selected = permIds.map(pid => ALL_PERMS_META.find(p => p.id === pid || p.name === pid)).filter(Boolean).map(p => p.name);
    db.sqlite.prepare('UPDATE roles SET permissions_json = ? WHERE id = ?').run(JSON.stringify(selected), roleId);
    res.json({ success: true, message: 'Role permissions saved successfully' });
});

app.get('/api/permissions/:id/user', requirePermission('manage_users_roles'), (req, res) => {
    const userRow = db.sqlite.prepare('SELECT * FROM users WHERE id = ?').get(parseInt(req.params.id, 10));
    if (!userRow) return res.status(404).json({ message: 'User not found.' });
    const user = db.mapUserRow(userRow);
    const userPerms = (user.permissions || []).map(pName => ALL_PERMS_META.find(p => p.name === pName)).filter(Boolean);
    res.json({ data: userPerms });
});

app.post('/api/permissions/:id/user', requirePermission('manage_users_roles'), (req, res) => {
    const userId = parseInt(req.params.id, 10);
    const userRow = db.sqlite.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!userRow) return res.status(404).json({ message: 'User not found.' });
    if (Array.isArray(req.body?.permissions)) {
        const selected = req.body.permissions
            .map(pid => ALL_PERMS_META.find(p => p.id === pid || p.name === pid))
            .filter(Boolean)
            .map(p => p.name);
        db.sqlite.prepare('UPDATE users SET permissions_json = ? WHERE id = ?').run(JSON.stringify(selected), userId);
        db.insertAuditLog({ user: req.user, action: 'USER_PERMISSIONS_UPDATED', resourceType: 'user', resourceId: userId, details: `Updated permissions for user ${userId}`, ip: req.ip });
    }
    res.json({ success: true, message: 'User permissions updated successfully' });
});

app.get('/api/roles/:id', requirePermission('manage_users_roles'), (req, res) => {
    const roleRow = db.sqlite.prepare('SELECT * FROM roles WHERE id = ?').get(parseInt(req.params.id, 10));
    if (!roleRow) return res.status(404).json({ message: `Role #${req.params.id} not found.` });
    const perms = db.parseJson(roleRow.permissions_json, []).map(n => ALL_PERMS_META.find(p => p.name === n)).filter(Boolean);
    res.json({
        data: {
            id: roleRow.id,
            name: roleRow.name,
            label: roleRow.label || roleRow.name,
            permissions: perms,
            permissions_count: perms.length,
            created_at: roleRow.created_at
        }
    });
});

app.get('/api/roles', requirePermission('manage_users_roles'), (req, res) => {
    const { page, perPage, offset } = paginateParams(req.query);
    const total = db.sqlite.prepare('SELECT COUNT(*) AS cnt FROM roles').get().cnt;
    const rows = db.sqlite.prepare('SELECT * FROM roles ORDER BY id ASC LIMIT ? OFFSET ?').all(perPage, offset);
    const data = rows.map(r => {
        const perms = db.parseJson(r.permissions_json, []);
        return {
            id: r.id,
            name: r.name,
            label: r.label || r.name,
            users_count: db.sqlite.prepare('SELECT COUNT(*) AS cnt FROM users WHERE role_slug = ?').get(r.name).cnt,
            permissions_count: perms.length,
            created_at: r.created_at
        };
    });
    const lastPage = Math.max(1, Math.ceil(total / perPage));
    res.json({ data, current_page: page, last_page: lastPage, per_page: perPage, total });
});

app.post('/api/roles', requirePermission('manage_users_roles'), (req, res) => {
    const rawName = String(req.body?.name || '').trim();
    if (!rawName) return res.status(400).json({ success: false, message: 'Role name is required.' });
    const slug = rawName.toLowerCase().replace(/[^a-z0-9-]+/g, '-');
    const perms = Array.isArray(req.body?.permissions) ? req.body.permissions : [];
    const createdAt = formatClinicDate();
    try {
        const result = db.sqlite.prepare('INSERT INTO roles (name, label, permissions_json, created_at) VALUES (?, ?, ?, ?)').run(slug, sanitizeText(rawName), JSON.stringify(perms), createdAt);
        const newId = Number(result.lastInsertRowid);
        db.insertAuditLog({ user: req.user, action: 'ROLE_CREATED', resourceType: 'role', resourceId: newId, details: `Created role ${slug}`, ip: req.ip });
        res.status(201).json({ success: true, message: 'Role created successfully', data: { id: newId, name: slug, label: sanitizeText(rawName), permissions: perms, permissions_count: perms.length, created_at: createdAt } });
    } catch (e) {
        return res.status(409).json({ success: false, message: 'Role already exists.' });
    }
});

app.put('/api/roles/:id', requirePermission('manage_users_roles'), (req, res) => {
    const roleId = parseInt(req.params.id, 10);
    const existing = db.sqlite.prepare('SELECT * FROM roles WHERE id = ?').get(roleId);
    if (!existing) return res.status(404).json({ message: 'Role not found' });
    const name = req.body?.name ? String(req.body.name).toLowerCase().replace(/[^a-z0-9-]+/g, '-') : existing.name;
    const label = req.body?.name ? sanitizeText(String(req.body.name)) : existing.label;
    const perms = Array.isArray(req.body?.permissions) ? req.body.permissions : db.parseJson(existing.permissions_json, []);
    db.sqlite.prepare('UPDATE roles SET name = ?, label = ?, permissions_json = ? WHERE id = ?').run(name, label, JSON.stringify(perms), roleId);
    res.json({ success: true, message: 'Role updated successfully', data: { id: roleId, name, label, permissions: perms } });
});

app.delete('/api/roles/:id', requirePermission('manage_users_roles'), (req, res) => {
    const roleId = parseInt(req.params.id, 10);
    const info = db.sqlite.prepare('DELETE FROM roles WHERE id = ?').run(roleId);
    if (!info.changes) return res.status(404).json({ message: 'Role not found' });
    res.json({ success: true, message: 'Role deleted successfully' });
});

// ==========================================
// 3. USERS MANAGEMENT (ADMIN ONLY)
// ==========================================
const USER_FILTER_OPTIONS = {
    roles: {
        'super-admin': 'Super Admin', 'admin': 'Admin', 'case-coordinator': 'Case Coordinator',
        'planner': 'CAD Planner', 'client': 'Client / Doctor', 'sub-client': 'Sub Client', 'vendor': 'Vendor / Lab'
    },
    genders: { male: 'Male', female: 'Female', other: 'Other' },
    statuses: { active: 'Active', inactive: 'Inactive', pending: 'Pending', suspended: 'Suspended' }
};

app.get('/api/users/filter-options', requirePermission('manage_users_roles'), (req, res) => {
    res.json({ data: USER_FILTER_OPTIONS });
});

app.get('/api/users', requirePermission('manage_users_roles'), (req, res) => {
    const { page, perPage, offset } = paginateParams(req.query);
    const total = db.sqlite.prepare('SELECT COUNT(*) AS cnt FROM users').get().cnt;
    const rows = db.sqlite.prepare('SELECT * FROM users ORDER BY id ASC LIMIT ? OFFSET ?').all(perPage, offset);
    const mappedUsers = rows.map(r => {
        const u = serializeUser(db.mapUserRow(r));
        return {
            ...u,
            role: {
                id: u.role_slug === 'super-admin' ? 1 : (u.role_slug === 'admin' ? 2 : 5),
                name: u.role_slug,
                label: (u.role_slug || 'none').replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
            }
        };
    });
    const lastPage = Math.max(1, Math.ceil(total / perPage));
    res.json({
        data: mappedUsers,
        current_page: page,
        last_page: lastPage,
        per_page: perPage,
        total,
        meta: { current_page: page, last_page: lastPage, per_page: perPage, total },
        additional: { filter_options: USER_FILTER_OPTIONS }
    });
});

app.get('/api/users/:id', requirePermission('manage_users_roles'), (req, res) => {
    const row = db.sqlite.prepare('SELECT * FROM users WHERE id = ?').get(parseInt(req.params.id, 10));
    if (!row) return res.status(404).json({ message: `User #${req.params.id} not found.` });
    const u = serializeUser(db.mapUserRow(row));
    const userPerms = (u.permissions || []).map(pName => ALL_PERMS_META.find(p => p.name === pName)).filter(Boolean);
    res.json({
        data: {
            ...u,
            role: {
                id: u.role_slug === 'super-admin' ? 1 : 2,
                name: u.role_slug,
                label: (u.role_slug || 'none').replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
                permissions: userPerms
            },
            permissions: userPerms
        }
    });
});

app.post('/api/users', requirePermission('manage_users_roles'), async (req, res) => {
    const body = req.body || {};
    const username = String(body.username || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const password = body.password;
    if (!username || !email) {
        return res.status(400).json({ success: false, message: 'Username and email are required.' });
    }
    if (!isStrongPassword(password)) {
        return res.status(422).json({ success: false, message: 'A strong password (>=8 chars, uppercase, lowercase, number) is required.' });
    }

    const firstName = sanitizeText(String(body.first_name || 'New').trim());
    const lastName = sanitizeText(String(body.last_name || 'User').trim());
    const fullName = `${firstName} ${lastName}`.trim();
    const roleSlug = PERMISSION_MATRIX[body.role || body.role_slug] ? (body.role || body.role_slug) : 'none';
    const gender = ['male', 'female', 'other'].includes(String(body.gender || '').toLowerCase()) ? String(body.gender).toLowerCase() : 'other';
    const clientId = body.client_id ? parseInt(body.client_id, 10) : null;
    const seeOnlyOwn = body.see_only_own_uploads ? 1 : 0;

    const matrixPerms = Object.entries(PERMISSION_MATRIX[roleSlug] || {}).filter(([, v]) => v !== 'N').map(([k]) => k);
    const { hash, salt } = await hashPasswordAsync(password);
    const statusJson = JSON.stringify({ label: 'Active', value: 'active', color: 'success' });

    try {
        const result = db.sqlite.prepare(`
            INSERT INTO users (name, full_name, first_name, last_name, username, email, phone, role_slug, gender, is_super_admin, client_id, see_only_own_uploads, status_value, status_json, profile_pic_url, password_hash, password_salt, permissions_json, integrations_json, extra_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, '/assets/velourcare-square.png', ?, ?, ?, '{}', '{}', ?)
        `).run(
            fullName, fullName, firstName, lastName, username, email,
            sanitizeText(String(body.phone || '+971 4 000 0000')),
            roleSlug, gender, roleSlug === 'super-admin' ? 1 : 0,
            clientId, seeOnlyOwn, statusJson, hash, salt,
            JSON.stringify(matrixPerms), formatClinicDateTime()
        );
        const created = db.mapUserRow(db.sqlite.prepare('SELECT * FROM users WHERE id = ?').get(Number(result.lastInsertRowid)));
        db.insertAuditLog({ user: req.user, action: 'USER_CREATED', resourceType: 'user', resourceId: created.id, details: `Created user ${username} (${roleSlug})`, ip: req.ip });
        res.status(201).json({ success: true, message: 'User created successfully', data: serializeUser(created) });
    } catch (e) {
        return res.status(409).json({ success: false, message: 'Username or email already exists.' });
    }
});

app.put('/api/users/:id', requirePermission('manage_users_roles'), (req, res) => {
    const userId = parseInt(req.params.id, 10);
    const existing = db.sqlite.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!existing) return res.status(404).json({ success: false, message: 'User not found' });

    const body = req.body || {};
    const first = body.first_name !== undefined ? sanitizeText(String(body.first_name)) : existing.first_name;
    const last = body.last_name !== undefined ? sanitizeText(String(body.last_name)) : existing.last_name;
    const fullName = body.name ? sanitizeText(String(body.name)) : `${first || ''} ${last || ''}`.trim();
    const phone = body.phone !== undefined ? sanitizeText(String(body.phone)) : existing.phone;
    const roleSlug = body.role_slug && PERMISSION_MATRIX[body.role_slug] ? body.role_slug : existing.role_slug;
    const clientId = body.client_id !== undefined ? (body.client_id ? parseInt(body.client_id, 10) : null) : existing.client_id;
    const seeOwn = body.see_only_own_uploads !== undefined ? (body.see_only_own_uploads ? 1 : 0) : existing.see_only_own_uploads;

    db.sqlite.prepare(`
        UPDATE users SET name = ?, full_name = ?, first_name = ?, last_name = ?, phone = ?, role_slug = ?, client_id = ?, see_only_own_uploads = ? WHERE id = ?
    `).run(fullName, fullName, first, last, phone, roleSlug, clientId, seeOwn, userId);

    const updated = db.mapUserRow(db.sqlite.prepare('SELECT * FROM users WHERE id = ?').get(userId));
    db.insertAuditLog({ user: req.user, action: 'USER_UPDATED', resourceType: 'user', resourceId: userId, details: `Updated user ${userId}`, ip: req.ip });
    res.json({ success: true, message: 'User updated successfully', data: serializeUser(updated) });
});

app.delete('/api/users/:id', requirePermission('manage_users_roles'), (req, res) => {
    const userId = parseInt(req.params.id, 10);
    if (userId === req.user.id) {
        return res.status(400).json({ success: false, message: 'Cannot delete your own active admin account.' });
    }
    const existing = db.sqlite.prepare('SELECT id FROM users WHERE id = ?').get(userId);
    if (!existing) return res.status(404).json({ success: false, message: 'User not found' });
    db.runTransaction(() => {
        db.sqlite.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
        db.sqlite.prepare('DELETE FROM users WHERE id = ?').run(userId);
    });
    db.insertAuditLog({ user: req.user, action: 'USER_DELETED', resourceType: 'user', resourceId: userId, details: `Deleted user ${userId}`, ip: req.ip });
    res.json({ success: true, message: 'User deleted successfully' });
});

app.post('/api/users/:id/update-role', requirePermission('manage_users_roles'), (req, res) => {
    const userId = parseInt(req.params.id, 10);
    const existing = db.sqlite.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!existing) return res.status(404).json({ success: false, message: 'User not found' });
    const newRole = req.body?.role;
    if (!newRole || !PERMISSION_MATRIX[newRole]) {
        return res.status(400).json({ success: false, message: 'Invalid role specified.' });
    }
    db.sqlite.prepare('UPDATE users SET role_slug = ?, is_super_admin = ? WHERE id = ?').run(newRole, newRole === 'super-admin' ? 1 : 0, userId);
    const updated = db.mapUserRow(db.sqlite.prepare('SELECT * FROM users WHERE id = ?').get(userId));
    db.insertAuditLog({ user: req.user, action: 'USER_ROLE_CHANGED', resourceType: 'user', resourceId: userId, details: `Changed user ${userId} role to ${newRole}`, ip: req.ip });
    res.json({ success: true, message: 'User role updated successfully', data: serializeUser(updated) });
});

app.patch('/api/users/:id/update-status', requirePermission('manage_users_roles'), (req, res) => {
    const userId = parseInt(req.params.id, 10);
    const existing = db.sqlite.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!existing) return res.status(404).json({ success: false, message: 'User not found' });
    const val = String(req.body?.status || '').trim().toLowerCase();
    if (!['active', 'inactive', 'pending', 'suspended', 'disabled'].includes(val)) {
        return res.status(400).json({ success: false, message: 'Invalid status value.' });
    }
    const statusObj = {
        label: val.replace(/\b\w/g, l => l.toUpperCase()),
        value: val,
        color: val === 'active' ? 'success' : 'secondary'
    };
    db.runTransaction(() => {
        db.sqlite.prepare('UPDATE users SET status_value = ?, status_json = ? WHERE id = ?').run(val, JSON.stringify(statusObj), userId);
        if (['inactive', 'disabled', 'suspended'].includes(val)) {
            db.sqlite.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
        }
    });
    if (['inactive', 'disabled', 'suspended'].includes(val)) {
        db.insertAuditLog({ user: req.user, action: 'USER_DEACTIVATED', resourceType: 'user', resourceId: userId, details: `Deactivated user ${userId} and terminated active sessions`, ip: req.ip });
    }
    const updated = db.mapUserRow(db.sqlite.prepare('SELECT * FROM users WHERE id = ?').get(userId));
    res.json({ success: true, message: 'User status updated', data: serializeUser(updated) });
});

app.post('/api/users/:id/send-reset-password-request', requirePermission('manage_users_roles'), (req, res) => {
    const userId = parseInt(req.params.id, 10);
    const userRow = db.sqlite.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!userRow) return res.status(404).json({ message: 'User not found.' });
    const resetToken = crypto.randomBytes(32).toString('hex');
    passwordResetTokens.set(resetToken, { userId, email: userRow.email, expiresAt: Date.now() + 15 * 60 * 1000 });
    db.insertAuditLog({ user: req.user, action: 'ADMIN_PASSWORD_RESET_ISSUED', resourceType: 'user', resourceId: userId, details: `Issued reset request for user ${userId}`, ip: req.ip });
    res.json({ success: true, message: 'Password reset link sent successfully' });
});

app.patch('/api/users/:id/change-password', requirePermission('manage_users_roles'), async (req, res) => {
    const userId = parseInt(req.params.id, 10);
    const userRow = db.sqlite.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!userRow) return res.status(404).json({ message: 'User not found.' });
    const newPassword = req.body?.password || req.body?.new_password;
    if (!isStrongPassword(newPassword)) {
        return res.status(422).json({ success: false, message: 'Password must be >= 8 characters with uppercase, lowercase, and numbers.' });
    }
    const { hash, salt } = await hashPasswordAsync(newPassword);
    db.runTransaction(() => {
        db.sqlite.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?').run(hash, salt, userId);
        db.sqlite.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
    });
    db.insertAuditLog({ user: req.user, action: 'ADMIN_CHANGED_USER_PASSWORD', resourceType: 'user', resourceId: userId, details: `Admin changed password for user ${userId}`, ip: req.ip });
    res.json({ success: true, message: 'Password changed successfully' });
});

app.post('/api/users/:id/smile-inspector', requirePermission('manage_users_roles'), (req, res) => {
    res.json({ success: true, message: 'User synced to SmileInspector successfully', siUserUid: 'si_usr_' + Date.now() });
});

// ==========================================
// 4. DASHBOARD STATISTICS (SCOPED BY USER/ROLE)
// ==========================================
app.get('/api/dashboard/statistics', requireAuth, (req, res) => {
    const role = getUserRole(req.user);
    const scope = buildCaseScopeSql(req.user);
    let caseCounts = { total_cases: 0, total_refinements: 0, total_retainers: 0, newly_created: 0, in_planning: 0, in_manufacturing: 0, step_files_ready: 0, treatment_plan_approved: 0, case_completed: 0 };
    if (!scope.empty) {
        const rows = db.sqlite.prepare(`SELECT status_value, category, COUNT(*) AS cnt FROM cases WHERE ${scope.sql} GROUP BY status_value, category`).all(...scope.params);
        for (const r of rows) {
            caseCounts.total_cases += r.cnt;
            if (r.category === 'Refinements') caseCounts.total_refinements += r.cnt;
            if (r.category === 'Retainers') caseCounts.total_retainers += r.cnt;
            if (r.status_value === 'newly-created') caseCounts.newly_created += r.cnt;
            if (r.status_value === 'in-planning') caseCounts.in_planning += r.cnt;
            if (r.status_value === 'in-manufacturing') caseCounts.in_manufacturing += r.cnt;
            if (r.status_value === 'plan-step-files-ready') caseCounts.step_files_ready += r.cnt;
            if (r.status_value === 'plan-approved') caseCounts.treatment_plan_approved += r.cnt;
            if (r.status_value === 'completed') caseCounts.case_completed += r.cnt;
        }
    }

    const isAdmin = role === 'super-admin' || role === 'admin';
    const canSeeRevenue = isAdmin || role === 'accounts';
    let revenueTotal = 0;
    if (canSeeRevenue) {
        const sumFils = db.sqlite.prepare("SELECT COALESCE(SUM(total_fils), 0) AS tot FROM invoices WHERE document_status != 'cancelled'").get().tot;
        revenueTotal = sumFils / 100;
    }

    res.json({
        data: {
            cases: caseCounts,
            clients: isAdmin ? { total: db.sqlite.prepare('SELECT COUNT(*) AS cnt FROM clients').get().cnt } : undefined,
            users: isAdmin ? { total: db.sqlite.prepare('SELECT COUNT(*) AS cnt FROM users').get().cnt } : undefined,
            revenue: canSeeRevenue ? { monthly: revenueTotal, currency: 'AED' } : undefined
        }
    });
});

// ==========================================
// 5. CASES MANAGEMENT
// ==========================================
function getCasesFilterOptionsPayload(user) {
    const settings = db.getPortalSettingsObj();
    const role = getUserRole(user);
    const allClients = settings.clients || [];
    const scopedClients = (role === 'client')
        ? allClients.filter(c => Number(c.id) === Number(user.client_id))
        : (role === 'accounts' || role === 'none' ? [] : allClients);

    const clientsList = scopedClients.map(c => ({
        id: c.id,
        name: c.name,
        case_id_prefix: c.case_id_prefix || 'VELOUR',
        is_express_delivery_active: c.is_express_delivery_active || 'YES',
        is_alphanumeric_case_id_active: c.is_alphanumeric_case_id_active || 'YES',
        sub_clients: c.sub_clients || [],
        addresses: c.addresses || [],
        shipment_addresses: c.addresses || []
    }));

    const doctorsSql = role === 'client'
        ? "SELECT id, name, client_id FROM users WHERE role_slug = 'client' AND client_id = ?"
        : "SELECT id, name, client_id FROM users WHERE role_slug = 'client'";
    const doctors = (role === 'accounts' || role === 'none')
        ? []
        : (role === 'client' ? db.sqlite.prepare(doctorsSql).all(Number(user.client_id)) : db.sqlite.prepare(doctorsSql).all()).map(db.plain);

    return {
        clients: clientsList,
        residencyTypes: settings.residencyTypes || {},
        categories: settings.caseCategories || {},
        categoryTypes: settings.caseCategoryTypes || {},
        deliveryTimes: settings.deliveryTimes || {},
        jawArchTypes: settings.jawArchTypes || {},
        jawArchCorrections: settings.jawArchCorrections || {},
        jawToothFormats: settings.jawToothFormats || {},
        statuses: {
            'newly-created': 'Newly Created',
            'clinical-review': 'Awaiting Doctor Input',
            'in-planning': 'In Planning',
            'review-treatment-plan': 'Review Treatment Plan',
            'plan-approved': 'Plan Approved',
            'plan-step-files-ready': 'Step Files Ready',
            'in-manufacturing': 'In Manufacturing',
            'completed': 'Completed'
        },
        doctors
    };
}

function extractCasesQueryParams(query = {}) {
    const params = {
        searchAll: '', searchCaseId: '', searchDoctor: '', searchPatientName: '', searchPatientEmail: '',
        status: null, clientId: null, category: null, categoryType: null,
        periodStart: null, periodEnd: null, sortField: 'id', sortDirection: 'asc', myCasesOnly: false
    };

    if (query['search[all]'] !== undefined) params.searchAll = String(query['search[all]']).trim().toLowerCase();
    else if (query.search?.all !== undefined) params.searchAll = String(query.search.all).trim().toLowerCase();
    else if (query.searchQuery !== undefined) params.searchAll = String(query.searchQuery).trim().toLowerCase();
    else if (query.q !== undefined) params.searchAll = String(query.q).trim().toLowerCase();

    if (query['search[case_id]']) params.searchCaseId = String(query['search[case_id]']).trim().toLowerCase();
    else if (query.search?.case_id) params.searchCaseId = String(query.search.case_id).trim().toLowerCase();

    if (query['search[case_doctor]']) params.searchDoctor = String(query['search[case_doctor]']).trim().toLowerCase();
    else if (query.search?.case_doctor) params.searchDoctor = String(query.search.case_doctor).trim().toLowerCase();

    if (query['search[patient_name]']) params.searchPatientName = String(query['search[patient_name]']).trim().toLowerCase();
    else if (query.search?.patient_name) params.searchPatientName = String(query.search.patient_name).trim().toLowerCase();

    if (query['search[patient_email]']) params.searchPatientEmail = String(query['search[patient_email]']).trim().toLowerCase();
    else if (query.search?.patient_email) params.searchPatientEmail = String(query.search.patient_email).trim().toLowerCase();

    const rawStatus = query.status ?? query['filters[status]'] ?? query.filters?.status;
    if (rawStatus && !['all', 'null', 'undefined', ''].includes(String(rawStatus).trim())) {
        params.status = String(rawStatus).trim();
    }

    const rawClient = query.client_id ?? query['filters[client_id]'] ?? query.filters?.client_id;
    if (rawClient && !['all', 'null'].includes(String(rawClient))) {
        params.clientId = Number(rawClient);
    }

    const rawCategory = query.category ?? query['filters[category]'] ?? query.filters?.category;
    if (rawCategory && !['all', 'null'].includes(String(rawCategory))) {
        params.category = String(rawCategory).trim();
    }

    const rawCatType = query.category_type ?? query['filters[category_type]'] ?? query['filters[case_category_type]'] ?? query.filters?.category_type ?? query.filters?.case_category_type;
    if (rawCatType && !['all', 'null'].includes(String(rawCatType))) {
        params.categoryType = String(rawCatType).trim();
    }

    const rawStart = query.period_start ?? query['filters[period_start]'] ?? query.filters?.period_start;
    if (rawStart) params.periodStart = String(rawStart).trim();

    const rawEnd = query.period_end ?? query['filters[period_end]'] ?? query.filters?.period_end;
    if (rawEnd) params.periodEnd = String(rawEnd).trim();

    const rawDoctor = query.doctor ?? query['filters[doctor]'] ?? query.filters?.doctor;
    if (rawDoctor && !['all', 'null'].includes(String(rawDoctor))) {
        params.searchDoctor = String(rawDoctor).trim().toLowerCase();
    }

    if (query.my_cases_only === 'true' || query.my_cases_only === '1' || query['filters[my_cases_only]'] === 'true' || query.scope === 'personal') {
        params.myCasesOnly = true;
    }

    if (query['sort[field]']) params.sortField = String(query['sort[field]']);
    else if (query.sort?.field) params.sortField = String(query.sort.field);

    if (query['sort[direction]']) params.sortDirection = String(query['sort[direction]']).toLowerCase();
    else if (query.sort?.direction) params.sortDirection = String(query.sort.direction).toLowerCase();

    return params;
}

app.get('/api/cases', requireAuth, (req, res) => {
    const filterOptionsPayload = getCasesFilterOptionsPayload(req.user);
    const qParams = extractCasesQueryParams(req.query);
    const scope = buildCaseScopeSql(req.user, { applyMyCasesOnly: qParams.myCasesOnly });

    if (scope.empty) {
        return res.json({
            data: [], current_page: 1, last_page: 1, per_page: 20, total: 0,
            meta: { current_page: 1, last_page: 1, per_page: 20, total: 0 },
            additional: {
                status_capsule_counts: [
                    { value: null, label: 'All Cases', count: 0, color: 'primary' },
                    { value: 'newly-created', label: 'Newly Created', count: 0, color: 'secondary' },
                    { value: 'in-planning', label: 'In Planning', count: 0, color: 'info' },
                    { value: 'review-treatment-plan', label: 'Review Treatment Plan', count: 0, color: 'warning' },
                    { value: 'plan-approved', label: 'Plan Approved', count: 0, color: 'success' },
                    { value: 'in-manufacturing', label: 'In Manufacturing', count: 0, color: 'primary' },
                    { value: 'completed', label: 'Completed', count: 0, color: 'success' }
                ],
                filter_options: filterOptionsPayload,
                discussion_members: []
            }
        });
    }

    // Include archived only if super-admin/admin explicitly requests it
    let baseSql = scope.sql;
    if (req.query.include_archived && canUser(req.user, 'manage_users_roles')) {
        baseSql = baseSql.replace('is_archived = 0', '1=1');
    }

    // Status capsule counts in ONE grouped SQL pass before query filters
    const groupedCounts = db.sqlite.prepare(`SELECT status_value, COUNT(*) AS cnt FROM cases WHERE ${baseSql} GROUP BY status_value`).all(...scope.params);
    const countByStatus = {};
    let baseTotal = 0;
    for (const row of groupedCounts) {
        countByStatus[row.status_value] = row.cnt;
        baseTotal += row.cnt;
    }

    const statusCapsules = [
        { value: null, label: 'All Cases', count: baseTotal, color: 'primary' },
        { value: 'newly-created', label: 'Newly Created', count: countByStatus['newly-created'] || 0, color: 'secondary' },
        { value: 'in-planning', label: 'In Planning', count: countByStatus['in-planning'] || 0, color: 'info' },
        { value: 'review-treatment-plan', label: 'Review Treatment Plan', count: countByStatus['review-treatment-plan'] || 0, color: 'warning' },
        { value: 'plan-approved', label: 'Plan Approved', count: countByStatus['plan-approved'] || 0, color: 'success' },
        { value: 'in-manufacturing', label: 'In Manufacturing', count: countByStatus['in-manufacturing'] || 0, color: 'primary' },
        { value: 'completed', label: 'Completed', count: countByStatus['completed'] || 0, color: 'success' }
    ];

    const where = [baseSql];
    const params = [...scope.params];

    if (qParams.searchAll) {
        const pat = `%${escapeLike(qParams.searchAll)}%`;
        where.push("(LOWER(patient_name) LIKE ? ESCAPE '!' OR LOWER(COALESCE(patient_email,'')) LIKE ? ESCAPE '!' OR LOWER(case_id) LIKE ? ESCAPE '!' OR LOWER(COALESCE(doctor_name,'')) LIKE ? ESCAPE '!' OR LOWER(COALESCE(category,'')) LIKE ? ESCAPE '!')");
        params.push(pat, pat, pat, pat, pat);
    }
    if (qParams.searchCaseId) {
        where.push("LOWER(case_id) LIKE ? ESCAPE '!'");
        params.push(`%${escapeLike(qParams.searchCaseId)}%`);
    }
    if (qParams.searchPatientName) {
        where.push("LOWER(patient_name) LIKE ? ESCAPE '!'");
        params.push(`%${escapeLike(qParams.searchPatientName)}%`);
    }
    if (qParams.searchPatientEmail) {
        where.push("LOWER(COALESCE(patient_email,'')) LIKE ? ESCAPE '!'");
        params.push(`%${escapeLike(qParams.searchPatientEmail)}%`);
    }
    if (qParams.searchDoctor) {
        where.push("LOWER(COALESCE(doctor_name,'')) LIKE ? ESCAPE '!'");
        params.push(`%${escapeLike(qParams.searchDoctor)}%`);
    }
    if (qParams.status) {
        where.push('status_value = ?');
        params.push(qParams.status);
    }
    if (qParams.clientId && canUser(req.user, 'manage_users_roles')) {
        where.push('client_id = ?');
        params.push(qParams.clientId);
    }
    if (qParams.category) {
        where.push('LOWER(COALESCE(category,\'\')) = LOWER(?)');
        params.push(qParams.category);
    }
    if (qParams.categoryType) {
        where.push('LOWER(COALESCE(category_type,\'\')) = LOWER(?)');
        params.push(qParams.categoryType);
    }
    if (qParams.periodStart) {
        const startStr = qParams.periodStart.length === 10 ? `${qParams.periodStart} 00:00` : qParams.periodStart;
        where.push('created_at >= ?');
        params.push(startStr);
    }
    if (qParams.periodEnd) {
        const endStr = qParams.periodEnd.length === 10 ? `${qParams.periodEnd} 23:59` : qParams.periodEnd;
        where.push('created_at <= ?');
        params.push(endStr);
    }

    const SORT_MAP = {
        id: 'id',
        case_doctor: 'LOWER(COALESCE(doctor_name,\'\'))',
        doctor_name: 'LOWER(COALESCE(doctor_name,\'\'))',
        patient_name: 'LOWER(patient_name)',
        case_id: 'LOWER(case_id)',
        created_at: 'created_at',
        updated_at: 'updated_at',
        deadline: 'deadline'
    };
    const sortCol = SORT_MAP[qParams.sortField] || 'id';
    const sortDir = qParams.sortDirection === 'desc' ? 'DESC' : 'ASC';

    const { page, perPage, offset } = paginateParams(req.query, { defaultPerPage: 20, maxPerPage: 100 });
    const fullWhere = where.join(' AND ');
    const total = db.sqlite.prepare(`SELECT COUNT(*) AS cnt FROM cases WHERE ${fullWhere}`).get(...params).cnt;
    const rows = db.sqlite.prepare(`SELECT * FROM cases WHERE ${fullWhere} ORDER BY ${sortCol} ${sortDir}, id ${sortDir} LIMIT ? OFFSET ?`).all(...params, perPage, offset);

    const lastPage = Math.max(1, Math.ceil(total / perPage));
    const role = getUserRole(req.user);
    const membersSql = role === 'client'
        ? "SELECT id, name, role_slug, profile_pic_url FROM users WHERE (client_id = ? OR role_slug IN ('admin','super-admin','planner')) AND status_value = 'active'"
        : "SELECT id, name, role_slug, profile_pic_url FROM users WHERE status_value = 'active'";
    const discussionMembers = (role === 'client'
        ? db.sqlite.prepare(membersSql).all(Number(req.user.client_id))
        : db.sqlite.prepare(membersSql).all()
    ).map(db.plain);

    res.json({
        data: rows.map(db.mapCaseRow),
        current_page: page,
        last_page: lastPage,
        per_page: perPage,
        total,
        meta: { current_page: page, last_page: lastPage, per_page: perPage, total },
        additional: {
            status_capsule_counts: statusCapsules,
            filter_options: filterOptionsPayload,
            discussion_members: discussionMembers
        }
    });
});

app.get('/api/cases/filter-options', requireAuth, (req, res) => {
    const payload = getCasesFilterOptionsPayload(req.user);
    res.json({ data: payload, ...payload });
});

app.get('/api/cases/verify-case-id', requireAuth, (req, res) => {
    const caseId = String(req.query.case_id || '').trim();
    if (!caseId) return res.status(400).json({ valid: false, message: 'Case ID is required.' });
    const existing = db.sqlite.prepare('SELECT id FROM cases WHERE LOWER(case_id) = LOWER(?)').get(caseId);
    if (existing) return res.status(409).json({ valid: false, message: 'Case ID already exists.' });
    res.json({ valid: true, message: 'Case ID available' });
});

app.get('/api/cases/verify-parent-case', requireAuth, (req, res) => {
    const parentId = String(req.query.parent_case_id || '').trim();
    if (!parentId) return res.status(400).json({ valid: false, message: 'Parent Case ID is required.' });
    const scope = buildCaseScopeSql(req.user);
    if (scope.empty) return res.status(403).json({ valid: false });
    const found = db.sqlite.prepare(`SELECT case_id FROM cases WHERE LOWER(case_id) = LOWER(?) AND ${scope.sql}`).get(parentId, ...scope.params);
    if (!found) return res.status(404).json({ valid: false, message: 'Parent case not found.' });
    res.json({ valid: true, parent_case_id: found.case_id });
});

app.post('/api/cases/store-in-pipeline', requirePermission('create_cases', 'Forbidden: You do not have permission to create cases.'), upload.any(), (req, res) => {
    if (!validateRequestFiles(req, res)) return;
    const body = req.body || {};
    const rawPatientName = body.patient_name || body.patient?.name;
    if (!rawPatientName || typeof rawPatientName !== 'string' || !rawPatientName.trim()) {
        cleanupUploadedFiles(req);
        return res.status(400).json({ success: false, message: 'Patient name is required.' });
    }

    const patientName = sanitizeText(rawPatientName.trim());
    const patientAge = body.patient_age !== undefined ? parseInt(body.patient_age, 10) : (body.patient?.age !== undefined ? parseInt(body.patient.age, 10) : null);
    if (patientAge !== null && (!Number.isFinite(patientAge) || patientAge < 1 || patientAge > 120)) {
        cleanupUploadedFiles(req);
        return res.status(400).json({ success: false, message: 'Patient age must be between 1 and 120.' });
    }

    const role = getUserRole(req.user);
    const targetClientId = (role === 'client' || !body.client_id)
        ? Number(req.user.client_id || 1)
        : parseInt(body.client_id, 10);
    const clientRow = db.sqlite.prepare('SELECT id, name FROM clients WHERE id = ?').get(targetClientId);
    if (!clientRow) {
        cleanupUploadedFiles(req);
        return res.status(400).json({ success: false, message: 'Invalid clinic/client specified.' });
    }

    const nowStr = formatClinicDateTime();
    const patientGender = sanitizeText(String(body.patient_gender || body.patient?.gender || 'Unspecified'));
    const patientEmail = sanitizeText(String(body.patient_email || body.patient?.email || ''));
    const patientPhone = sanitizeText(String(body.patient_phone || body.phone || ''));
    const doctorName = sanitizeText(String(body.case_doctor || body.doctor_name || req.user.name));
    const chiefComplaint = sanitizeText(String(body.chief_complaint || ''));
    const malocclusion = sanitizeText(String(body.malocclusion || ''));
    const category = sanitizeText(String(body.category || 'New Case'));
    const categoryType = sanitizeText(String(body.category_type || body.caseCategoryType || 'Aligners'));
    const requestedCaseId = body.case_id ? sanitizeText(String(body.case_id).trim()) : null;

    try {
        const created = db.runTransaction(() => {
            const nextSeq = (db.sqlite.prepare('SELECT COALESCE(MAX(id), 0) AS m FROM cases').get().m) + 1;
            const caseCode = requestedCaseId || (`VELOUR-${String(nextSeq).padStart(4, '0')}`);
            const dup = db.sqlite.prepare('SELECT id FROM cases WHERE LOWER(case_id) = LOWER(?)').get(caseCode);
            if (dup) {
                const err = new Error('Case ID already exists.');
                err.status = 409;
                throw err;
            }
            const statusObj = { value: 'newly-created', label: 'Newly Created', color: 'primary' };
            const clinicalObj = {
                jawArchType: sanitizeText(String(body.jaw_arch_type || 'Both Arch')),
                jawArchCorrection: sanitizeText(String(body.jaw_arch_correction || 'Standard Alignment')),
                jawToothFormat: sanitizeText(String(body.jaw_tooth_format || 'FDI Notation')),
                needsIpr: sanitizeText(String(body.needs_ipr || 'No')),
                needsAttachments: sanitizeText(String(body.needs_attachments || 'No')),
                needsExtraction: sanitizeText(String(body.needs_extraction || 'No'))
            };

            const ins = db.sqlite.prepare(`
                INSERT INTO cases (case_id, patient_name, patient_age, patient_gender, patient_email, patient_phone, patient_dob, patient_national_id, patient_residency_type, patient_address, patient_medical_history, doctor_name, doctor_id, uploader_id, created_by, doctor_email, client_id, client_name, category, category_type, status_value, status_json, is_draft, version, is_archived, deadline, upper_aligners, lower_aligners, chief_complaint, malocclusion, clinical_json, shipment_batches_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'newly-created', ?, 0, 1, 0, ?, 0, 0, ?, ?, ?, '[]', ?, ?)
            `).run(
                caseCode, patientName, patientAge, patientGender, patientEmail, patientPhone,
                body.patient_date_of_birth ? sanitizeText(String(body.patient_date_of_birth)) : null,
                body.patient_national_id ? sanitizeText(String(body.patient_national_id)) : null,
                sanitizeText(String(body.patient_residency_type || body.residency_type || 'local')),
                sanitizeText(String(body.patient_address || body.address || '')),
                sanitizeText(String(body.patient_medical_history || '')),
                doctorName, req.user.id, req.user.id, req.user.id, req.user.email,
                clientRow.id, clientRow.name, category, categoryType, JSON.stringify(statusObj),
                sanitizeText(String(body.deadline || formatClinicDate(new Date(Date.now() + 14 * 86400000)))),
                chiefComplaint, malocclusion, JSON.stringify(clinicalObj), nowStr, nowStr
            );
            const caseIdNum = Number(ins.lastInsertRowid);
            if (Array.isArray(req.files) && req.files.length > 0) {
                const insAtt = db.sqlite.prepare(`
                    INSERT INTO case_attachments (case_id, client_id, uploader_id, disk_filename, original_name, file_url, file_size, mime_type, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                `);
                for (const f of req.files) {
                    insAtt.run(caseIdNum, clientRow.id, req.user.id, f.filename, sanitizeFileName(f.originalname), `/uploads/${f.filename}`, `${(f.size / 1024 / 1024).toFixed(2)} MB`, f.mimetype, nowStr);
                }
            }
            return db.mapCaseRow(db.sqlite.prepare('SELECT * FROM cases WHERE id = ?').get(caseIdNum));
        });

        db.insertAuditLog({ user: req.user, action: 'CREATE_CASE', resourceType: 'case', resourceId: created.id, details: `Created case ${created.case_id}`, ip: req.ip });
        res.json({ success: true, message: 'Case registered successfully', data: created });
    } catch (e) {
        cleanupUploadedFiles(req);
        return res.status(e.status || 400).json({ success: false, message: e.message || 'Unable to create case.' });
    }
});

app.get('/api/cases/:id', ...requireCaseAccess('view_all_cases'), (req, res) => {
    const c = req.caseRow;
    const plans = db.sqlite.prepare('SELECT * FROM treatment_plans WHERE case_id = ? ORDER BY id ASC').all(c.id).map(db.mapPlanRow);
    const attachments = db.sqlite.prepare('SELECT * FROM case_attachments WHERE case_id = ? ORDER BY id ASC').all(c.id).map(db.mapAttachmentRow);
    const stepFiles = db.sqlite.prepare('SELECT * FROM step_files WHERE case_id = ? ORDER BY id ASC').all(c.id).map(db.mapStepFileRow);
    const clientRow = db.sqlite.prepare('SELECT * FROM clients WHERE id = ?').get(c.client_id);
    const mappedClient = clientRow ? db.mapClientRow(clientRow) : { id: c.client_id, name: c.client_name };

    db.insertAuditLog({ user: req.user, action: 'VIEW_CASE_DETAIL', resourceType: 'case', resourceId: c.id, details: `Opened case ${c.case_id}`, ip: req.ip });
    res.json({
        data: {
            ...c,
            client: {
                id: mappedClient.id,
                name: mappedClient.name,
                is_express_delivery_active: mappedClient.is_express_delivery_active || 'NO'
            },
            attachments,
            treatment_plans: plans,
            step_files: stepFiles
        }
    });
});

function handleUpdateCase(req, res) {
    if (!validateRequestFiles(req, res)) return;
    const found = req.caseRow;
    const body = req.body || {};

    if (body.version !== undefined && parseInt(body.version, 10) !== found.version) {
        cleanupUploadedFiles(req);
        return res.status(409).json({
            success: false,
            message: 'Conflict: This case has been updated by another user. Please refresh and review latest changes before saving.'
        });
    }

    const nextCaseId = body.case_id ? sanitizeText(String(body.case_id).trim()) : found.case_id;
    const nextDoctor = body.case_doctor ? sanitizeText(String(body.case_doctor)) : found.doctor_name;
    const nextComplaint = body.chief_complaint !== undefined ? sanitizeText(String(body.chief_complaint)) : found.chief_complaint;
    const nextMalocclusion = body.malocclusion !== undefined ? sanitizeText(String(body.malocclusion)) : found.malocclusion;
    const nextUpper = body.upper_aligners !== undefined ? (parseInt(body.upper_aligners, 10) || 0) : found.upper_aligners;
    const nextLower = body.lower_aligners !== undefined ? (parseInt(body.lower_aligners, 10) || 0) : found.lower_aligners;
    const nowStr = formatClinicDateTime();

    const upd = db.sqlite.prepare(`
        UPDATE cases
        SET case_id = ?, doctor_name = ?, chief_complaint = ?, malocclusion = ?, upper_aligners = ?, lower_aligners = ?, version = version + 1, updated_at = ?
        WHERE id = ? AND version = ?
    `).run(nextCaseId, nextDoctor, nextComplaint, nextMalocclusion, nextUpper, nextLower, nowStr, found.id, found.version);

    if (!upd.changes) {
        cleanupUploadedFiles(req);
        return res.status(409).json({ success: false, message: 'Conflict: Concurrent edit detected.' });
    }

    const updated = db.mapCaseRow(db.sqlite.prepare('SELECT * FROM cases WHERE id = ?').get(found.id));
    db.insertAuditLog({ user: req.user, action: 'EDIT_CASE', resourceType: 'case', resourceId: found.id, details: `Updated case ${updated.case_id}`, ip: req.ip });
    res.json({ success: true, message: 'Case updated successfully', data: updated });
}

app.put(['/api/cases/:id', '/api/cases/:id/edit'], ...requireCaseAccess('create_edit_case'), upload.any(), handleUpdateCase);
app.post(['/api/cases/:id', '/api/cases/:id/edit'], ...requireCaseAccess('create_edit_case'), upload.any(), handleUpdateCase);

app.delete('/api/cases/:id', ...requireCaseAccess('delete_anything'), (req, res) => {
    const found = req.caseRow;
    db.sqlite.prepare('UPDATE cases SET is_archived = 1, archived_at = ?, archived_by = ? WHERE id = ?').run(new Date().toISOString(), req.user.id, found.id);
    db.insertAuditLog({ user: req.user, action: 'ARCHIVE_CASE', resourceType: 'case', resourceId: found.id, details: `Soft-archived case ${found.case_id}`, ip: req.ip });
    res.json({ success: true, message: 'Case archived successfully (soft deleted)' });
});

app.get('/api/cases/:id/activities', ...requireCaseAccess('view_all_cases'), (req, res) => {
    const logs = db.sqlite.prepare("SELECT id, action, details, timestamp FROM audit_logs WHERE resource_type = 'case' AND resource_id = ? ORDER BY id DESC LIMIT 50").all(String(req.caseRow.id));
    const data = logs.length ? logs.map(l => ({ id: l.id, event: l.action, description: l.details, created_at: l.timestamp })) : [
        { id: 1, event: 'Case Created', description: `Case ${req.caseRow.case_id} registered`, created_at: req.caseRow.created_at }
    ];
    res.json({ data });
});

app.patch('/api/cases/:id/assign-planner', requirePermission('manage_users_roles'), loadCaseParam('id'), (req, res) => {
    const plannerId = parseInt(req.body?.planner_id, 10);
    const plannerRow = db.sqlite.prepare("SELECT id, name FROM users WHERE id = ? AND role_slug IN ('planner','admin','super-admin')").get(plannerId);
    if (!plannerRow) return res.status(400).json({ success: false, message: 'Valid CAD planner ID is required.' });
    db.insertAuditLog({ user: req.user, action: 'ASSIGN_PLANNER', resourceType: 'case', resourceId: req.caseRow.id, details: `Assigned planner ${plannerRow.id}`, ip: req.ip });
    res.json({ success: true, message: 'CAD Planner assigned successfully', data: { planner: db.plain(plannerRow) } });
});

app.patch('/api/cases/:id/change-client', requirePermission('manage_users_roles'), loadCaseParam('id'), (req, res) => {
    const clientId = parseInt(req.body?.client_id, 10);
    const clientRow = db.sqlite.prepare('SELECT id, name FROM clients WHERE id = ?').get(clientId);
    if (!clientRow) return res.status(404).json({ success: false, message: 'Target client not found.' });
    db.sqlite.prepare('UPDATE cases SET client_id = ?, client_name = ?, updated_at = ? WHERE id = ?').run(clientRow.id, clientRow.name, formatClinicDateTime(), req.caseRow.id);
    db.insertAuditLog({ user: req.user, action: 'CHANGE_CASE_CLIENT', resourceType: 'case', resourceId: req.caseRow.id, details: `Moved case to client ${clientRow.id}`, ip: req.ip });
    res.json({ success: true, message: 'Client updated successfully' });
});

app.patch('/api/cases/:id/change-case-id', requireAuth, loadCaseParam('id'), (req, res) => {
    const role = getUserRole(req.user);
    if (!['super-admin', 'admin', 'planner'].includes(role)) {
        return res.status(403).json({ success: false, message: 'Forbidden: Only Admin or Planner can rename Case IDs.' });
    }
    const newId = sanitizeText(String(req.body?.case_id || '').trim());
    if (!newId) return res.status(400).json({ success: false, message: 'case_id is required.' });
    try {
        db.sqlite.prepare('UPDATE cases SET case_id = ?, updated_at = ? WHERE id = ?').run(newId, formatClinicDateTime(), req.caseRow.id);
        db.insertAuditLog({ user: req.user, action: 'CHANGE_CASE_ID', resourceType: 'case', resourceId: req.caseRow.id, details: `Renamed case ID to ${newId}`, ip: req.ip });
        res.json({ success: true, message: 'Case ID updated successfully' });
    } catch (e) {
        return res.status(409).json({ success: false, message: 'Case ID already exists.' });
    }
});

app.patch('/api/cases/:id/status', requireAuth, loadCaseParam('id'), (req, res) => {
    const role = getUserRole(req.user);
    if (!['super-admin', 'admin', 'planner', 'vendor'].includes(role) || !canAccessCase(req.user, req.caseRow, 'update_production_status')) {
        return res.status(403).json({ success: false, message: 'Forbidden: You cannot override case workflow status.' });
    }
    const val = String(req.body?.status || '').trim();
    if (!val) return res.status(400).json({ success: false, message: 'Status value is required.' });
    const statusObj = {
        value: val,
        label: val.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' '),
        color: val.includes('approved') ? 'success' : val.includes('review') ? 'info' : 'primary'
    };
    db.sqlite.prepare('UPDATE cases SET status_value = ?, status_json = ?, updated_at = ? WHERE id = ?').run(val, JSON.stringify(statusObj), formatClinicDateTime(), req.caseRow.id);
    db.insertAuditLog({ user: req.user, action: 'CASE_STATUS_CHANGED', resourceType: 'case', resourceId: req.caseRow.id, details: `Changed status to ${val}`, ip: req.ip });
    res.json({ success: true, message: 'Case status updated successfully' });
});

app.post('/api/cases/:id/update-draft-pipeline', ...requireCaseAccess('create_edit_case'), (req, res) => {
    res.json({ success: true, message: 'Draft pipeline updated successfully' });
});

app.post('/api/cases/:id/update-draft', ...requireCaseAccess('create_edit_case'), (req, res) => {
    res.json({ success: true, message: 'Draft updated successfully' });
});

app.post('/api/cases/:id/attachments', ...requireCaseAccess('upload_scans_photos'), upload.single('attachment'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, message: 'Attachment file is required.' });
    }
    if (!validateRequestFiles(req, res)) return;
    const nowStr = formatClinicDateTime();
    const safeOrig = sanitizeFileName(req.file.originalname);
    const sizeLabel = `${(req.file.size / 1024 / 1024).toFixed(2)} MB`;
    const ins = db.sqlite.prepare(`
        INSERT INTO case_attachments (case_id, client_id, uploader_id, disk_filename, original_name, file_url, file_size, mime_type, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(req.caseRow.id, req.caseRow.client_id, req.user.id, req.file.filename, safeOrig, `/uploads/${req.file.filename}`, sizeLabel, req.file.mimetype, nowStr);

    const created = db.mapAttachmentRow(db.sqlite.prepare('SELECT * FROM case_attachments WHERE id = ?').get(Number(ins.lastInsertRowid)));
    db.insertAuditLog({ user: req.user, action: 'UPLOAD_ATTACHMENT', resourceType: 'case', resourceId: req.caseRow.id, details: `Uploaded attachment ${safeOrig}`, ip: req.ip });
    res.json({ success: true, message: 'File uploaded successfully', data: created });
});

app.delete('/api/cases/:id/attachments/:attachmentId', ...requireCaseAccess('create_edit_case'), (req, res) => {
    const attId = parseInt(req.params.attachmentId, 10);
    const att = db.sqlite.prepare('SELECT * FROM case_attachments WHERE id = ? AND case_id = ?').get(attId, req.caseRow.id);
    if (!att) return res.status(404).json({ success: false, message: 'Attachment not found.' });
    if (!canUser(req.user, 'delete_anything') && Number(att.uploader_id) !== Number(req.user.id)) {
        return res.status(403).json({ success: false, message: 'Forbidden: Only administrators or original uploader can delete attachments.' });
    }
    db.sqlite.prepare('DELETE FROM case_attachments WHERE id = ?').run(attId);
    const diskPath = path.join(uploadDir, path.basename(att.disk_filename));
    if (fs.existsSync(diskPath)) {
        try { fs.unlinkSync(diskPath); } catch (e) {}
    }
    db.insertAuditLog({ user: req.user, action: 'DELETE_ATTACHMENT', resourceType: 'case', resourceId: req.caseRow.id, details: `Deleted attachment ${att.original_name}`, ip: req.ip });
    res.json({ success: true, message: 'Attachment deleted' });
});

app.patch('/api/cases/:id/shipment-address', ...requireCaseAccess('create_edit_case'), (req, res) => {
    res.json({ success: true, message: 'Shipment address updated successfully' });
});

app.post('/api/cases/:id/sync-to-waveatp', ...requireCaseAccess('view_all_cases'), (req, res) => {
    res.json({ success: true, message: 'Case geometry successfully synchronized with WaveATP CAD system.' });
});

app.post('/api/cases/:id/open-in-smile-inspector', ...requireCaseAccess('view_all_cases'), (req, res) => {
    res.json({
        success: true,
        viewer_url: `/simulation/${encodeURIComponent(req.caseRow.case_id || req.caseRow.id)}`
    });
});

app.get('/api/cases/:id/step-files', ...requireCaseAccess('view_all_cases'), (req, res) => {
    const rows = db.sqlite.prepare('SELECT * FROM step_files WHERE case_id = ? ORDER BY id ASC').all(req.caseRow.id);
    res.json({ data: rows.map(db.mapStepFileRow) });
});

app.post('/api/cases/:id/step-files', ...requireCaseAccess('upload_scans_photos'), upload.single('zip_file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, message: "A valid zip/medical model file (.zip, .stl, .ply, .o3c) is required in the 'zip_file' field." });
    }
    if (!validateRequestFiles(req, res)) return;
    const nowStr = formatClinicDateTime();
    const safeOrig = sanitizeFileName(req.file.originalname);
    const statusJson = JSON.stringify({ value: 'pending', label: 'Pending', color: 'info' });
    const ins = db.sqlite.prepare(`
        INSERT INTO step_files (case_id, client_id, uploader_id, v_tratransfer_link, description, disk_filename, zip_file_url, zip_file_name, status_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
        req.caseRow.id, req.caseRow.client_id, req.user.id,
        sanitizeText(String(req.body?.v_tratransfer_link || '')),
        sanitizeRichHtml(String(req.body?.description || '')),
        req.file.filename, `/uploads/${req.file.filename}`, safeOrig, statusJson, nowStr, nowStr
    );
    const created = db.mapStepFileRow(db.sqlite.prepare('SELECT * FROM step_files WHERE id = ?').get(Number(ins.lastInsertRowid)));
    db.insertAuditLog({ user: req.user, action: 'UPLOAD_STEP_FILE', resourceType: 'case', resourceId: req.caseRow.id, details: `Uploaded step file ${safeOrig}`, ip: req.ip });
    res.json({ success: true, message: 'Step file uploaded successfully', data: created });
});

app.delete('/api/cases/:caseId/step-files/:fileId', ...requireCaseAccess('create_edit_case', 'caseId'), (req, res) => {
    const fileId = parseInt(req.params.fileId, 10);
    const row = db.sqlite.prepare('SELECT * FROM step_files WHERE id = ? AND case_id = ?').get(fileId, req.caseRow.id);
    if (!row) return res.status(404).json({ success: false, message: 'Step file not found.' });
    if (!canUser(req.user, 'delete_anything') && Number(row.uploader_id) !== Number(req.user.id)) {
        return res.status(403).json({ success: false, message: 'Forbidden: Insufficient permissions to remove step file.' });
    }
    db.sqlite.prepare('DELETE FROM step_files WHERE id = ?').run(fileId);
    if (row.disk_filename) {
        const diskPath = path.join(uploadDir, path.basename(row.disk_filename));
        if (fs.existsSync(diskPath)) {
            try { fs.unlinkSync(diskPath); } catch (e) {}
        }
    }
    res.json({ success: true, message: 'Step file removed' });
});

app.post('/api/cases/:id/shipment-batches/start-next', requireAuth, loadCaseParam('id'), (req, res) => {
    const role = getUserRole(req.user);
    if (!['super-admin', 'admin', 'planner', 'vendor'].includes(role) || !canAccessCase(req.user, req.caseRow, 'update_production_status')) {
        return res.status(403).json({ success: false, message: 'Forbidden: Only production/admin staff can dispatch manufacturing batches.' });
    }
    const batches = Array.isArray(req.caseRow.shipment_batches) ? [...req.caseRow.shipment_batches] : [];
    const batchNumber = batches.length + 1;
    const trackingNumber = sanitizeText(String(req.body?.tracking_number || `DHL-MED-${Date.now().toString().slice(-8)}`));
    const courier = sanitizeText(String(req.body?.courier || 'DHL Express Medical'));
    const newBatch = {
        batch_id: batchNumber,
        batch_label: `Batch ${batchNumber} (Aligners ${((batchNumber - 1) * 6) + 1}-${batchNumber * 6})`,
        courier,
        tracking_number: trackingNumber,
        tracking_url: `https://www.dhl.com/en/express/tracking.html?AWB=${encodeURIComponent(trackingNumber)}`,
        status: 'dispatched',
        dispatched_at: formatClinicDateTime()
    };
    batches.push(newBatch);

    const existingRow = db.sqlite.prepare('SELECT clinical_json FROM cases WHERE id = ?').get(req.caseRow.id);
    const clinical = db.parseJson(existingRow?.clinical_json, {});
    clinical.latest_tracking = newBatch;
    const statusObj = { value: 'in-manufacturing', label: 'In Manufacturing / Dispatched', color: 'primary' };

    db.sqlite.prepare('UPDATE cases SET shipment_batches_json = ?, clinical_json = ?, status_value = ?, status_json = ?, updated_at = ? WHERE id = ?')
        .run(JSON.stringify(batches), JSON.stringify(clinical), 'in-manufacturing', JSON.stringify(statusObj), formatClinicDateTime(), req.caseRow.id);

    const updated = db.mapCaseRow(db.sqlite.prepare('SELECT * FROM cases WHERE id = ?').get(req.caseRow.id));
    db.insertAuditLog({ user: req.user, action: 'DISPATCH_BATCH', resourceType: 'case', resourceId: req.caseRow.id, details: `Dispatched batch ${batchNumber} (${trackingNumber})`, ip: req.ip });
    res.json({ success: true, message: 'Next aligner batch dispatched to manufacturing with DHL tracking.', batch: newBatch, case: updated });
});

app.post('/api/cases/:id/shipment-batches/notify-next', ...requireCaseAccess('view_all_cases'), (req, res) => {
    res.json({ success: true, message: 'Doctor notified regarding next batch.' });
});

// Case Comments & Presence
app.get('/api/cases/:id/comments', ...requireCaseAccess('view_all_cases'), (req, res) => {
    const { page, perPage, offset } = paginateParams(req.query, { defaultPerPage: 15, maxPerPage: 100 });
    const total = db.sqlite.prepare('SELECT COUNT(*) AS cnt FROM case_comments WHERE case_id = ?').get(req.caseRow.id).cnt;
    const rows = db.sqlite.prepare('SELECT * FROM case_comments WHERE case_id = ? ORDER BY id ASC LIMIT ? OFFSET ?').all(req.caseRow.id, perPage, offset);
    const data = rows.map(r => ({
        id: r.id,
        case_id: r.case_id,
        user: { id: r.user_id, name: r.user_name, role: r.user_role, profile_pic_url: r.user_pic },
        content: r.content,
        attachments: db.parseJson(r.attachments_json, []),
        created_at: r.created_at
    }));
    const lastPage = Math.max(1, Math.ceil(total / perPage));
    res.json({
        data,
        meta: { current_page: page, last_page: lastPage, per_page: perPage, total }
    });
});

app.post('/api/cases/:id/comments', ...requireCaseAccess('view_all_cases'), upload.any(), (req, res) => {
    if (!validateRequestFiles(req, res)) return;
    const cleanContent = sanitizeRichHtml(String(req.body?.content || 'Comment submitted.'));
    const nowStr = formatClinicDateTime();
    const atts = [];
    if (Array.isArray(req.files)) {
        const insAtt = db.sqlite.prepare(`
            INSERT INTO case_attachments (case_id, client_id, uploader_id, disk_filename, original_name, file_url, file_size, mime_type, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        for (const f of req.files) {
            const orig = sanitizeFileName(f.originalname);
            insAtt.run(req.caseRow.id, req.caseRow.client_id, req.user.id, f.filename, orig, `/uploads/${f.filename}`, `${(f.size / 1024).toFixed(1)} KB`, f.mimetype, nowStr);
            atts.push({ name: orig, url: `/uploads/${f.filename}` });
        }
    }
    const ins = db.sqlite.prepare(`
        INSERT INTO case_comments (case_id, user_id, user_name, user_role, user_pic, content, attachments_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(req.caseRow.id, req.user.id, req.user.name, req.user.role_slug, req.user.profile_pic_url || '/assets/velourcare-square.png', cleanContent, JSON.stringify(atts), nowStr);

    const comment = {
        id: Number(ins.lastInsertRowid),
        case_id: req.caseRow.id,
        user: { id: req.user.id, name: req.user.name, profile_pic_url: req.user.profile_pic_url },
        content: cleanContent,
        attachments: atts,
        created_at: nowStr
    };
    db.insertAuditLog({ user: req.user, action: 'COMMENT_ADDED', resourceType: 'case', resourceId: req.caseRow.id, details: `Added comment on case ${req.caseRow.case_id}`, ip: req.ip });
    res.status(201).json({ data: comment, message: 'Comment added successfully' });
});

app.get('/api/cases/:id/comments/presence', ...requireCaseAccess('view_all_cases'), (req, res) => {
    res.json({ users: [{ id: req.user.id, name: req.user.name }] });
});

app.post('/api/cases/:id/comments/presence', ...requireCaseAccess('view_all_cases'), (req, res) => {
    res.json({ success: true, message: 'Joined presence' });
});

app.post('/api/cases/:id/comments/presence/leave', ...requireCaseAccess('view_all_cases'), (req, res) => {
    res.json({ success: true, message: 'Left presence' });
});

app.post('/api/notifications/send-test-email', requireAuth, (req, res) => {
    res.json({
        success: true,
        message: 'The test email has been sent successfully. Please check your inbox shortly; it should arrive within a few moments.'
    });
});

// ==========================================
// CHAT & NOTIFICATIONS (USER-SCOPED)
// ==========================================
app.get('/api/chat', requireAuth, (req, res) => {
    const { page, perPage, offset } = paginateParams(req.query, { defaultPerPage: 15, maxPerPage: 100 });
    const rows = db.sqlite.prepare(`
        SELECT m.*, u.name AS peer_name, u.username AS peer_username, u.profile_pic_url AS peer_pic, u.role_slug AS peer_role
        FROM chat_messages m
        JOIN users u ON u.id = CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END
        WHERE m.sender_id = ? OR m.receiver_id = ?
        ORDER BY m.id DESC LIMIT ? OFFSET ?
    `).all(req.user.id, req.user.id, req.user.id, perPage, offset);

    const contacts = db.sqlite.prepare("SELECT id, name, email, role_slug AS role, profile_pic_url FROM users WHERE id != ? AND status_value = 'active' AND (client_id = ? OR role_slug IN ('admin','super-admin','planner','vendor'))").all(req.user.id, req.user.client_id || 0).map(db.plain);
    const lastPage = Math.max(1, Math.ceil(rows.length / perPage));
    res.json({
        data: rows.map(r => ({
            id: r.id,
            receiver_id: r.receiver_id,
            user: { id: r.sender_id === req.user.id ? r.receiver_id : r.sender_id, name: r.peer_name, username: r.peer_username, profile_pic_url: r.peer_pic, role_name: r.peer_role },
            last_message: { id: r.id, message: r.message, created_at: r.created_at, is_read: Boolean(r.is_read) },
            unread_count: 0
        })),
        additional: { contacts },
        meta: { current_page: page, last_page: lastPage, per_page: perPage, total: rows.length }
    });
});

app.get('/api/chat/unread-counts', requireAuth, (req, res) => {
    const unread = db.sqlite.prepare('SELECT COUNT(*) AS cnt FROM chat_messages WHERE receiver_id = ? AND is_read = 0').get(req.user.id).cnt;
    res.json({ unread_count: unread, data: { total: unread } });
});

app.get('/api/chat/:id', requireAuth, (req, res) => {
    const peerId = parseInt(req.params.id, 10);
    const msgs = db.sqlite.prepare(`
        SELECT * FROM chat_messages
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY id ASC
    `).all(req.user.id, peerId, peerId, req.user.id).map(r => ({
        id: r.id, sender_id: r.sender_id, receiver_id: r.receiver_id,
        message: r.message, created_at: r.created_at, is_read: Boolean(r.is_read)
    }));
    res.json({ data: msgs });
});

app.post('/api/chat', requireAuth, (req, res) => {
    const receiverId = parseInt(req.body?.receiver_id, 10);
    const message = sanitizeText(String(req.body?.message || '').trim());
    if (!receiverId || !message) {
        return res.status(400).json({ success: false, message: 'receiver_id and message are required.' });
    }
    const target = db.sqlite.prepare('SELECT id FROM users WHERE id = ?').get(receiverId);
    if (!target) return res.status(404).json({ success: false, message: 'Recipient not found.' });
    const nowStr = formatClinicDateTime();
    const ins = db.sqlite.prepare('INSERT INTO chat_messages (sender_id, receiver_id, message, is_read, created_at) VALUES (?, ?, ?, 0, ?)').run(req.user.id, receiverId, message, nowStr);
    res.json({
        success: true,
        data: { id: Number(ins.lastInsertRowid), sender_id: req.user.id, receiver_id: receiverId, message, created_at: nowStr, is_read: false }
    });
});

app.post('/api/chat/:id/mark-as-read', requireAuth, (req, res) => {
    const peerId = parseInt(req.params.id, 10);
    db.sqlite.prepare('UPDATE chat_messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ?').run(peerId, req.user.id);
    res.json({ success: true, message: 'Marked as read' });
});

app.get('/api/notifications', requireAuth, (req, res) => {
    const rows = db.sqlite.prepare('SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 50').all(req.user.id).map(db.plain);
    res.json({ data: rows });
});

app.get('/api/notifications/unread-counts', requireAuth, (req, res) => {
    const total = db.sqlite.prepare('SELECT COUNT(*) AS cnt FROM notifications WHERE user_id = ? AND is_read = 0').get(req.user.id).cnt;
    res.json({ total, by_category: { case_lifecycle: 0, messages: 0, alerts: total }, by_tab: { all: total } });
});

app.patch('/api/notifications/:id/read', requireAuth, (req, res) => {
    db.sqlite.prepare('UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?').run(parseInt(req.params.id, 10), req.user.id);
    res.json({ success: true });
});

app.post('/api/notifications/mark-all-read', requireAuth, (req, res) => {
    db.sqlite.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(req.user.id);
    res.json({ success: true });
});

// ==========================================
// 6. TREATMENT PLANS & IPR DOCUMENT
// ==========================================
app.get('/api/cases/:id/treatment-plans', ...requireCaseAccess('view_all_cases'), (req, res) => {
    const plans = db.sqlite.prepare('SELECT * FROM treatment_plans WHERE case_id = ? ORDER BY id ASC').all(req.caseRow.id).map(db.mapPlanRow);
    res.json({ data: plans });
});

app.get('/api/cases/:caseId/treatment-plans/:planId/document', ...requireCaseAccess('view_all_cases', 'caseId'), (req, res) => {
    const planId = parseInt(req.params.planId, 10);
    const planRow = db.sqlite.prepare('SELECT * FROM treatment_plans WHERE id = ? AND case_id = ?').get(planId, req.caseRow.id);
    if (!planRow) {
        return res.status(404).json({ message: `Treatment plan #${req.params.planId} not found for this case.` });
    }
    const plan = db.mapPlanRow(planRow);
    const c = req.caseRow;
    res.json({
        data: {
            plan_document_data: plan.plan_document_data,
            ipr_chart_file_url: plan.ipr_chart_file_url,
            case_meta: {
                patient_name: c.patient_name,
                doctor_name: c.doctor_name,
                clinic_name: c.client_name,
                case_number: c.case_id,
                plan_number: plan.id,
                client_logo_url: '/assets/velourcare-logo.png',
                client_tp_pdf_logo_url: '/assets/velourcare-logo.png',
                parent_tp_pdf_logo_url: '/assets/velourcare-logo.png',
                client_profile_logo_url: '/assets/velourcare-square.png',
                cover_page_content: 'VelourCare Ortho Treatment Plan & IPR Protocol'
            }
        }
    });
});

app.put('/api/cases/:caseId/treatment-plans/:planId/document', ...requireCaseAccess('create_edit_case', 'caseId'), (req, res) => {
    const planId = parseInt(req.params.planId, 10);
    const planRow = db.sqlite.prepare('SELECT * FROM treatment_plans WHERE id = ? AND case_id = ?').get(planId, req.caseRow.id);
    if (!planRow) return res.status(404).json({ message: 'Treatment plan not found.' });
    let docData = db.parseJson(planRow.plan_document_json, {});
    if (req.body?.plan_document_data) {
        try {
            docData = typeof req.body.plan_document_data === 'string' ? JSON.parse(req.body.plan_document_data) : req.body.plan_document_data;
        } catch (e) {
            return res.status(400).json({ success: false, message: 'Invalid plan_document_data JSON.' });
        }
    }
    db.sqlite.prepare('UPDATE treatment_plans SET plan_document_json = ? WHERE id = ?').run(JSON.stringify(docData), planId);
    res.json({
        success: true,
        message: 'Plan document and IPR chart updated successfully',
        data: { plan_document_data: docData, ipr_chart_file_url: planRow.ipr_chart_file_url }
    });
});

app.post('/api/cases/:caseId/treatment-plans/:planId/document', ...requireCaseAccess('create_edit_case', 'caseId'), upload.single('ipr_chart_pdf'), (req, res) => {
    if (!validateRequestFiles(req, res)) return;
    const planId = parseInt(req.params.planId, 10);
    const planRow = db.sqlite.prepare('SELECT * FROM treatment_plans WHERE id = ? AND case_id = ?').get(planId, req.caseRow.id);
    if (!planRow) {
        cleanupUploadedFiles(req);
        return res.status(404).json({ message: 'Treatment plan not found.' });
    }
    let docData = db.parseJson(planRow.plan_document_json, {});
    if (req.body?.plan_document_data) {
        try {
            docData = typeof req.body.plan_document_data === 'string' ? JSON.parse(req.body.plan_document_data) : req.body.plan_document_data;
        } catch (e) {
            cleanupUploadedFiles(req);
            return res.status(400).json({ success: false, message: 'Invalid plan_document_data JSON.' });
        }
    }
    const chartUrl = req.file ? `/uploads/${req.file.filename}` : planRow.ipr_chart_file_url;
    db.sqlite.prepare('UPDATE treatment_plans SET plan_document_json = ?, ipr_chart_file_url = ? WHERE id = ?').run(JSON.stringify(docData), chartUrl, planId);
    res.json({
        success: true,
        message: 'Plan document and IPR chart saved successfully',
        data: { plan_document_data: docData, ipr_chart_file_url: chartUrl }
    });
});

app.post('/api/cases/:caseId/treatment-plans/:planId/approve', ...requireCaseAccess('approve_treatment_plan', 'caseId'), (req, res) => {
    const caseId = req.caseRow.id;
    const planId = parseInt(req.params.planId, 10);

    let txResult;
    try {
        txResult = db.runTransaction(() => {
            const curCase = db.sqlite.prepare('SELECT * FROM cases WHERE id = ? AND is_archived = 0').get(caseId);
            const curPlan = db.sqlite.prepare('SELECT * FROM treatment_plans WHERE id = ? AND case_id = ?').get(planId, caseId);
            if (!curPlan) {
                const err = new Error('Treatment plan not found for this case.');
                err.status = 404;
                throw err;
            }
            if (curCase.status_value === 'plan-approved' || curPlan.status_value === 'approved') {
                const err = new Error('Treatment plan has already been approved.');
                err.status = 409;
                throw err;
            }
            const existingInv = db.sqlite.prepare("SELECT id FROM invoices WHERE case_id = ? AND plan_id = ? AND document_status != 'cancelled'").get(caseId, planId);
            if (existingInv) {
                const err = new Error('An invoice has already been generated for this treatment plan approval.');
                err.status = 409;
                throw err;
            }

            const approvedPlanStatus = { value: 'approved', label: 'Approved', color: 'success' };
            const approvedCaseStatus = { value: 'plan-approved', label: 'Plan Approved', color: 'success' };
            const nowStr = formatClinicDateTime();
            const today = formatClinicDate();
            const endDay = formatClinicDate(new Date(Date.now() + 30 * 86400000));
            const dueDay = formatClinicDate(new Date(Date.now() + 14 * 86400000));

            db.sqlite.prepare('UPDATE treatment_plans SET status_value = ?, status_json = ? WHERE id = ?').run('approved', JSON.stringify(approvedPlanStatus), planId);
            db.sqlite.prepare('UPDATE cases SET status_value = ?, status_json = ?, version = version + 1, updated_at = ? WHERE id = ?').run('plan-approved', JSON.stringify(approvedCaseStatus), nowStr, caseId);

            const calc = calculateInvoiceTotalsServerSide([
                { service_code: 'full-aligner-package', description: `VelourCare Clear Aligner Full Treatment Package - Case ${curCase.case_id}`, quantity: 1 }
            ], 0, 0.05);
            const invNumber = db.getNextInvoiceNumber();

            const insInv = db.sqlite.prepare(`
                INSERT INTO invoices (invoice_number, client_id, client_name, case_id, plan_id, patient_name, billing_period_start, billing_period_end, document_status, document_status_label, payment_status, payment_status_label, subtotal_fils, discount_fils, tax_fils, total_fils, amount_paid_fils, balance_due_fils, currency, is_locked, due_date, issued_at, created_at, notes, items_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'issued', 'Issued', 'unpaid', 'Pending Payment', ?, ?, ?, ?, 0, ?, 'AED', 1, ?, ?, ?, '', ?)
            `).run(
                invNumber, curCase.client_id, curCase.client_name, curCase.id, planId, curCase.patient_name,
                today, endDay, calc.subtotalFils, calc.discountFils, calc.taxFils, calc.totalFils, calc.totalFils,
                dueDay, today, today, JSON.stringify(calc.items)
            );

            return {
                caseObj: db.mapCaseRow(db.sqlite.prepare('SELECT * FROM cases WHERE id = ?').get(caseId)),
                planObj: db.mapPlanRow(db.sqlite.prepare('SELECT * FROM treatment_plans WHERE id = ?').get(planId)),
                invObj: db.mapInvoiceRow(db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(Number(insInv.lastInsertRowid)))
            };
        });
    } catch (e) {
        return res.status(e.status || 409).json({ success: false, message: e.message });
    }

    db.insertAuditLog({ user: req.user, action: 'APPROVE_TREATMENT_PLAN', resourceType: 'case', resourceId: caseId, details: `Approved treatment plan ${planId}; generated invoice ${txResult.invObj.invoice_number}`, ip: req.ip });
    res.json({
        success: true,
        message: 'Treatment plan approved. Case status updated to Plan Approved and production invoice generated.',
        data: { case: txResult.caseObj, plan: txResult.planObj, invoice: txResult.invObj }
    });
});

app.post('/api/cases/:caseId/treatment-plans/:planId/reject', ...requireCaseAccess('approve_treatment_plan', 'caseId'), (req, res) => {
    const caseId = req.caseRow.id;
    const planId = parseInt(req.params.planId, 10);
    const planRow = db.sqlite.prepare('SELECT * FROM treatment_plans WHERE id = ? AND case_id = ?').get(planId, caseId);
    if (!planRow) return res.status(404).json({ message: 'Treatment plan not found.' });

    const notes = sanitizeText(String(req.body?.notes || req.body?.reason || 'Modification requested by doctor.'));
    const revPlanStatus = { value: 'revision-requested', label: 'Revision Requested', color: 'warning' };
    const revCaseStatus = { value: 'needs-revision', label: 'Needs Revision', color: 'warning' };
    const nowStr = formatClinicDateTime();

    const commentId = db.runTransaction(() => {
        db.sqlite.prepare('UPDATE treatment_plans SET status_value = ?, status_json = ? WHERE id = ?').run('revision-requested', JSON.stringify(revPlanStatus), planId);
        db.sqlite.prepare('UPDATE cases SET status_value = ?, status_json = ?, version = version + 1, updated_at = ? WHERE id = ?').run('needs-revision', JSON.stringify(revCaseStatus), nowStr, caseId);
        const ins = db.sqlite.prepare(`
            INSERT INTO case_comments (case_id, user_id, user_name, user_role, user_pic, content, attachments_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, '[]', ?)
        `).run(caseId, req.user.id, req.user.name, req.user.role_slug, req.user.profile_pic_url || '/assets/velourcare-square.png', `[Plan Revision Request]: ${notes}`, nowStr);
        return Number(ins.lastInsertRowid);
    });

    db.insertAuditLog({ user: req.user, action: 'REJECT_TREATMENT_PLAN', resourceType: 'case', resourceId: caseId, details: `Requested revision on plan ${planId}`, ip: req.ip });
    res.json({
        success: true,
        message: 'Modification requested for treatment plan.',
        case: db.mapCaseRow(db.sqlite.prepare('SELECT * FROM cases WHERE id = ?').get(caseId)),
        plan: db.mapPlanRow(db.sqlite.prepare('SELECT * FROM treatment_plans WHERE id = ?').get(planId)),
        comment: { id: commentId, case_id: caseId, author_name: req.user.name, author_role: req.user.role_slug, message: `[Plan Revision Request]: ${notes}`, created_at: nowStr }
    });
});

// ==========================================
// 7. CLIENTS & SUB-CLIENTS (TENANT-SCOPED)
// ==========================================
app.get('/api/clients', requireAuth, (req, res) => {
    const role = getUserRole(req.user);
    if (role === 'vendor' || role === 'none') {
        return res.status(403).json({ success: false, message: 'Forbidden.' });
    }
    const { page, perPage, offset } = paginateParams(req.query);
    if (role === 'client') {
        const row = db.sqlite.prepare('SELECT * FROM clients WHERE id = ?').get(Number(req.user.client_id));
        const data = row ? [db.mapClientRow(row)] : [];
        return res.json({ data, current_page: 1, last_page: 1, per_page: perPage, total: data.length });
    }
    const total = db.sqlite.prepare('SELECT COUNT(*) AS cnt FROM clients').get().cnt;
    const rows = db.sqlite.prepare('SELECT * FROM clients ORDER BY id ASC LIMIT ? OFFSET ?').all(perPage, offset).map(db.mapClientRow);
    const lastPage = Math.max(1, Math.ceil(total / perPage));
    res.json({ data: rows, current_page: page, last_page: lastPage, per_page: perPage, total });
});

app.get('/api/clients/as-filter-options', requireAuth, (req, res) => {
    const role = getUserRole(req.user);
    if (role === 'vendor' || role === 'none') return res.json({ data: [] });
    const rows = role === 'client'
        ? db.sqlite.prepare('SELECT id, name, case_id_prefix FROM clients WHERE id = ?').all(Number(req.user.client_id))
        : db.sqlite.prepare('SELECT id, name, case_id_prefix FROM clients ORDER BY id ASC').all();
    res.json({ data: rows.map(c => ({ id: c.id, label: c.name, prefix: c.case_id_prefix })) });
});

app.get('/api/clients/verify-case-id-prefix', requirePermission('manage_users_roles'), (req, res) => {
    const prefix = String(req.query.case_id_prefix || '').toUpperCase().trim();
    if (['REF', 'RET'].includes(prefix)) {
        return res.status(422).json({ message: 'The prefixes REF and RET are reserved.', errors: { case_id_prefix: ['Reserved for refinements and retainers.'] } });
    }
    res.json({ valid: true });
});

app.get('/api/clients/:id', requireAuth, (req, res) => {
    const clientId = parseInt(req.params.id, 10);
    if (!canAccessClient(req.user, clientId)) {
        return res.status(404).json({ message: `Client #${req.params.id} not found.` });
    }
    const row = db.sqlite.prepare('SELECT * FROM clients WHERE id = ?').get(clientId);
    if (!row) return res.status(404).json({ message: `Client #${req.params.id} not found.` });
    res.json({ data: db.mapClientRow(row) });
});

app.post('/api/clients', requirePermission('manage_users_roles'), upload.any(), async (req, res) => {
    if (!validateRequestFiles(req, res)) return;
    const body = req.body || {};
    const clientName = sanitizeText(String(body.client_name || body.name || '').trim());
    if (!clientName) {
        cleanupUploadedFiles(req);
        return res.status(400).json({ success: false, message: 'Client name is required.' });
    }
    const prefix = sanitizeText(String(body.case_id_prefix || 'CLI').toUpperCase().slice(0, 12));
    const defaultAddrs = [{
        id: 1, title: 'Main Practice Address', address_line_1: sanitizeText(String(body.address_line_1 || '')),
        city: sanitizeText(String(body.city || 'Dubai')), country: sanitizeText(String(body.country || 'United Arab Emirates')),
        phone: sanitizeText(String(body.phone || '+971 4 000 0000')), is_default: true
    }];
    const nowStr = formatClinicDateTime();
    const ins = db.sqlite.prepare(`
        INSERT INTO clients (name, company_title, company_name, email, phone, case_id_prefix, is_manufacturing_active, is_express_delivery_active, is_alphanumeric_case_id_active, is_sub_clients_allowed, last_case_number, country, login_uri, status_json, addresses_json, extra_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'YES', ?, 0, ?, ?, ?, ?, '{}', ?, ?)
    `).run(
        clientName, sanitizeText(String(body.company_title || clientName)), sanitizeText(String(body.company_name || clientName)),
        sanitizeText(String(body.email || '')), sanitizeText(String(body.phone || '+971 4 000 0000')),
        prefix, body.is_manufacturing_active || 'NO', body.is_express_delivery_active || 'NO',
        body.is_sub_clients_allowed || 'NO', sanitizeText(String(body.country || 'United Arab Emirates')),
        sanitizeText(String(body.login_uri || prefix).toLowerCase()),
        JSON.stringify({ label: 'Active', color: 'success', value: 'active' }), JSON.stringify(defaultAddrs), nowStr, nowStr
    );
    const newClientId = Number(ins.lastInsertRowid);

    if (body.username && isStrongPassword(body.password)) {
        const { hash, salt } = await hashPasswordAsync(body.password);
        const perms = ['view_cases', 'create_cases', 'view_case_activities', 'view_treatment_plans', 'edit_treatment_plans', 'view_invoices'];
        db.sqlite.prepare(`
            INSERT INTO users (name, full_name, first_name, last_name, username, email, phone, role_slug, gender, is_super_admin, client_id, see_only_own_uploads, status_value, status_json, profile_pic_url, password_hash, password_salt, permissions_json, integrations_json, extra_json, created_at)
            VALUES (?, ?, ?, 'Doctor', ?, ?, ?, 'client', 'male', 0, ?, 0, 'active', ?, '/assets/velourcare-square.png', ?, ?, ?, '{}', '{}', ?)
        `).run(
            clientName, clientName, clientName.split(' ')[0] || 'Client',
            sanitizeText(String(body.username).trim()), sanitizeText(String(body.email || `${body.username}@velourcare.com`).toLowerCase()),
            sanitizeText(String(body.phone || '+971 4 000 0000')), newClientId,
            JSON.stringify({ label: 'Active', value: 'active', color: 'success' }), hash, salt, JSON.stringify(perms), nowStr
        );
    }

    const created = db.mapClientRow(db.sqlite.prepare('SELECT * FROM clients WHERE id = ?').get(newClientId));
    db.insertAuditLog({ user: req.user, action: 'CLIENT_CREATED', resourceType: 'client', resourceId: newClientId, details: `Created client ${clientName}`, ip: req.ip });
    res.json({ success: true, message: 'Client created successfully', data: created });
});

function requireClientAccess(req, res, next) {
    const clientId = parseInt(req.params.id, 10);
    if (!canAccessClient(req.user, clientId)) {
        return res.status(403).json({ success: false, message: 'Forbidden.' });
    }
    return next();
}

function updateClientHandler(req, res) {
    if (!validateRequestFiles(req, res)) return;
    const clientId = parseInt(req.params.id, 10);
    if (!canAccessClient(req.user, clientId)) {
        cleanupUploadedFiles(req);
        return res.status(403).json({ success: false, message: 'Forbidden.' });
    }
    const existing = db.sqlite.prepare('SELECT * FROM clients WHERE id = ?').get(clientId);
    if (!existing) {
        cleanupUploadedFiles(req);
        return res.status(404).json({ success: false, message: 'Client not found' });
    }
    const body = req.body || {};
    const name = body.client_name || body.name ? sanitizeText(String(body.client_name || body.name)) : existing.name;
    const companyTitle = body.company_title ? sanitizeText(String(body.company_title)) : existing.company_title;
    const email = body.email ? sanitizeText(String(body.email)) : existing.email;
    const phone = body.phone ? sanitizeText(String(body.phone)) : existing.phone;
    const addrs = body.shipment_addresses || body.addresses || db.parseJson(existing.addresses_json, []);
    db.sqlite.prepare('UPDATE clients SET name = ?, company_title = ?, email = ?, phone = ?, addresses_json = ?, updated_at = ? WHERE id = ?')
        .run(name, companyTitle, email, phone, JSON.stringify(addrs), formatClinicDateTime(), clientId);
    const updated = db.mapClientRow(db.sqlite.prepare('SELECT * FROM clients WHERE id = ?').get(clientId));
    res.json({ success: true, message: 'Client updated successfully', data: updated });
}

app.put(['/api/clients/:id', '/api/clients/:id/edit', '/api/clients/:id/update-personal-details', '/api/clients/:id/edit-personal-details'], requireAuth, requireClientAccess, upload.any(), updateClientHandler);
app.post(['/api/clients/:id/edit', '/api/clients/:id/update-personal-details', '/api/clients/:id/edit-personal-details'], requireAuth, requireClientAccess, upload.any(), updateClientHandler);

app.post('/api/clients/:id/shipment-addresses', requireAuth, (req, res) => {
    const clientId = parseInt(req.params.id, 10);
    if (!canAccessClient(req.user, clientId)) return res.status(403).json({ success: false, message: 'Forbidden.' });
    const row = db.sqlite.prepare('SELECT addresses_json, phone FROM clients WHERE id = ?').get(clientId);
    if (!row) return res.status(404).json({ success: false, message: 'Client not found' });
    const addrs = db.parseJson(row.addresses_json, []);
    const newId = addrs.length ? Math.max(...addrs.map(a => a.id || 0)) + 1 : 1;
    const newAddr = {
        id: newId,
        is_default: Boolean(req.body?.is_default) || addrs.length === 0,
        title: sanitizeText(String(req.body?.title || 'Practice Branch Address')),
        address_line_1: sanitizeText(String(req.body?.address_line_1 || '')),
        address_line_2: sanitizeText(String(req.body?.address_line_2 || '')),
        city: sanitizeText(String(req.body?.city || 'Dubai')),
        state: sanitizeText(String(req.body?.state || 'Dubai')),
        postal_code: sanitizeText(String(req.body?.postal_code || '00000')),
        country: sanitizeText(String(req.body?.country || 'United Arab Emirates')),
        phone: sanitizeText(String(req.body?.phone || row.phone || ''))
    };
    if (newAddr.is_default) addrs.forEach(a => { a.is_default = false; });
    addrs.push(newAddr);
    db.sqlite.prepare('UPDATE clients SET addresses_json = ?, updated_at = ? WHERE id = ?').run(JSON.stringify(addrs), formatClinicDateTime(), clientId);
    res.json({ success: true, message: 'Shipment address added successfully', data: newAddr });
});

app.put('/api/clients/:id/shipment-addresses/:addressId', requireAuth, (req, res) => {
    const clientId = parseInt(req.params.id, 10);
    if (!canAccessClient(req.user, clientId)) return res.status(403).json({ success: false, message: 'Forbidden.' });
    const row = db.sqlite.prepare('SELECT addresses_json FROM clients WHERE id = ?').get(clientId);
    if (!row) return res.status(404).json({ success: false, message: 'Client not found' });
    const addrs = db.parseJson(row.addresses_json, []);
    const addr = addrs.find(a => a.id === parseInt(req.params.addressId, 10));
    if (!addr) return res.status(404).json({ success: false, message: 'Address not found' });
    if (req.body?.title !== undefined) addr.title = sanitizeText(String(req.body.title));
    if (req.body?.address_line_1 !== undefined) addr.address_line_1 = sanitizeText(String(req.body.address_line_1));
    if (req.body?.city !== undefined) addr.city = sanitizeText(String(req.body.city));
    if (req.body?.phone !== undefined) addr.phone = sanitizeText(String(req.body.phone));
    if (req.body?.is_default) addrs.forEach(a => { a.is_default = (a.id === addr.id); });
    db.sqlite.prepare('UPDATE clients SET addresses_json = ?, updated_at = ? WHERE id = ?').run(JSON.stringify(addrs), formatClinicDateTime(), clientId);
    res.json({ success: true, message: 'Shipment address updated successfully', data: addr });
});

app.delete('/api/clients/:id/shipment-addresses/:addressId', requireAuth, (req, res) => {
    const clientId = parseInt(req.params.id, 10);
    if (!canAccessClient(req.user, clientId)) return res.status(403).json({ success: false, message: 'Forbidden.' });
    const row = db.sqlite.prepare('SELECT addresses_json FROM clients WHERE id = ?').get(clientId);
    if (!row) return res.status(404).json({ success: false, message: 'Client not found' });
    const addrs = db.parseJson(row.addresses_json, []).filter(a => a.id !== parseInt(req.params.addressId, 10));
    db.sqlite.prepare('UPDATE clients SET addresses_json = ?, updated_at = ? WHERE id = ?').run(JSON.stringify(addrs), formatClinicDateTime(), clientId);
    res.json({ success: true, message: 'Shipment address deleted successfully' });
});

app.patch('/api/clients/:id/shipment-addresses/:addressId/set-default', requireAuth, (req, res) => {
    const clientId = parseInt(req.params.id, 10);
    if (!canAccessClient(req.user, clientId)) return res.status(403).json({ success: false, message: 'Forbidden.' });
    const row = db.sqlite.prepare('SELECT addresses_json FROM clients WHERE id = ?').get(clientId);
    if (!row) return res.status(404).json({ success: false, message: 'Client not found' });
    const targetId = parseInt(req.params.addressId, 10);
    const addrs = db.parseJson(row.addresses_json, []);
    addrs.forEach(a => { a.is_default = (a.id === targetId); });
    db.sqlite.prepare('UPDATE clients SET addresses_json = ? WHERE id = ?').run(JSON.stringify(addrs), clientId);
    res.json({ success: true, message: 'Default address set successfully' });
});

app.put(['/api/clients/:id/update-shipment-addresses', '/api/clients/:id/edit-shipment-addresses'], requireAuth, (req, res) => {
    const clientId = parseInt(req.params.id, 10);
    if (!canAccessClient(req.user, clientId)) return res.status(403).json({ success: false, message: 'Forbidden.' });
    const addrs = Array.isArray(req.body?.shipment_addresses || req.body?.addresses) ? (req.body.shipment_addresses || req.body.addresses) : [];
    db.sqlite.prepare('UPDATE clients SET addresses_json = ? WHERE id = ?').run(JSON.stringify(addrs), clientId);
    res.json({ success: true, message: 'Shipment addresses saved successfully' });
});

app.all([
    '/api/clients/:id/update-treatment-details', '/api/clients/:id/edit-treatment-details',
    '/api/clients/:id/update-manufacturing-details', '/api/clients/:id/edit-manufacturing-details',
    '/api/clients/:id/update-account-details', '/api/clients/:id/update-payment-details',
    '/api/clients/:id/update-privacy-restrictions', '/api/clients/:id/edit-privacy-restrictions'
], requireAuth, (req, res) => {
    const clientId = parseInt(req.params.id, 10);
    if (!canAccessClient(req.user, clientId)) return res.status(403).json({ success: false, message: 'Forbidden.' });
    res.json({ success: true, message: 'Client settings updated successfully' });
});

app.get('/api/admin/portal-config', requirePermission('manage_users_roles'), (req, res) => {
    res.json({ success: true, data: db.getPortalSettingsObj() });
});

app.post('/api/admin/portal-config', requirePermission('manage_users_roles'), (req, res) => {
    const body = req.body || {};
    const allowedKeys = ['residencyTypes', 'caseCategories', 'caseCategoryTypes', 'deliveryTimes', 'jawArchTypes', 'jawArchCorrections', 'jawToothFormats'];
    const upd = db.sqlite.prepare('INSERT OR REPLACE INTO portal_settings (key, value_json) VALUES (?, ?)');
    for (const k of allowedKeys) {
        if (body[k] && typeof body[k] === 'object') upd.run(k, JSON.stringify(body[k]));
    }
    db.insertAuditLog({ user: req.user, action: 'PORTAL_CONFIG_UPDATED', details: 'Updated portal dropdown configuration', ip: req.ip });
    res.json({ success: true, message: 'Portal configuration updated successfully' });
});

app.get('/api/clients/:id/next-case-id', requireAuth, (req, res) => {
    const clientId = parseInt(req.params.id, 10);
    if (!canAccessClient(req.user, clientId)) return res.status(403).json({ success: false, message: 'Forbidden.' });
    const count = db.sqlite.prepare('SELECT COALESCE(MAX(id), 0) AS m FROM cases').get().m;
    res.json({ next_case_id: `VELOUR-${String(count + 1).padStart(4, '0')}` });
});

app.patch('/api/clients/:id/update-status', requirePermission('manage_users_roles'), (req, res) => {
    const clientId = parseInt(req.params.id, 10);
    const val = String(req.body?.status || 'active').toLowerCase();
    db.sqlite.prepare('UPDATE clients SET status_json = ? WHERE id = ?').run(JSON.stringify({ label: val, value: val, color: val === 'active' ? 'success' : 'secondary' }), clientId);
    res.json({ success: true, message: 'Client status updated' });
});

app.patch('/api/clients/:id/toggle-sub-client-feature', requirePermission('manage_users_roles'), (req, res) => {
    res.json({ success: true, message: 'Sub-client permissions updated' });
});

app.post('/api/clients/:id/regenerate-status-webhook-secret', requirePermission('manage_users_roles'), (req, res) => {
    res.json({ success: true, secret: 'whsec_velourcare_' + crypto.randomBytes(16).toString('hex') });
});

app.get('/api/clients/:id/allocated-vendors', requireAuth, (req, res) => {
    const clientId = parseInt(req.params.id, 10);
    if (!canAccessClient(req.user, clientId)) return res.status(403).json({ success: false, message: 'Forbidden.' });
    const vendors = db.sqlite.prepare('SELECT * FROM vendors').all().map(v => ({
        id: v.id, name: v.name, email: v.email, phone: v.phone,
        status: db.parseJson(v.status_json, {}), services: db.parseJson(v.services_json, [])
    }));
    res.json({ data: vendors });
});

app.get('/api/clients/:id/billable-preview', requireAuth, (req, res) => {
    const role = getUserRole(req.user);
    if (!['super-admin', 'admin', 'accounts', 'client'].includes(role)) {
        return res.status(403).json({ success: false, message: 'Forbidden.' });
    }
    const clientId = parseInt(req.params.id, 10);
    if (!canAccessClient(req.user, clientId)) {
        return res.status(404).json({ message: `Client #${req.params.id} not found.` });
    }
    const clientRow = db.sqlite.prepare('SELECT * FROM clients WHERE id = ?').get(clientId);
    if (!clientRow) return res.status(404).json({ message: `Client #${req.params.id} not found.` });

    const clientCases = db.sqlite.prepare('SELECT * FROM cases WHERE client_id = ? AND is_archived = 0 ORDER BY id ASC LIMIT 20').all(clientId).map(db.mapCaseRow);
    const billableLines = clientCases.map((c, idx) => {
        const forPlan = idx % 2 === 0;
        const unit = forPlan ? 1500.00 : 3000.00;
        return {
            patient_case_billable_id: idx + 1,
            case_id: c.case_id,
            patient_name: c.patient_name,
            case_owner: c.doctor_name,
            billable_for: forPlan ? 'treatment-planning' : 'manufacturing',
            billable_for_label: forPlan ? 'Treatment Planning' : 'Manufacturing',
            billable_at: formatClinicDate(),
            case_status: c.status?.label || 'In Planning',
            quantity: 1,
            unit_price: unit,
            amount: unit,
            total: unit
        };
    });
    const subtotal = billableLines.reduce((acc, l) => acc + l.total, 0);
    const tax = Math.round(subtotal * 5) / 100;
    const total = Math.round((subtotal + tax) * 100) / 100;

    res.json({
        data: {
            client_id: clientId,
            client_name: clientRow.name,
            treatment_planning_count: billableLines.filter(l => l.billable_for === 'treatment-planning').length,
            manufacturing_count: billableLines.filter(l => l.billable_for === 'manufacturing').length,
            estimated_subtotal: subtotal,
            estimated_tax: tax,
            estimated_total: total,
            estimated_total_formatted: `AED ${total.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`,
            currency: 'AED',
            billable_lines: billableLines,
            unbilled_cases: billableLines,
            total_amount: total
        }
    });
});

// ==========================================
// SUB-CLIENTS (TENANT-SCOPED + PAGINATED)
// ==========================================
app.get('/api/sub-clients/filter-options', requireAuth, (req, res) => {
    const role = getUserRole(req.user);
    const clients = role === 'client'
        ? db.sqlite.prepare('SELECT id, name FROM clients WHERE id = ?').all(Number(req.user.client_id))
        : (['super-admin', 'admin', 'planner', 'accounts'].includes(role) ? db.sqlite.prepare('SELECT id, name FROM clients ORDER BY id ASC').all() : []);
    res.json({ data: { clients: clients.map(db.plain), statuses: { active: 'Active', inactive: 'Inactive' } } });
});

app.get('/api/sub-clients', requireAuth, (req, res) => {
    const role = getUserRole(req.user);
    if (!['super-admin', 'admin', 'planner', 'accounts', 'client'].includes(role)) {
        return res.status(403).json({ success: false, message: 'Forbidden.' });
    }
    const { page, perPage, offset } = paginateParams(req.query);
    const whereSql = role === 'client' ? 'WHERE parent_client_id = ?' : '';
    const params = role === 'client' ? [Number(req.user.client_id)] : [];
    const total = db.sqlite.prepare(`SELECT COUNT(*) AS cnt FROM sub_clients ${whereSql}`).get(...params).cnt;
    const rows = db.sqlite.prepare(`SELECT * FROM sub_clients ${whereSql} ORDER BY id ASC LIMIT ? OFFSET ?`).all(...params, perPage, offset);
    const data = rows.map(r => ({
        id: r.id, name: r.name, email: r.email, phone: r.phone,
        parent_client_id: r.parent_client_id, case_id_prefix: r.case_id_prefix,
        status: db.parseJson(r.status_json, {}), ...db.parseJson(r.extra_json, {}), created_at: r.created_at
    }));
    const lastPage = Math.max(1, Math.ceil(total / perPage));
    res.json({ data, current_page: page, last_page: lastPage, per_page: perPage, total, meta: { current_page: page, last_page: lastPage, per_page: perPage, total } });
});

app.get('/api/sub-clients/:id', requireAuth, (req, res) => {
    const row = db.sqlite.prepare('SELECT * FROM sub_clients WHERE id = ?').get(parseInt(req.params.id, 10));
    if (!row || !canAccessClient(req.user, row.parent_client_id)) {
        return res.status(404).json({ message: `Sub-client #${req.params.id} not found.` });
    }
    res.json({ data: { id: row.id, name: row.name, email: row.email, phone: row.phone, parent_client_id: row.parent_client_id, status: db.parseJson(row.status_json, {}) } });
});

app.post('/api/sub-clients', requirePermission('manage_users_roles'), (req, res) => {
    const parentId = parseInt(req.body?.parent_id, 10) || 1;
    const name = sanitizeText(String(req.body?.client_name || req.body?.name || 'New Clinic Branch'));
    const prefix = sanitizeText(String(req.body?.case_id_prefix || 'SUB').toUpperCase());
    const statusJson = JSON.stringify({ label: 'Active', value: 'active', color: 'success' });
    const ins = db.sqlite.prepare('INSERT INTO sub_clients (parent_client_id, name, case_id_prefix, status_json, extra_json, created_at) VALUES (?, ?, ?, ?, ?, ?)')
        .run(parentId, name, prefix, statusJson, JSON.stringify({ cases_count: 0 }), formatClinicDateTime());
    res.json({ success: true, message: 'Sub client created successfully', data: { id: Number(ins.lastInsertRowid), name, parent_client_id: parentId, case_id_prefix: prefix } });
});

app.put(['/api/sub-clients/:id', '/api/sub-clients/:id/edit'], requirePermission('manage_users_roles'), (req, res) => {
    const id = parseInt(req.params.id, 10);
    const row = db.sqlite.prepare('SELECT * FROM sub_clients WHERE id = ?').get(id);
    if (!row) return res.status(404).json({ success: false, message: 'Sub client not found' });
    const name = req.body?.name || req.body?.client_name ? sanitizeText(String(req.body.name || req.body.client_name)) : row.name;
    db.sqlite.prepare('UPDATE sub_clients SET name = ? WHERE id = ?').run(name, id);
    res.json({ success: true, message: 'Sub client updated successfully', data: { id, name } });
});

app.delete('/api/sub-clients/:id', requirePermission('manage_users_roles'), (req, res) => {
    const info = db.sqlite.prepare('DELETE FROM sub_clients WHERE id = ?').run(parseInt(req.params.id, 10));
    if (!info.changes) return res.status(404).json({ success: false, message: 'Sub client not found' });
    res.json({ success: true, message: 'Sub client deleted successfully' });
});

app.patch('/api/sub-clients/:id/update-status', requirePermission('manage_users_roles'), (req, res) => {
    res.json({ success: true, message: 'Sub client status updated' });
});

// ==========================================
// 8. INVOICES & PAYMENTS (SQLITE ACID + CATALOG PRICING + IDEMPOTENCY)
// ==========================================
app.get('/api/invoices', requireAuth, (req, res) => {
    const role = getUserRole(req.user);
    if (role === 'planner' || role === 'vendor' || role === 'none') {
        return res.status(403).json({ success: false, message: 'Forbidden: You do not have permission to view financial invoices.' });
    }
    const { page, perPage, offset } = paginateParams(req.query);
    const where = [];
    const params = [];
    if (role === 'client') {
        where.push('client_id = ?');
        params.push(Number(req.user.client_id));
    } else if (req.query.client_id) {
        where.push('client_id = ?');
        params.push(parseInt(req.query.client_id, 10));
    }
    if (req.query.document_status) {
        where.push('document_status = ?');
        params.push(String(req.query.document_status));
    }
    if (req.query.payment_status) {
        where.push('payment_status = ?');
        params.push(String(req.query.payment_status));
    }
    const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';
    const total = db.sqlite.prepare(`SELECT COUNT(*) AS cnt FROM invoices ${whereSql}`).get(...params).cnt;
    const rows = db.sqlite.prepare(`SELECT * FROM invoices ${whereSql} ORDER BY id DESC LIMIT ? OFFSET ?`).all(...params, perPage, offset).map(r => db.mapInvoiceRow(r));
    const lastPage = Math.max(1, Math.ceil(total / perPage));
    res.json({ data: rows, current_page: page, last_page: lastPage, per_page: perPage, total });
});

app.get(['/api/invoices/filter-options', '/api/invoices/as-filter-options'], requireAuth, (req, res) => {
    const role = getUserRole(req.user);
    if (role === 'planner' || role === 'vendor' || role === 'none') {
        return res.status(403).json({ success: false, message: 'Forbidden.' });
    }
    const clients = role === 'client'
        ? db.sqlite.prepare('SELECT * FROM clients WHERE id = ?').all(Number(req.user.client_id)).map(db.mapClientRow)
        : db.sqlite.prepare('SELECT * FROM clients ORDER BY id ASC').all().map(db.mapClientRow);

    const subMap = new Map();
    for (const sc of db.sqlite.prepare('SELECT * FROM sub_clients').all()) {
        if (!subMap.has(sc.parent_client_id)) subMap.set(sc.parent_client_id, []);
        subMap.get(sc.parent_client_id).push({ id: sc.id, name: sc.name });
    }
    const formatted = clients.map(c => ({
        id: c.id, name: c.name, company_name: c.company_name || c.name,
        is_manufacturing_active: c.is_manufacturing_active || 'YES',
        tp_billing_agreement: null,
        sub_clients: subMap.get(c.id) || []
    }));
    res.json({
        data: {
            clients: formatted,
            document_statuses: { issued: 'Issued', draft: 'Draft', cancelled: 'Cancelled' },
            payment_statuses: { unpaid: 'Unpaid', paid: 'Paid', partially_paid: 'Partially Paid', failed: 'Failed' }
        },
        clients: formatted
    });
});

app.get('/api/invoices/:id', requireAuth, (req, res) => {
    const role = getUserRole(req.user);
    if (role === 'planner' || role === 'vendor' || role === 'none') {
        return res.status(403).json({ success: false, message: 'Forbidden: You do not have permission to view financial invoices.' });
    }
    const invRow = db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(parseInt(req.params.id, 10));
    if (!invRow) return res.status(404).json({ message: `Invoice #${req.params.id} not found.` });

    if (!canAccessInvoice(req.user, invRow)) {
        db.insertAuditLog({ user: req.user, action: 'IDOR_INVOICE_TAMPERING_BLOCKED', resourceType: 'invoice', resourceId: invRow.id, details: 'Unauthorized attempt to inspect another clinic invoice', ip: req.ip });
        return res.status(404).json({ message: `Invoice #${req.params.id} not found.` });
    }
    const payments = db.sqlite.prepare('SELECT id, amount_fils, method, reference, created_at FROM invoice_payments WHERE invoice_id = ? ORDER BY id ASC').all(invRow.id)
        .map(p => ({ id: p.id, amount: p.amount_fils / 100, method: p.method, reference: p.reference, date: p.created_at }));
    db.insertAuditLog({ user: req.user, action: 'VIEW_INVOICE', resourceType: 'invoice', resourceId: invRow.id, details: `Viewed invoice ${invRow.invoice_number}`, ip: req.ip });
    res.json({ data: db.mapInvoiceRow(invRow, payments) });
});

app.post('/api/invoices/generate', requirePermission('create_edit_invoices', 'Forbidden: Only Admin and Accounts can create invoices.'), (req, res) => {
    const body = req.body || {};
    const idemHeader = req.headers['idempotency-key'] ? String(req.headers['idempotency-key']).trim() : null;
    const cacheKey = idemHeader ? `${req.user.id}:POST:/api/invoices/generate:${idemHeader}` : null;

    const clientId = parseInt(body.client_id, 10);
    if (!clientId) return res.status(400).json({ success: false, message: 'Valid client_id is required.' });
    const clientRow = db.sqlite.prepare('SELECT id, name FROM clients WHERE id = ?').get(clientId);
    if (!clientRow) return res.status(404).json({ success: false, message: 'Target clinic/client not found.' });

    const itemsInput = body.items !== undefined ? body.items : [{
        service_code: BILLABLE_CATALOG[body.billable_for] ? body.billable_for : 'full-aligner-package',
        description: BILLABLE_CATALOG[body.billable_for]?.label || 'VelourCare Clear Aligner Full Treatment Package',
        quantity: 1
    }];
    const calc = calculateInvoiceTotalsServerSide(itemsInput, body.discount_percent ?? 0, 0.05);
    if (calc.error) return res.status(400).json({ success: false, message: calc.error });

    const today = formatClinicDate();
    const periodStart = sanitizeText(String(body.billing_period_start || today));
    const periodEnd = sanitizeText(String(body.billing_period_end || formatClinicDate(new Date(Date.now() + 30 * 86400000))));
    const dueDate = formatClinicDate(new Date(Date.now() + 14 * 86400000));
    const notes = body.notes ? sanitizeText(String(body.notes)) : '';

    const result = db.runTransaction(() => {
        if (cacheKey) {
            const cached = db.sqlite.prepare('SELECT status_code, response_json FROM idempotency_keys WHERE cache_key = ? AND expires_at > ?').get(cacheKey, Date.now());
            if (cached) return { statusCode: cached.status_code, payload: JSON.parse(cached.response_json), replayed: true };
        }
        const invNumber = db.getNextInvoiceNumber();
        const ins = db.sqlite.prepare(`
            INSERT INTO invoices (invoice_number, client_id, client_name, billing_period_start, billing_period_end, document_status, document_status_label, payment_status, payment_status_label, subtotal_fils, discount_fils, tax_fils, total_fils, amount_paid_fils, balance_due_fils, currency, is_locked, due_date, issued_at, created_at, notes, items_json)
            VALUES (?, ?, ?, ?, ?, 'issued', 'Issued', 'unpaid', 'Pending Payment', ?, ?, ?, ?, 0, ?, 'AED', 1, ?, ?, ?, ?, ?)
        `).run(
            invNumber, clientRow.id, clientRow.name, periodStart, periodEnd,
            calc.subtotalFils, calc.discountFils, calc.taxFils, calc.totalFils, calc.totalFils,
            dueDate, today, today, notes, JSON.stringify(calc.items)
        );
        const created = db.mapInvoiceRow(db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(Number(ins.lastInsertRowid)));
        const payload = { success: true, message: 'Invoice generated successfully', data: created };
        if (cacheKey) {
            db.sqlite.prepare('INSERT OR REPLACE INTO idempotency_keys (cache_key, status_code, response_json, expires_at) VALUES (?, ?, ?, ?)')
                .run(cacheKey, 200, JSON.stringify(payload), Date.now() + 24 * 60 * 60 * 1000);
        }
        return { statusCode: 200, payload, replayed: false };
    });

    if (!result.replayed) {
        db.insertAuditLog({ user: req.user, action: 'CREATE_INVOICE', resourceType: 'invoice', resourceId: result.payload.data.id, details: `Created invoice ${result.payload.data.invoice_number} for client ${clientRow.id}`, ip: req.ip });
    }
    res.status(result.statusCode).json(result.payload);
});

app.put('/api/invoices/:id', requirePermission('create_edit_invoices', 'Forbidden: You do not have permission to modify invoices.'), (req, res) => {
    const invId = parseInt(req.params.id, 10);
    const invRow = db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(invId);
    if (!invRow) return res.status(404).json({ success: false, message: 'Invoice not found.' });
    if (invRow.is_locked || ['issued', 'sent', 'paid'].includes(invRow.document_status) || invRow.payment_status === 'paid') {
        return res.status(400).json({ success: false, message: 'Locked: Issued, sent, or paid invoices cannot be modified directly. Please issue a credit note.' });
    }
    const body = req.body || {};
    const notes = body.notes !== undefined ? sanitizeText(String(body.notes)) : invRow.notes;
    const dueDate = body.due_date ? sanitizeText(String(body.due_date)) : invRow.due_date;
    db.sqlite.prepare('UPDATE invoices SET notes = ?, due_date = ? WHERE id = ?').run(notes, dueDate, invId);
    res.json({ success: true, message: 'Invoice updated', data: db.mapInvoiceRow(db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(invId)) });
});

app.delete('/api/invoices/:id', requirePermission('delete_anything', 'Forbidden: Only Super Administrators can delete invoices.'), (req, res) => {
    const invId = parseInt(req.params.id, 10);
    const invRow = db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(invId);
    if (!invRow) return res.status(404).json({ success: false, message: 'Invoice not found.' });
    if (invRow.is_locked || ['issued', 'sent', 'paid'].includes(invRow.document_status) || invRow.payment_status === 'paid') {
        return res.status(400).json({ success: false, message: 'Locked: Issued, sent, or paid invoices cannot be deleted. Please issue a credit note.' });
    }
    db.sqlite.prepare('DELETE FROM invoices WHERE id = ?').run(invId);
    res.json({ success: true, message: 'Invoice draft deleted' });
});

app.post('/api/invoices/:id/record-payment', requirePermission('create_edit_invoices', 'Forbidden: Only Admin and Accounts can record payments.'), (req, res) => {
    const invId = parseInt(req.params.id, 10);
    const rawAmount = Number(req.body?.amount);
    if (!Number.isFinite(rawAmount) || rawAmount <= 0) {
        return res.status(400).json({ success: false, message: 'Payment amount must be greater than zero.' });
    }
    const paymentFils = Math.round(rawAmount * 100);
    const method = sanitizeText(String(req.body?.payment_method || 'Bank Wire / Stripe'));
    const reference = sanitizeText(String(req.body?.reference || `PAY-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`));

    let updated;
    try {
        updated = db.runTransaction(() => {
            const inv = db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(invId);
            if (!inv) {
                const err = new Error('Invoice not found.');
                err.status = 404;
                throw err;
            }
            if (inv.document_status === 'cancelled') {
                const err = new Error('Cannot record payment on a cancelled invoice.');
                err.status = 409;
                throw err;
            }
            if (inv.payment_status === 'paid' || inv.balance_due_fils <= 0) {
                const err = new Error('Invoice is already paid in full.');
                err.status = 409;
                throw err;
            }
            if (paymentFils > inv.balance_due_fils) {
                const err = new Error(`Payment exceeds remaining balance due (${(inv.balance_due_fils / 100).toFixed(2)} AED).`);
                err.status = 400;
                throw err;
            }
            try {
                db.sqlite.prepare('INSERT INTO invoice_payments (invoice_id, amount_fils, method, reference, recorded_by, created_at) VALUES (?, ?, ?, ?, ?, ?)')
                    .run(invId, paymentFils, method, reference, req.user.id, new Date().toISOString());
            } catch (dupErr) {
                const err = new Error('Duplicate payment reference for this invoice.');
                err.status = 409;
                throw err;
            }

            const newPaidFils = inv.amount_paid_fils + paymentFils;
            const newDueFils = Math.max(0, inv.total_fils - newPaidFils);
            const payStatus = newDueFils === 0 ? 'paid' : 'partially_paid';
            const payLabel = newDueFils === 0 ? 'Paid in Full' : 'Partially Paid';

            db.sqlite.prepare('UPDATE invoices SET amount_paid_fils = ?, balance_due_fils = ?, payment_status = ?, payment_status_label = ? WHERE id = ?')
                .run(newPaidFils, newDueFils, payStatus, payLabel, invId);

            const payments = db.sqlite.prepare('SELECT id, amount_fils, method, reference, created_at FROM invoice_payments WHERE invoice_id = ? ORDER BY id ASC').all(invId)
                .map(p => ({ id: p.id, amount: p.amount_fils / 100, method: p.method, reference: p.reference, date: p.created_at }));
            return db.mapInvoiceRow(db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(invId), payments);
        });
    } catch (e) {
        return res.status(e.status || 400).json({ success: false, message: e.message });
    }

    db.insertAuditLog({ user: req.user, action: 'RECORD_PAYMENT', resourceType: 'invoice', resourceId: invId, details: `Recorded payment of AED ${(paymentFils / 100).toFixed(2)} on invoice ${updated.invoice_number}`, ip: req.ip });
    res.json({ success: true, message: 'Payment recorded successfully', data: updated });
});

app.post('/api/invoices/:id/mark-paid', requirePermission('create_edit_invoices', 'Forbidden: Only Admin and Accounts can mark invoices paid.'), (req, res) => {
    const invId = parseInt(req.params.id, 10);
    let updated;
    try {
        updated = db.runTransaction(() => {
            const inv = db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(invId);
            if (!inv) { const e = new Error('Invoice not found.'); e.status = 404; throw e; }
            if (inv.document_status === 'cancelled') { const e = new Error('Cancelled invoice cannot be marked paid.'); e.status = 409; throw e; }
            if (inv.payment_status === 'paid' || inv.balance_due_fils <= 0) { const e = new Error('Invoice is already paid.'); e.status = 409; throw e; }
            db.sqlite.prepare('INSERT INTO invoice_payments (invoice_id, amount_fils, method, reference, recorded_by, created_at) VALUES (?, ?, ?, ?, ?, ?)')
                .run(invId, inv.balance_due_fils, 'Manual Mark Paid', `MARKPAID-${invId}-${Date.now()}`, req.user.id, new Date().toISOString());
            db.sqlite.prepare("UPDATE invoices SET amount_paid_fils = total_fils, balance_due_fils = 0, payment_status = 'paid', payment_status_label = 'Paid in Full' WHERE id = ?").run(invId);
            return db.mapInvoiceRow(db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(invId));
        });
    } catch (e) {
        return res.status(e.status || 400).json({ success: false, message: e.message });
    }
    db.insertAuditLog({ user: req.user, action: 'INVOICE_MARKED_PAID', resourceType: 'invoice', resourceId: invId, details: `Marked invoice ${updated.invoice_number} paid`, ip: req.ip });
    res.json({ success: true, message: 'Invoice marked as paid.', data: updated });
});

app.post('/api/invoices/:id/fail-payment', requirePermission('create_edit_invoices', 'Forbidden.'), (req, res) => {
    const invId = parseInt(req.params.id, 10);
    const inv = db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(invId);
    if (!inv) return res.status(404).json({ success: false, message: 'Invoice not found.' });
    if (inv.payment_status === 'paid') return res.status(409).json({ success: false, message: 'Paid invoice cannot be marked failed.' });
    db.sqlite.prepare("UPDATE invoices SET payment_status = 'failed', payment_status_label = 'Payment Failed' WHERE id = ?").run(invId);
    db.insertAuditLog({ user: req.user, action: 'INVOICE_PAYMENT_FAILED', resourceType: 'invoice', resourceId: invId, details: `Marked payment failed for ${inv.invoice_number}`, ip: req.ip });
    res.json({ success: true, message: 'Invoice payment marked failed.', data: db.mapInvoiceRow(db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(invId)) });
});

app.post('/api/invoices/:id/cancel', requirePermission('create_edit_invoices', 'Forbidden: Only Admin and Accounts can cancel invoices.'), (req, res) => {
    const invId = parseInt(req.params.id, 10);
    const inv = db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(invId);
    if (!inv) return res.status(404).json({ success: false, message: 'Invoice not found.' });
    if (inv.payment_status === 'paid') return res.status(409).json({ success: false, message: 'Paid invoice cannot be cancelled directly.' });
    db.sqlite.prepare("UPDATE invoices SET document_status = 'cancelled', document_status_label = 'Cancelled', is_locked = 1 WHERE id = ?").run(invId);
    db.insertAuditLog({ user: req.user, action: 'INVOICE_CANCELLED', resourceType: 'invoice', resourceId: invId, details: `Cancelled invoice ${inv.invoice_number}`, ip: req.ip });
    res.json({ success: true, message: 'Invoice cancelled.', data: db.mapInvoiceRow(db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(invId)) });
});

app.post('/api/invoices/:id/issue', requirePermission('create_edit_invoices', 'Forbidden.'), (req, res) => {
    const invId = parseInt(req.params.id, 10);
    const inv = db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(invId);
    if (!inv) return res.status(404).json({ success: false, message: 'Invoice not found.' });
    if (inv.document_status === 'cancelled') return res.status(409).json({ success: false, message: 'Cancelled invoice cannot be issued.' });
    db.sqlite.prepare("UPDATE invoices SET document_status = 'issued', document_status_label = 'Issued', is_locked = 1, issued_at = ? WHERE id = ?").run(formatClinicDate(), invId);
    db.insertAuditLog({ user: req.user, action: 'INVOICE_ISSUED', resourceType: 'invoice', resourceId: invId, details: `Issued invoice ${inv.invoice_number}`, ip: req.ip });
    res.json({ success: true, message: 'Invoice issued to client.', data: db.mapInvoiceRow(db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(invId)) });
});

app.post('/api/invoices/:id/checkout', requireAuth, (req, res) => {
    const inv = db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(parseInt(req.params.id, 10));
    if (!inv || !canAccessInvoice(req.user, inv)) return res.status(404).json({ success: false, message: 'Invoice not found.' });
    if (inv.payment_status === 'paid') return res.status(409).json({ success: false, message: 'Invoice is already paid.' });
    res.json({ success: true, checkout_url: `/invoices/${inv.id}` });
});

app.post('/api/invoices/:id/submit-payment-proof', requireAuth, (req, res, next) => {
    const inv = db.sqlite.prepare('SELECT * FROM invoices WHERE id = ?').get(parseInt(req.params.id, 10));
    if (!inv || !canAccessInvoice(req.user, inv)) return res.status(404).json({ success: false, message: 'Invoice not found.' });
    req.invoiceRow = inv;
    next();
}, upload.single('payment_proof'), (req, res) => {
    if (!req.file) return res.status(400).json({ success: false, message: 'Payment proof file is required.' });
    if (!validateRequestFiles(req, res)) return;
    const proof = { filename: req.file.filename, original_name: sanitizeFileName(req.file.originalname), submitted_by: req.user.id, submitted_at: new Date().toISOString() };
    db.sqlite.prepare('UPDATE invoices SET payment_proof_json = ? WHERE id = ?').run(JSON.stringify(proof), req.invoiceRow.id);
    db.insertAuditLog({ user: req.user, action: 'PAYMENT_PROOF_SUBMITTED', resourceType: 'invoice', resourceId: req.invoiceRow.id, details: `Submitted payment proof on ${req.invoiceRow.invoice_number}`, ip: req.ip });
    res.json({ success: true, message: 'Payment proof submitted successfully.', data: proof });
});

// ==========================================
// 9. VENDORS, BANK ACCOUNTS & PATIENTS
// ==========================================
app.get('/api/vendors', requireAuth, (req, res) => {
    const role = getUserRole(req.user);
    if (!['super-admin', 'admin', 'planner', 'vendor'].includes(role)) {
        return res.status(403).json({ success: false, message: 'Forbidden.' });
    }
    const { page, perPage, offset } = paginateParams(req.query);
    const total = db.sqlite.prepare('SELECT COUNT(*) AS cnt FROM vendors').get().cnt;
    const rows = db.sqlite.prepare('SELECT * FROM vendors ORDER BY id ASC LIMIT ? OFFSET ?').all(perPage, offset).map(v => ({
        id: v.id, name: v.name, email: v.email, phone: v.phone,
        status: db.parseJson(v.status_json, {}), services: db.parseJson(v.services_json, []),
        ...db.parseJson(v.extra_json, {}), created_at: v.created_at
    }));
    const lastPage = Math.max(1, Math.ceil(total / perPage));
    res.json({ data: rows, current_page: page, last_page: lastPage, per_page: perPage, total, meta: { current_page: page, last_page: lastPage, per_page: perPage, total } });
});

app.get('/api/vendors/as-filter-options', requireAuth, (req, res) => {
    const rows = db.sqlite.prepare('SELECT id, name FROM vendors ORDER BY id ASC').all();
    res.json({ data: rows.map(v => ({ id: v.id, label: v.name })) });
});

app.get('/api/vendors/manufacturing-filter-options', requireAuth, (req, res) => {
    const rows = db.sqlite.prepare('SELECT * FROM vendors ORDER BY id ASC').all().map(v => ({ id: v.id, name: v.name, services: db.parseJson(v.services_json, []) }));
    res.json({ data: { vendors: rows, filter_options: { input_types: ['Text', 'Number', 'File', 'Date', 'Dropdown'], selection_types: ['Single', 'Multiple', 'Toggle'] } } });
});

app.get('/api/vendors/:id', requireAuth, (req, res) => {
    const role = getUserRole(req.user);
    if (!['super-admin', 'admin', 'planner', 'vendor'].includes(role)) return res.status(403).json({ success: false, message: 'Forbidden.' });
    const v = db.sqlite.prepare('SELECT * FROM vendors WHERE id = ?').get(parseInt(req.params.id, 10));
    if (!v) return res.status(404).json({ message: 'Vendor not found.' });
    res.json({ data: { id: v.id, name: v.name, email: v.email, phone: v.phone, status: db.parseJson(v.status_json, {}), services: db.parseJson(v.services_json, []) } });
});

app.post('/api/vendors', requirePermission('manage_users_roles'), upload.single('logo'), (req, res) => {
    if (!validateRequestFiles(req, res)) return;
    const name = sanitizeText(String(req.body?.vendor_name || req.body?.name || 'New Production Lab'));
    const email = sanitizeText(String(req.body?.email || 'lab@velourcare.com'));
    const ins = db.sqlite.prepare('INSERT INTO vendors (name, email, status_json, services_json, extra_json, created_at) VALUES (?, ?, ?, ?, ?, ?)')
        .run(name, email, JSON.stringify({ label: 'Active', value: 'active', color: 'success' }), '[]', JSON.stringify({ services_count: 0 }), formatClinicDateTime());
    res.json({ success: true, message: 'Vendor created successfully', data: { id: Number(ins.lastInsertRowid), name, email } });
});

app.put(['/api/vendors/:id', '/api/vendors/:id/edit'], requirePermission('manage_users_roles'), (req, res) => {
    const id = parseInt(req.params.id, 10);
    const v = db.sqlite.prepare('SELECT * FROM vendors WHERE id = ?').get(id);
    if (!v) return res.status(404).json({ success: false, message: 'Vendor not found' });
    const name = req.body?.name ? sanitizeText(String(req.body.name)) : v.name;
    const email = req.body?.email ? sanitizeText(String(req.body.email)) : v.email;
    db.sqlite.prepare('UPDATE vendors SET name = ?, email = ? WHERE id = ?').run(name, email, id);
    res.json({ success: true, message: 'Vendor updated successfully', data: { id, name, email } });
});

app.delete('/api/vendors/:id', requirePermission('manage_users_roles'), (req, res) => {
    const info = db.sqlite.prepare('DELETE FROM vendors WHERE id = ?').run(parseInt(req.params.id, 10));
    if (!info.changes) return res.status(404).json({ success: false, message: 'Vendor not found' });
    res.json({ success: true, message: 'Vendor deleted successfully' });
});

app.patch('/api/vendors/:id/update-status', requirePermission('manage_users_roles'), (req, res) => {
    res.json({ success: true, message: 'Vendor status updated' });
});

app.get(['/api/vendors/:id/services', '/api/vendors/:id/services/as-filter-options'], requireAuth, (req, res) => {
    const v = db.sqlite.prepare('SELECT services_json FROM vendors WHERE id = ?').get(parseInt(req.params.id, 10));
    if (!v) return res.status(404).json({ message: 'Vendor not found.' });
    const services = db.parseJson(v.services_json, []);
    res.json({ data: services.map(s => ({ ...s, value: s.id, label: s.name })) });
});

app.all([
    '/api/vendors/:id/services', '/api/vendors/:id/services/auth-vendor-create',
    '/api/vendors/:id/services/:serviceId', '/api/vendors/:id/services/:serviceId/auth-vendor-edit',
    '/api/vendors/:id/services/:serviceId/auth-vendor-delete',
    '/api/vendors/:id/services/:serviceId/toggle-status', '/api/vendors/:id/services/:serviceId/auth-vendor-toggle-status',
    '/api/vendors/:id/allocate-clients', '/api/vendors/:id/detach-clients/:clientId'
], requirePermission('manage_users_roles'), (req, res) => {
    res.json({ success: true, message: 'Vendor configuration updated' });
});

app.get(['/api/vendors/:id/allocated-clients', '/api/vendors/:id/allocatable-clients'], requirePermission('manage_users_roles'), (req, res) => {
    const clients = db.sqlite.prepare('SELECT * FROM clients ORDER BY id ASC').all().map(db.mapClientRow);
    res.json({ data: clients });
});

// Bank Accounts (Admin & Accounts only)
function requireBillingRead(req, res, next) {
    if (!req.user) return res.status(401).json({ message: 'Unauthenticated.' });
    const role = getUserRole(req.user);
    if (!['super-admin', 'admin', 'accounts'].includes(role)) {
        return res.status(403).json({ success: false, message: 'Forbidden: Banking details require Admin or Accounts access.' });
    }
    next();
}

app.get('/api/bank-accounts', requireBillingRead, (req, res) => {
    const { page, perPage, offset } = paginateParams(req.query);
    const total = db.sqlite.prepare('SELECT COUNT(*) AS cnt FROM bank_accounts').get().cnt;
    const rows = db.sqlite.prepare('SELECT * FROM bank_accounts ORDER BY id ASC LIMIT ? OFFSET ?').all(perPage, offset).map(b => ({ ...db.plain(b), is_default: Boolean(b.is_default) }));
    const lastPage = Math.max(1, Math.ceil(total / perPage));
    res.json({ data: rows, current_page: page, last_page: lastPage, per_page: perPage, total });
});

app.get(['/api/bank-accounts/as-filter-options', '/api/bank-accounts/filter-options'], requireBillingRead, (req, res) => {
    const rows = db.sqlite.prepare('SELECT * FROM bank_accounts ORDER BY id ASC').all();
    res.json({
        data: rows.map(b => ({
            id: b.id, value: b.id, label: `${b.bank_name} - ${b.account_number} (${b.currency})`,
            bank_name: b.bank_name, account_number: b.account_number, currency: b.currency, is_default: Boolean(b.is_default)
        }))
    });
});

app.get('/api/bank-accounts/:id', requireBillingRead, (req, res) => {
    const acc = db.sqlite.prepare('SELECT * FROM bank_accounts WHERE id = ?').get(parseInt(req.params.id, 10));
    if (!acc) return res.status(404).json({ message: `Bank account #${req.params.id} not found.` });
    res.json({ data: { ...db.plain(acc), is_default: Boolean(acc.is_default) } });
});

app.post('/api/bank-accounts', requirePermission('manage_users_roles'), (req, res) => {
    const body = req.body || {};
    const ins = db.sqlite.prepare('INSERT INTO bank_accounts (bank_name, account_name, account_number, iban, swift_code, currency, is_default) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(sanitizeText(String(body.bank_name || 'Emirates NBD')), sanitizeText(String(body.account_title || body.account_name || 'VelourCare Ortho')), sanitizeText(String(body.account_number || '000000000')), sanitizeText(String(body.iban || '')), sanitizeText(String(body.swift_code || '')), sanitizeText(String(body.currency || 'AED')), body.is_default ? 1 : 0);
    const created = db.plain(db.sqlite.prepare('SELECT * FROM bank_accounts WHERE id = ?').get(Number(ins.lastInsertRowid)));
    res.json({ success: true, message: 'Bank account created successfully', data: created });
});

app.put('/api/bank-accounts/:id', requirePermission('manage_users_roles'), (req, res) => {
    const id = parseInt(req.params.id, 10);
    const acc = db.sqlite.prepare('SELECT * FROM bank_accounts WHERE id = ?').get(id);
    if (!acc) return res.status(404).json({ message: 'Bank account not found' });
    db.sqlite.prepare('UPDATE bank_accounts SET bank_name = ? WHERE id = ?').run(sanitizeText(String(req.body?.bank_name || acc.bank_name)), id);
    res.json({ success: true, message: 'Bank account updated successfully' });
});

app.delete('/api/bank-accounts/:id', requirePermission('manage_users_roles'), (req, res) => {
    const info = db.sqlite.prepare('DELETE FROM bank_accounts WHERE id = ?').run(parseInt(req.params.id, 10));
    if (!info.changes) return res.status(404).json({ message: 'Bank account not found' });
    res.json({ success: true, message: 'Bank account deleted successfully' });
});

app.patch('/api/bank-accounts/:id/set-default', requirePermission('manage_users_roles'), (req, res) => {
    const id = parseInt(req.params.id, 10);
    db.runTransaction(() => {
        db.sqlite.prepare('UPDATE bank_accounts SET is_default = 0').run();
        db.sqlite.prepare('UPDATE bank_accounts SET is_default = 1 WHERE id = ?').run(id);
    });
    res.json({ success: true, message: 'Default bank account updated' });
});

// Patients (Strictly Tenant & Ownership Scoped + Paginated + XSS Sanitized)
app.get('/api/patients', requireAuth, (req, res) => {
    const scope = buildCaseScopeSql(req.user);
    if (scope.empty) {
        return res.status(403).json({ success: false, message: 'Forbidden: You do not have permission to view patient PHI.' });
    }
    const { page, perPage, offset } = paginateParams(req.query);
    const total = db.sqlite.prepare(`SELECT COUNT(*) AS cnt FROM cases WHERE ${scope.sql}`).get(...scope.params).cnt;
    const rows = db.sqlite.prepare(`SELECT * FROM cases WHERE ${scope.sql} ORDER BY id ASC LIMIT ? OFFSET ?`).all(...scope.params, perPage, offset);
    const patients = rows.map(c => ({
        id: c.id,
        name: c.patient_name,
        gender: c.patient_gender,
        age: c.patient_age,
        email: c.patient_email,
        phone: c.patient_phone,
        case_id: c.case_id,
        status: db.parseJson(c.status_json, {})
    }));
    const lastPage = Math.max(1, Math.ceil(total / perPage));
    res.json({ data: patients, current_page: page, last_page: lastPage, per_page: perPage, total });
});

app.get('/api/patients/:id', ...requireCaseAccess('view_all_cases'), (req, res) => {
    const c = req.caseRow;
    res.json({
        data: {
            id: c.id,
            name: c.patient_name,
            gender: c.patient_gender,
            age: c.patient_age,
            email: c.patient_email,
            phone: c.patient_phone,
            address: c.patient_address || '',
            case_id: c.case_id,
            status: c.status
        }
    });
});

function updatePatientHandler(req, res) {
    if (!validateRequestFiles(req, res)) return;
    const c = req.caseRow;
    const body = req.body || {};
    const name = body.name !== undefined ? sanitizeText(String(body.name)) : c.patient_name;
    const gender = body.gender !== undefined ? sanitizeText(String(body.gender)) : c.patient_gender;
    const email = body.email !== undefined ? sanitizeText(String(body.email)) : c.patient_email;
    const phone = body.phone !== undefined ? sanitizeText(String(body.phone)) : c.patient_phone;
    const address = body.address !== undefined ? sanitizeText(String(body.address)) : (c.patient_address || '');
    const dob = body.date_of_birth !== undefined ? sanitizeText(String(body.date_of_birth)) : c.patient_date_of_birth;
    const nationalId = body.national_id !== undefined ? sanitizeText(String(body.national_id)) : c.patient_national_id;
    const residency = body.residency_type !== undefined ? sanitizeText(String(body.residency_type)) : c.patient_residency_type;
    const medHistory = body.medical_history !== undefined ? sanitizeText(String(body.medical_history)) : (c.patient_medical_history || '');

    db.sqlite.prepare(`
        UPDATE cases SET patient_name = ?, patient_gender = ?, patient_email = ?, patient_phone = ?, patient_address = ?, patient_dob = ?, patient_national_id = ?, patient_residency_type = ?, patient_medical_history = ?, updated_at = ?
        WHERE id = ?
    `).run(name, gender, email, phone, address, dob, nationalId, residency, medHistory, formatClinicDateTime(), c.id);

    db.insertAuditLog({ user: req.user, action: 'PATIENT_UPDATED', resourceType: 'case', resourceId: c.id, details: `Updated patient details on case ${c.case_id}`, ip: req.ip });
    res.json({
        success: true,
        message: 'Patient details updated successfully',
        data: { id: c.id, name, gender, email, phone, address, date_of_birth: dob, national_id: nationalId, residency_type: residency, medical_history: medHistory }
    });
}

app.put(['/api/patients/:id', '/api/patients/:id/edit'], ...requireCaseAccess('create_edit_case'), upload.any(), updatePatientHandler);
app.post('/api/patients/:id', ...requireCaseAccess('create_edit_case'), upload.any(), updatePatientHandler);

// ==========================================
// 10. STRIPE, API CREDENTIALS & WEBSOCKET AUTH
// ==========================================
app.get('/api/stripe/platform-status', requireBillingRead, (req, res) => {
    res.json({ data: { connected: true, account_id: 'acct_velourcare_platform', currency: 'AED', payouts_enabled: true, charges_enabled: true } });
});

app.get('/api/clients/:id/stripe-connect', requireAuth, (req, res) => {
    const clientId = parseInt(req.params.id, 10);
    if (!canAccessClient(req.user, clientId)) return res.status(403).json({ success: false, message: 'Forbidden.' });
    res.json({ data: { connected: true, onboarded: true, details_submitted: true, payouts_enabled: true } });
});

app.post('/api/clients/:id/stripe-connect/onboard', requirePermission('manage_users_roles'), (req, res) => {
    res.json({ status: 'pending', url: 'https://connect.stripe.com/setup/s/velourcare-onboard' });
});

app.get('/api/client-api-credentials', requirePermission('manage_users_roles'), (req, res) => {
    res.json({ data: [{ id: 1, name: 'EMR / Dental Clinic PMS Integration', created_at: '2026-03-15' }] });
});

app.post(['/broadcasting/auth', '/api/broadcasting/auth'], requireAuth, (req, res) => {
    const { socket_id, channel_name } = req.body || {};
    if (!socket_id || !channel_name) return res.status(400).json({ message: 'socket_id and channel_name required.' });
    res.json({
        auth: 'velourcare-pusher-auth:' + crypto.createHash('sha256').update(`${req.user.id}:${socket_id}:${channel_name}`).digest('hex').slice(0, 16),
        channel_data: JSON.stringify({ user_id: req.user.id, user_info: { name: req.user.name } })
    });
});

// ==========================================
// 11. AUDIT LOGS, BACKUPS, HEALTH & LEGAL
// ==========================================
app.get('/api/audit-logs', requirePermission('view_audit_log', 'Forbidden: Audit logs can only be inspected by Super Administrators.'), (req, res) => {
    const { page, perPage, offset } = paginateParams(req.query, { defaultPerPage: 100, maxPerPage: 200 });
    const { total, rows } = db.queryAuditLogs({
        action: req.query.action ? String(req.query.action) : null,
        username: req.query.username ? String(req.query.username) : null,
        limit: perPage,
        offset
    });
    res.json({ success: true, total, current_page: page, per_page: perPage, data: rows });
});

app.post('/api/admin/backups/create', requirePermission('manage_users_roles', 'Forbidden: Super Administrator access required.'), (req, res) => {
    const { createBackup } = require('./scripts/backup.js');
    const result = createBackup(db.exportSnapshot({ includeAuthSecrets: false }), db.getPortalSettingsObj());
    db.insertAuditLog({ user: req.user, action: 'BACKUP_CREATED', details: `Created backup archive ${result.fileName}`, ip: req.ip });
    res.json(result);
});

app.post('/api/admin/backups/restore', requirePermission('manage_users_roles', 'Forbidden: Super Administrator access required.'), (req, res) => {
    const { restoreBackup } = require('./scripts/restore.js');
    const backupsDir = path.join(__dirname, 'backups');
    const files = fs.existsSync(backupsDir) ? fs.readdirSync(backupsDir).filter(f => f.endsWith('.json')).sort().reverse() : [];
    if (files.length === 0) return res.status(400).json({ message: 'No backup archives available to restore.' });
    const result = restoreBackup(path.join(backupsDir, files[0]), db);
    db.insertAuditLog({ user: req.user, action: 'BACKUP_RESTORED', details: `Restored backup from ${result.restoredTimestamp}`, ip: req.ip });
    res.json(result);
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.get('/api/permission-matrix', requireAuth, (req, res) => {
    res.json({ success: true, matrix: PERMISSION_MATRIX });
});

app.get('/api/legal/privacy-policy', (req, res) => {
    res.json({
        title: 'VelourCare Ortho Cloud Privacy Policy',
        version: '1.0.0',
        effective_date: 'November 2026',
        compliance: ['UAE Federal Health Data Law No. 2 of 2019', 'HIPAA 45 CFR Part 160/164', 'GDPR Art. 9 Special Category Data'],
        dpo_email: 'privacy@velourcare.com'
    });
});

app.get('/api/legal/terms-of-service', (req, res) => {
    res.json({
        title: 'VelourCare Ortho Cloud Terms of Service',
        version: '1.0.0',
        clinical_disclaimer: 'Treating orthodontist/dentist retains sole clinical responsibility for patient examination, treatment plan approval, and aligner fit.'
    });
});

// ==========================================
// 12. PROTECTED SIGNED DOWNLOADS & /uploads
// ==========================================
app.get('/api/files/signed-download-token', requireAuth, (req, res) => {
    const role = getUserRole(req.user);
    if (role === 'accounts' || role === 'none') {
        return res.status(403).json({ message: 'Forbidden: Your role cannot access clinical files.' });
    }
    const rawFile = req.query.filename;
    const caseId = parseInt(req.query.case_id, 10);
    if (!rawFile || !Number.isFinite(caseId) || caseId <= 0) {
        return res.status(400).json({ message: 'Both filename and valid numeric case_id are required.' });
    }
    const safeName = path.basename(String(rawFile));
    const caseRow = db.sqlite.prepare('SELECT * FROM cases WHERE id = ? AND is_archived = 0').get(caseId);
    if (!caseRow) return res.status(404).json({ message: 'Case not found.' });
    const mappedCase = db.mapCaseRow(caseRow);
    if (!canAccessCase(req.user, mappedCase, 'view_all_cases')) {
        return res.status(404).json({ message: 'Case not found.' });
    }
    if (!db.caseHasFile(caseId, safeName)) {
        return res.status(404).json({ message: 'File does not belong to the specified case.' });
    }

    const token = 'sig-' + crypto.randomBytes(24).toString('hex');
    signedFileTokens.set(token, {
        filename: safeName,
        caseId,
        userId: req.user.id,
        expiresAt: Date.now() + 15 * 60 * 1000
    });
    db.insertAuditLog({ user: req.user, action: 'SIGNED_URL_MINTED', resourceType: 'case', resourceId: caseId, details: `Minted download token for ${safeName}`, ip: req.ip });
    res.json({ success: true, token, download_url: `/api/files/signed-download?token=${token}` });
});

app.get('/api/files/signed-download', (req, res) => {
    const token = String(req.query.token || '');
    if (!token || !signedFileTokens.has(token)) {
        return res.status(403).json({ message: 'Invalid or expired file download signature.' });
    }
    const rec = signedFileTokens.get(token);
    signedFileTokens.delete(token); // Single-use token
    if (Date.now() > rec.expiresAt) {
        return res.status(403).json({ message: 'Download signature has expired.' });
    }
    const safeName = path.basename(rec.filename);
    const filePath = path.join(uploadDir, safeName);
    const pubPath = path.join(publicUploads, safeName);
    const target = fs.existsSync(filePath) ? filePath : (fs.existsSync(pubPath) ? pubPath : null);
    if (!target) return res.status(404).json({ message: 'File not found on storage.' });

    db.insertAuditLog({ user: { id: rec.userId, username: `user#${rec.userId}`, role_slug: 'verified' }, action: 'SIGNED_FILE_DOWNLOAD', resourceType: 'case', resourceId: rec.caseId, details: `Downloaded ${safeName}`, ip: req.ip });
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
    res.download(target, safeName);
});

app.get('/uploads/:filename', (req, res) => {
    if (!req.user) {
        return res.status(401).json({ message: 'Unauthenticated. PHI scan assets require an authorized session.' });
    }
    const role = getUserRole(req.user);
    if (role === 'accounts' || role === 'none') {
        return res.status(403).json({ message: 'Forbidden: Accounts and unauthorized roles cannot access clinical scan assets.' });
    }

    const safeName = path.basename(String(req.params.filename || ''));
    if (!safeName || safeName === '.' || safeName === '..') {
        return res.status(404).json({ message: 'File not found.' });
    }

    const ownership = db.findFileOwnership(safeName);
    const filePath = path.join(uploadDir, safeName);
    const pubPath = path.join(publicUploads, safeName);

    if (ownership) {
        const caseRow = db.sqlite.prepare('SELECT * FROM cases WHERE id = ? AND is_archived = 0').get(ownership.case_id);
        if (!caseRow || !canAccessCase(req.user, db.mapCaseRow(caseRow), 'view_all_cases')) {
            return res.status(404).json({ message: 'File not found.' });
        }
    } else if (!fs.existsSync(pubPath)) {
        // Never serve unlinked files from runtime uploads/
        return res.status(404).json({ message: 'File not found.' });
    }

    const target = fs.existsSync(filePath) ? filePath : (fs.existsSync(pubPath) ? pubPath : null);
    if (!target) return res.status(404).json({ message: 'File not found.' });

    db.insertAuditLog({ user: req.user, action: 'DOWNLOAD_FILE', resourceType: 'case', resourceId: ownership ? ownership.case_id : null, details: `Downloaded ${safeName}`, ip: req.ip });
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
    res.sendFile(target);
});

// ==========================================
// 13. STATIC ASSETS, SPA ROUTING & ERROR HANDLER
// ==========================================
app.get(['/assets/vc-connect-logo.png', '/assets/velourcare-logo.png'], (req, res) => {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.sendFile(path.resolve(publicAssets, 'vc-connect-logo-v2.png'));
});
app.get(['/assets/vc-connect-square.png', '/assets/velourcare-square.png'], (req, res) => {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.sendFile(path.resolve(publicAssets, 'vc-connect-square-v2.png'));
});

app.use('/assets', express.static(publicAssets, {
    setHeaders: (res, filePath) => {
        if (/\.(png|jpe?g|gif|svg|ico|webp)$/i.test(filePath) || /BrandImage/i.test(filePath)) {
            res.setHeader('Cache-Control', 'no-cache, must-revalidate');
        } else {
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        }
    }
}));

app.use(express.static(publicPath, { maxAge: 0 }));

app.get(['/clients/:id', '/sub-clients/:id', '/vendors/:id'], (req, res, next) => {
    if (req.accepts('html') && !req.headers['accept']?.includes('application/json')) {
        return res.redirect(302, `${req.path}/edit`);
    }
    next();
});

app.use((req, res) => {
    if (req.method === 'GET' && !req.path.startsWith('/api/') && !req.path.startsWith('/sanctum/') && !req.path.includes('.') && req.accepts('html') && !req.headers['accept']?.includes('application/json')) {
        return res.sendFile(path.join(publicPath, 'index.html'));
    }
    res.status(404).json({ message: `Endpoint ${req.path} not found.` });
});

app.use((err, req, res, next) => {
    cleanupUploadedFiles(req);
    if (err.code === 'INVALID_FILE_TYPE' || err.name === 'MulterError' || (err.message && err.message.includes('not permitted'))) {
        return res.status(400).json({ success: false, message: err.message });
    }
    console.error('Server error:', err.message);
    res.status(500).json({
        success: false,
        message: 'An unexpected internal error occurred. Please contact VelourCare support.'
    });
});

app.listen(PORT, () => {
    console.log('=======================================================');
    console.log('  VC CONNECT PORTAL IS RUNNING (SQLite Hardened Mode)  ');
    console.log(`  Local URL:  http://localhost:${PORT}                 `);
    console.log(`  Database:   ${db.dbPath}                             `);
    console.log('=======================================================');
});
