/**
 * VelourCare Ortho Cloud — Hardened Backup Engine
 * Creates atomic timestamped backups of SQLite snapshot, portal configuration,
 * audit trails, and file inventory. Never writes raw password hashes in plaintext backups.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const backupsDir = path.join(__dirname, '..', 'backups');
if (!fs.existsSync(backupsDir)) {
    fs.mkdirSync(backupsDir, { recursive: true });
}

function sanitizeDatabasePayload(payload) {
    if (!payload || typeof payload !== 'object') return {};
    const copy = { ...payload };
    if (Array.isArray(copy.users)) {
        copy.users = copy.users.map(u => {
            const clean = { ...u };
            delete clean.password_hash;
            delete clean.password_salt;
            return clean;
        });
    }
    return copy;
}

function encryptPayload(obj, secretKey) {
    const key = crypto.createHash('sha256').update(String(secretKey)).digest();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
        algorithm: 'aes-256-gcm',
        iv: iv.toString('hex'),
        tag: tag.toString('hex'),
        ciphertext: encrypted.toString('base64')
    };
}

function createBackup(customPayload = null, portalConfigOverride = null) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFileName = `velourcare-backup-${timestamp}.json`;
    const backupFilePath = path.join(backupsDir, backupFileName);
    const tmpPath = backupFilePath + '.tmp';

    const configPath = path.join(__dirname, '..', 'data', 'portal_config.json');
    const uploadsPath = path.join(__dirname, '..', 'uploads');

    let portalConfig = portalConfigOverride || {};
    if (!portalConfigOverride && fs.existsSync(configPath)) {
        try { portalConfig = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch (e) {}
    }

    let snapshot = customPayload;
    if (!snapshot) {
        const { createDatabase } = require('../db');
        const db = createDatabase();
        try {
            snapshot = db.exportSnapshot({ includeAuthSecrets: false });
        } finally {
            db.sqlite.close();
        }
    }

    const auditLogs = Array.isArray(snapshot.auditLogs) ? snapshot.auditLogs : [];
    const safeDb = sanitizeDatabasePayload({
        clients: snapshot.clients || [],
        users: snapshot.users || [],
        cases: snapshot.cases || [],
        invoices: snapshot.invoices || []
    });

    let fileInventory = [];
    if (fs.existsSync(uploadsPath)) {
        fileInventory = fs.readdirSync(uploadsPath).filter(f => f !== '.gitkeep').map(file => {
            const stat = fs.statSync(path.join(uploadsPath, file));
            return { name: file, size: stat.size, mtime: stat.mtime };
        });
    }

    const encKey = process.env.BACKUP_ENCRYPTION_KEY;
    const backupData = {
        version: '2.0.0',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'production',
        encrypted: Boolean(encKey),
        portalConfig,
        fileInventory
    };

    if (encKey) {
        backupData.encryptedPayload = encryptPayload({ auditLogs, database: safeDb }, encKey);
    } else {
        backupData.auditLogs = auditLogs;
        backupData.database = safeDb;
    }

    fs.writeFileSync(tmpPath, JSON.stringify(backupData, null, 2), 'utf8');
    fs.renameSync(tmpPath, backupFilePath);
    console.log(`[BACKUP SUCCESS] Created backup at: ${backupFilePath} (${fileInventory.length} uploads tracked)`);
    return { success: true, filePath: backupFilePath, fileName: backupFileName, timestamp: backupData.timestamp };
}

if (require.main === module) {
    const res = createBackup();
    console.log(JSON.stringify(res, null, 2));
}

module.exports = { createBackup };
