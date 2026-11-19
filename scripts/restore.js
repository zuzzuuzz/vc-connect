/**
 * VelourCare Ortho Cloud — Hardened Backup Restore & Integrity Verification Utility
 * Restores configuration, decrypts encrypted backups when configured, and restores SQLite state.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function decryptPayload(enc, secretKey) {
    const key = crypto.createHash('sha256').update(String(secretKey)).digest();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(enc.iv, 'hex'));
    decipher.setAuthTag(Buffer.from(enc.tag, 'hex'));
    const decrypted = Buffer.concat([decipher.update(Buffer.from(enc.ciphertext, 'base64')), decipher.final()]);
    return JSON.parse(decrypted.toString('utf8'));
}

function restoreBackup(backupFilePath, dbInstance = null) {
    if (!fs.existsSync(backupFilePath)) {
        throw new Error(`Backup file does not exist: ${backupFilePath}`);
    }

    const backupData = JSON.parse(fs.readFileSync(backupFilePath, 'utf8'));
    if (!backupData.version || !backupData.timestamp) {
        throw new Error('Invalid backup archive format: missing version or timestamp.');
    }

    let auditLogs = backupData.auditLogs || [];
    let database = backupData.database || {};
    if (backupData.encrypted && backupData.encryptedPayload) {
        const encKey = process.env.BACKUP_ENCRYPTION_KEY;
        if (!encKey) {
            throw new Error('BACKUP_ENCRYPTION_KEY is required to restore an encrypted backup.');
        }
        const decrypted = decryptPayload(backupData.encryptedPayload, encKey);
        auditLogs = decrypted.auditLogs || [];
        database = decrypted.database || {};
    }

    if (process.env.PERSIST_STATE !== 'false' && (!dbInstance || dbInstance.dbPath !== ':memory:') && backupData.portalConfig && typeof backupData.portalConfig === 'object') {
        const configPath = path.join(__dirname, '..', 'data', 'portal_config.json');
        const tmpPath = configPath + '.tmp';
        fs.writeFileSync(tmpPath, JSON.stringify(backupData.portalConfig, null, 2), 'utf8');
        fs.renameSync(tmpPath, configPath);
    }

    let ownDb = null;
    const db = dbInstance || (() => {
        const { createDatabase } = require('../db');
        ownDb = createDatabase();
        return ownDb;
    })();

    try {
        const stats = db.restoreSnapshot({ ...database, auditLogs });
        console.log(`[RESTORE VERIFICATION] Restored ${stats.casesRestored} cases, ${stats.invoicesRestored} invoices, ${auditLogs.length} audit logs.`);
        return {
            success: true,
            restoredTimestamp: backupData.timestamp,
            auditLogsRestored: auditLogs.length,
            casesVerified: stats.casesRestored,
            invoicesVerified: stats.invoicesRestored,
            filesTracked: (backupData.fileInventory || []).length
        };
    } finally {
        if (ownDb) ownDb.sqlite.close();
    }
}

if (require.main === module) {
    const backupsDir = path.join(__dirname, '..', 'backups');
    const files = fs.readdirSync(backupsDir).filter(f => f.endsWith('.json'));
    if (files.length === 0) {
        console.error('No backup files found in /backups.');
        process.exit(1);
    }
    const latest = files.sort().reverse()[0];
    const result = restoreBackup(path.join(backupsDir, latest));
    console.log(JSON.stringify(result, null, 2));
}

module.exports = { restoreBackup };
