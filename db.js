const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const ALL_PERMISSION_NAMES = [
    'view_users', 'manage_users_permissions',
    'view_clients', 'edit_clients',
    'view_sub_clients', 'edit_sub_clients',
    'view_vendors', 'edit_vendors', 'allocate_vendor_clients',
    'view_cases', 'create_cases', 'delete_cases', 'view_case_activities',
    'view_treatment_plans', 'create_treatment_plans', 'edit_treatment_plans', 'view_treatment_plan_reviews',
    'view_invoices', 'create_invoices', 'export_invoices',
    'view_roles', 'manage_roles_permissions',
    'view_bank_accounts',
    'manage_stripe_platform', 'manage_stripe_connect',
    'view_api_credentials'
];

const PERMISSION_MATRIX = {
    'super-admin': {
        view_all_cases: 'Y', create_edit_case: 'Y', upload_scans_photos: 'Y',
        approve_treatment_plan: 'Y', view_production_queue: 'Y', update_production_status: 'Y',
        view_invoices: 'Y', create_edit_invoices: 'Y', delete_anything: 'Y',
        export_data: 'Y', manage_users_roles: 'Y', view_audit_log: 'Y'
    },
    'admin': {
        view_all_cases: 'Y', create_edit_case: 'Y', upload_scans_photos: 'Y',
        approve_treatment_plan: 'Y', view_production_queue: 'Y', update_production_status: 'Y',
        view_invoices: 'Y', create_edit_invoices: 'Y', delete_anything: 'Y',
        export_data: 'Y', manage_users_roles: 'Y', view_audit_log: 'Y'
    },
    'planner': {
        view_all_cases: 'Y', create_edit_case: 'Y', upload_scans_photos: 'Y',
        approve_treatment_plan: 'Y', view_production_queue: 'Y', update_production_status: 'N',
        view_invoices: 'N', create_edit_invoices: 'N', delete_anything: 'N',
        export_data: 'N', manage_users_roles: 'N', view_audit_log: 'N'
    },
    'vendor': {
        view_all_cases: 'Assigned', create_edit_case: 'N', upload_scans_photos: 'N',
        approve_treatment_plan: 'N', view_production_queue: 'Y', update_production_status: 'Y',
        view_invoices: 'N', create_edit_invoices: 'N', delete_anything: 'N',
        export_data: 'N', manage_users_roles: 'N', view_audit_log: 'N'
    },
    'accounts': {
        view_all_cases: 'N', create_edit_case: 'N', upload_scans_photos: 'N',
        approve_treatment_plan: 'N', view_production_queue: 'N', update_production_status: 'N',
        view_invoices: 'Y', create_edit_invoices: 'Y', delete_anything: 'N',
        export_data: 'Y_invoices', manage_users_roles: 'N', view_audit_log: 'N'
    },
    'client': {
        view_all_cases: 'Own', create_edit_case: 'Own_create', upload_scans_photos: 'Own',
        approve_treatment_plan: 'Own_approve', view_production_queue: 'N', update_production_status: 'N',
        view_invoices: 'Own', create_edit_invoices: 'N', delete_anything: 'N',
        export_data: 'N', manage_users_roles: 'N', view_audit_log: 'N'
    },
    'none': {
        view_all_cases: 'N', create_edit_case: 'N', upload_scans_photos: 'N',
        approve_treatment_plan: 'N', view_production_queue: 'N', update_production_status: 'N',
        view_invoices: 'N', create_edit_invoices: 'N', delete_anything: 'N',
        export_data: 'N', manage_users_roles: 'N', view_audit_log: 'N'
    }
};

function hashPasswordSync(password, salt = null) {
    const useSalt = salt || crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, useSalt, 64).toString('hex');
    return { hash, salt: useSalt };
}

function hashPasswordAsync(password, salt = null) {
    return new Promise((resolve, reject) => {
        const useSalt = salt || crypto.randomBytes(16).toString('hex');
        crypto.scrypt(password, useSalt, 64, (err, key) => {
            if (err) return reject(err);
            resolve({ hash: key.toString('hex'), salt: useSalt });
        });
    });
}

function verifyPasswordAsync(password, hash, salt) {
    return new Promise((resolve) => {
        if (!password || !hash || !salt || typeof password !== 'string') return resolve(false);
        crypto.scrypt(password, salt, 64, (err, computed) => {
            if (err) return resolve(false);
            try {
                const hashBuf = Buffer.from(hash, 'hex');
                if (hashBuf.length !== computed.length) return resolve(false);
                resolve(crypto.timingSafeEqual(hashBuf, computed));
            } catch (e) {
                resolve(false);
            }
        });
    });
}

function parseJson(raw, fallback) {
    if (raw === null || raw === undefined || raw === '') return fallback;
    try { return JSON.parse(raw); } catch (e) { return fallback; }
}

function plain(row) {
    return row ? { ...row } : null;
}

function serializeUser(u) {
    if (!u) return null;
    const out = { ...u };
    delete out.password_hash;
    delete out.password_salt;
    return out;
}

function createDatabase(customPath = null) {
    const dbPath = customPath || process.env.DB_PATH || (process.env.PERSIST_STATE === 'false' ? ':memory:' : path.join(__dirname, 'data', 'velourcare.sqlite'));
    if (dbPath !== ':memory:') {
        fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    }

    const sqlite = new DatabaseSync(dbPath);
    sqlite.exec(`
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;
        PRAGMA synchronous = NORMAL;
        PRAGMA busy_timeout = 5000;
    `);

    sqlite.exec(`
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            company_title TEXT,
            company_name TEXT,
            email TEXT,
            phone TEXT,
            case_id_prefix TEXT NOT NULL DEFAULT 'CLI',
            is_manufacturing_active TEXT DEFAULT 'YES',
            is_express_delivery_active TEXT DEFAULT 'NO',
            is_alphanumeric_case_id_active TEXT DEFAULT 'YES',
            is_sub_clients_allowed TEXT DEFAULT 'NO',
            last_case_number INTEGER DEFAULT 0,
            country TEXT DEFAULT 'United Arab Emirates',
            login_uri TEXT,
            status_json TEXT,
            addresses_json TEXT,
            extra_json TEXT,
            created_at TEXT,
            updated_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_clients_prefix ON clients(case_id_prefix);
        CREATE INDEX IF NOT EXISTS idx_clients_login_uri ON clients(login_uri);

        CREATE TABLE IF NOT EXISTS sub_clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            case_id_prefix TEXT,
            status_json TEXT,
            extra_json TEXT,
            created_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_sub_clients_parent_id ON sub_clients(parent_client_id);

        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            label TEXT,
            permissions_json TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            full_name TEXT,
            first_name TEXT,
            last_name TEXT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT,
            role_slug TEXT NOT NULL DEFAULT 'none',
            gender TEXT,
            is_super_admin INTEGER NOT NULL DEFAULT 0,
            client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL,
            see_only_own_uploads INTEGER NOT NULL DEFAULT 0,
            status_value TEXT NOT NULL DEFAULT 'active',
            status_json TEXT,
            profile_pic_url TEXT,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            permissions_json TEXT,
            integrations_json TEXT,
            assigned_role_modal_json TEXT,
            extra_json TEXT,
            created_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_users_client_id ON users(client_id);
        CREATE INDEX IF NOT EXISTS idx_users_role_slug ON users(role_slug);

        CREATE TABLE IF NOT EXISTS vendors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            status_json TEXT,
            services_json TEXT,
            extra_json TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT UNIQUE NOT NULL,
            patient_name TEXT NOT NULL,
            patient_age INTEGER,
            patient_gender TEXT,
            patient_email TEXT,
            patient_phone TEXT,
            patient_dob TEXT,
            patient_national_id TEXT,
            patient_residency_type TEXT,
            patient_address TEXT,
            patient_medical_history TEXT,
            doctor_name TEXT,
            doctor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            uploader_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            doctor_email TEXT,
            client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
            client_name TEXT,
            vendor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            category TEXT,
            category_type TEXT,
            status_value TEXT NOT NULL DEFAULT 'newly-created',
            status_json TEXT,
            is_draft INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 1,
            is_archived INTEGER NOT NULL DEFAULT 0,
            archived_at TEXT,
            archived_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            deadline TEXT,
            upper_aligners INTEGER NOT NULL DEFAULT 0,
            lower_aligners INTEGER NOT NULL DEFAULT 0,
            chief_complaint TEXT,
            malocclusion TEXT,
            clinical_json TEXT,
            shipment_batches_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_cases_client_id ON cases(client_id, is_archived, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_cases_doctor_id ON cases(doctor_id);
        CREATE INDEX IF NOT EXISTS idx_cases_uploader_id ON cases(uploader_id);
        CREATE INDEX IF NOT EXISTS idx_cases_created_by ON cases(created_by);
        CREATE INDEX IF NOT EXISTS idx_cases_vendor_id ON cases(vendor_id);
        CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status_value, is_archived);
        CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at DESC);

        CREATE TABLE IF NOT EXISTS treatment_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            title TEXT,
            has_plan_document INTEGER NOT NULL DEFAULT 1,
            upper_aligner_count INTEGER NOT NULL DEFAULT 0,
            lower_aligner_count INTEGER NOT NULL DEFAULT 0,
            status_value TEXT NOT NULL DEFAULT 'pending-review',
            status_json TEXT,
            ipr_chart_file_url TEXT,
            container_file_url TEXT,
            zip_file_url TEXT,
            simulation_link TEXT,
            description TEXT,
            plan_document_json TEXT,
            review_json TEXT,
            created_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_treatment_plans_case_id ON treatment_plans(case_id);

        CREATE TABLE IF NOT EXISTS case_attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
            uploader_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            disk_filename TEXT UNIQUE NOT NULL,
            original_name TEXT NOT NULL,
            file_url TEXT NOT NULL,
            file_size TEXT,
            mime_type TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_case_attachments_case_id ON case_attachments(case_id);
        CREATE INDEX IF NOT EXISTS idx_case_attachments_client_id ON case_attachments(client_id);

        CREATE TABLE IF NOT EXISTS step_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
            uploader_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            v_tratransfer_link TEXT,
            description TEXT,
            disk_filename TEXT,
            zip_file_url TEXT,
            zip_file_name TEXT,
            status_json TEXT,
            created_at TEXT,
            updated_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_step_files_case_id ON step_files(case_id);
        CREATE INDEX IF NOT EXISTS idx_step_files_disk_filename ON step_files(disk_filename);

        CREATE TABLE IF NOT EXISTS case_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            user_name TEXT,
            user_role TEXT,
            user_pic TEXT,
            content TEXT NOT NULL,
            attachments_json TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_case_comments_case_id ON case_comments(case_id, created_at ASC);
        CREATE INDEX IF NOT EXISTS idx_case_comments_user_id ON case_comments(user_id);

        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_number TEXT UNIQUE NOT NULL,
            client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
            client_name TEXT,
            case_id INTEGER REFERENCES cases(id) ON DELETE SET NULL,
            plan_id INTEGER REFERENCES treatment_plans(id) ON DELETE SET NULL,
            patient_name TEXT,
            billing_period_start TEXT,
            billing_period_end TEXT,
            document_status TEXT NOT NULL DEFAULT 'issued',
            document_status_label TEXT,
            payment_status TEXT NOT NULL DEFAULT 'unpaid',
            payment_status_label TEXT,
            subtotal_fils INTEGER NOT NULL,
            discount_fils INTEGER NOT NULL DEFAULT 0,
            tax_fils INTEGER NOT NULL DEFAULT 0,
            total_fils INTEGER NOT NULL,
            amount_paid_fils INTEGER NOT NULL DEFAULT 0,
            balance_due_fils INTEGER NOT NULL,
            currency TEXT NOT NULL DEFAULT 'AED',
            is_locked INTEGER NOT NULL DEFAULT 1,
            due_date TEXT,
            issued_at TEXT,
            created_at TEXT NOT NULL,
            notes TEXT,
            items_json TEXT NOT NULL,
            payment_proof_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_invoices_client_id ON invoices(client_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_invoices_case_id ON invoices(case_id);
        CREATE INDEX IF NOT EXISTS idx_invoices_payment_status ON invoices(payment_status);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_invoices_plan_approval ON invoices(case_id, plan_id) WHERE plan_id IS NOT NULL AND document_status != 'cancelled';

        CREATE TABLE IF NOT EXISTS invoice_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_id INTEGER NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
            amount_fils INTEGER NOT NULL,
            method TEXT,
            reference TEXT NOT NULL,
            recorded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL,
            UNIQUE(invoice_id, reference)
        );
        CREATE INDEX IF NOT EXISTS idx_invoice_payments_invoice_id ON invoice_payments(invoice_id);

        CREATE TABLE IF NOT EXISTS bank_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bank_name TEXT NOT NULL,
            account_name TEXT NOT NULL,
            account_number TEXT NOT NULL,
            iban TEXT,
            swift_code TEXT,
            currency TEXT NOT NULL DEFAULT 'AED',
            branch TEXT,
            is_default INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            message TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_chat_sender ON chat_messages(sender_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_chat_receiver ON chat_messages(receiver_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            category TEXT NOT NULL DEFAULT 'alerts',
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id, is_read, created_at DESC);

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at INTEGER NOT NULL,
            last_active_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            ip_address TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

        CREATE TABLE IF NOT EXISTS idempotency_keys (
            cache_key TEXT PRIMARY KEY,
            status_code INTEGER NOT NULL,
            response_json TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_idempotency_expires ON idempotency_keys(expires_at);

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id INTEGER,
            username TEXT,
            role TEXT,
            client_id INTEGER,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            details TEXT,
            ip_address TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_audit_logs_ts ON audit_logs(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);

        CREATE TABLE IF NOT EXISTS counters (
            name TEXT PRIMARY KEY,
            value INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS portal_settings (
            key TEXT PRIMARY KEY,
            value_json TEXT NOT NULL
        );
    `);

    function runTransaction(fn) {
        sqlite.exec('BEGIN IMMEDIATE');
        try {
            const result = fn();
            sqlite.exec('COMMIT');
            return result;
        } catch (err) {
            try { sqlite.exec('ROLLBACK'); } catch (e) {}
            throw err;
        }
    }

    function mapClientRow(row) {
        if (!row) return null;
        const r = plain(row);
        const addrs = parseJson(r.addresses_json, []);
        const extra = parseJson(r.extra_json, {});
        const status = parseJson(r.status_json, { label: 'Active', color: 'success', value: 'active' });
        return {
            ...extra,
            id: r.id,
            name: r.name,
            company_title: r.company_title || r.name,
            company_name: r.company_name || r.name,
            email: r.email,
            phone: r.phone,
            case_id_prefix: r.case_id_prefix,
            is_manufacturing_active: r.is_manufacturing_active,
            is_express_delivery_active: r.is_express_delivery_active,
            is_alphanumeric_case_id_active: r.is_alphanumeric_case_id_active,
            is_sub_clients_allowed: r.is_sub_clients_allowed,
            last_case_number: r.last_case_number,
            country: r.country,
            login_uri: r.login_uri,
            status,
            addresses: addrs,
            shipment_addresses: addrs,
            created_at: r.created_at,
            updated_at: extra.updated_at_obj || r.updated_at
        };
    }

    function mapUserRow(row, clientMap = null) {
        if (!row) return null;
        const r = plain(row);
        const extra = parseJson(r.extra_json, {});
        const permissions = parseJson(r.permissions_json, []);
        const integrations = parseJson(r.integrations_json, {});
        const assignedRoleModal = parseJson(r.assigned_role_modal_json, null);
        const status = parseJson(r.status_json, { label: 'Active', value: r.status_value || 'active', color: r.status_value === 'active' ? 'success' : 'secondary' });
        let clientObj = extra.client || null;
        if (!clientObj && r.client_id) {
            const cRow = clientMap ? clientMap.get(r.client_id) : sqlite.prepare('SELECT id, name, case_id_prefix, is_manufacturing_active FROM clients WHERE id = ?').get(r.client_id);
            if (cRow) {
                clientObj = {
                    id: cRow.id,
                    name: cRow.name,
                    case_id_prefix: cRow.case_id_prefix,
                    is_manufacturing_active: cRow.is_manufacturing_active
                };
            }
        }
        return {
            ...extra,
            id: r.id,
            name: r.name,
            fullName: r.full_name || r.name,
            first_name: r.first_name,
            last_name: r.last_name,
            username: r.username,
            email: r.email,
            phone: r.phone,
            role_slug: r.role_slug,
            gender: r.gender,
            is_super_admin: Boolean(r.is_super_admin),
            client_id: r.client_id,
            see_only_own_uploads: Boolean(r.see_only_own_uploads),
            status,
            profile_pic_url: r.profile_pic_url,
            password_hash: r.password_hash,
            password_salt: r.password_salt,
            permissions,
            integrations,
            assigned_role_modal: assignedRoleModal,
            client: clientObj,
            created_at: r.created_at
        };
    }

    function mapCaseRow(row) {
        if (!row) return null;
        const r = plain(row);
        const status = parseJson(r.status_json, { value: r.status_value, label: r.status_value, color: 'primary' });
        const clinical = parseJson(r.clinical_json, {});
        const batches = parseJson(r.shipment_batches_json, []);
        return {
            id: r.id,
            case_id: r.case_id,
            caseId: r.case_id,
            patient_name: r.patient_name,
            patient_age: r.patient_age,
            patient_gender: r.patient_gender,
            patient_email: r.patient_email,
            patient_phone: r.patient_phone,
            patient_date_of_birth: r.patient_dob,
            patient_national_id: r.patient_national_id,
            patient_residency_type: r.patient_residency_type,
            patient_address: r.patient_address,
            patient_medical_history: r.patient_medical_history,
            patient: {
                name: r.patient_name,
                email: r.patient_email,
                age: r.patient_age,
                gender: r.patient_gender,
                dob: r.patient_dob,
                phone: r.patient_phone,
                address: r.patient_address,
                residencyType: r.patient_residency_type,
                nationalId: r.patient_national_id,
                medicalHistory: r.patient_medical_history
            },
            doctor_name: r.doctor_name,
            caseDoctor: r.doctor_name,
            doctor_id: r.doctor_id,
            uploader_id: r.uploader_id,
            created_by: r.created_by,
            doctor_email: r.doctor_email,
            client_id: r.client_id,
            client_name: r.client_name,
            client: { id: r.client_id, name: r.client_name, parent_client: null },
            vendor_id: r.vendor_id,
            category: r.category,
            caseCategory: r.category,
            caseCategoryType: r.category_type,
            status,
            isDraftCase: Boolean(r.is_draft),
            version: r.version,
            is_archived: Boolean(r.is_archived),
            archived_at: r.archived_at,
            archived_by: r.archived_by,
            deadline: r.deadline,
            upper_aligners: r.upper_aligners,
            lower_aligners: r.lower_aligners,
            chief_complaint: r.chief_complaint,
            chiefComplaint: r.chief_complaint,
            malocclusion: r.malocclusion,
            ...clinical,
            shipment_batches: batches,
            created_at: r.created_at,
            createdAt: { human_readable: r.created_at, timestamp: r.created_at, iso_date: r.created_at },
            updated_at: r.updated_at,
            updatedAt: { human_readable: r.updated_at, timestamp: r.updated_at }
        };
    }

    function mapPlanRow(row) {
        if (!row) return null;
        const r = plain(row);
        return {
            id: r.id,
            case_id: r.case_id,
            title: r.title,
            has_plan_document: Boolean(r.has_plan_document),
            upper_aligner_count: r.upper_aligner_count,
            lower_aligner_count: r.lower_aligner_count,
            status: parseJson(r.status_json, { value: r.status_value, label: r.status_value, color: 'info' }),
            ipr_chart_file_url: r.ipr_chart_file_url,
            container_file_url: r.container_file_url,
            zip_file_url: r.zip_file_url,
            simulation_link: r.simulation_link,
            description: r.description,
            modifications: [],
            review: parseJson(r.review_json, null),
            plan_document_data: parseJson(r.plan_document_json, {}),
            created_at: { human_readable: r.created_at, timestamp: r.created_at }
        };
    }

    function mapAttachmentRow(row) {
        if (!row) return null;
        const r = plain(row);
        return {
            id: r.id,
            case_id: r.case_id,
            client_id: r.client_id,
            uploader_id: r.uploader_id,
            disk_filename: r.disk_filename,
            name: r.original_name,
            file_url: r.file_url,
            file_size: r.file_size,
            type: r.mime_type,
            created_at: r.created_at
        };
    }

    function mapStepFileRow(row) {
        if (!row) return null;
        const r = plain(row);
        return {
            id: r.id,
            case_id: r.case_id,
            client_id: r.client_id,
            uploader_id: r.uploader_id,
            v_tratransfer_link: r.v_tratransfer_link,
            description: r.description,
            zip_file_url: r.zip_file_url,
            zip_file_name: r.zip_file_name,
            status: parseJson(r.status_json, { value: 'pending', label: 'Pending', color: 'info' }),
            created_at: { human_readable: r.created_at, timestamp: r.created_at },
            updated_at: { human_readable: r.updated_at, timestamp: r.updated_at }
        };
    }

    function mapInvoiceRow(row, payments = null) {
        if (!row) return null;
        const r = plain(row);
        const items = parseJson(r.items_json, []).map(it => {
            const unit = Number(it.unit_amount ?? it.unit_price ?? 0);
            const tot = Number(it.total_amount ?? it.total ?? 0);
            return { ...it, unit_price: unit, unit_amount: unit, total: tot, total_amount: tot };
        });
        const subtotal = r.subtotal_fils / 100;
        const discount = r.discount_fils / 100;
        const tax = r.tax_fils / 100;
        const total = r.total_fils / 100;
        const amountPaid = r.amount_paid_fils / 100;
        const balanceDue = r.balance_due_fils / 100;
        const out = {
            id: r.id,
            invoice_number: r.invoice_number,
            client_id: r.client_id,
            client_name: r.client_name,
            client: { id: r.client_id, name: r.client_name },
            case_id: r.case_id,
            plan_id: r.plan_id,
            patient_name: r.patient_name,
            billing_period_start: r.billing_period_start,
            billing_period_end: r.billing_period_end,
            status: r.document_status,
            document_status: r.document_status,
            document_status_label: r.document_status_label,
            payment_status: r.payment_status,
            payment_status_label: r.payment_status_label,
            subtotal,
            discount,
            tax,
            amount: total,
            total,
            amount_paid: amountPaid,
            balance_due: balanceDue,
            currency: r.currency,
            is_locked: Boolean(r.is_locked),
            due_date: r.due_date,
            issued_at: r.issued_at,
            created_at: r.created_at,
            notes: r.notes || '',
            items,
            payment_proof: parseJson(r.payment_proof_json, null)
        };
        if (payments) out.payments = payments;
        return out;
    }

    function seedIfEmpty() {
        const userCount = sqlite.prepare('SELECT COUNT(*) AS cnt FROM users').get().cnt;
        if (userCount > 0) return;

        const bootstrapPassword = process.env.SEED_DEFAULT_PASSWORD || (process.env.NODE_ENV === 'production' ? null : 'VelourSecure2026!#');
        if (!bootstrapPassword) {
            throw new Error('Production startup aborted: database has no users and SEED_DEFAULT_PASSWORD is not configured.');
        }

        let portalConfig = {};
        const cfgFile = path.join(__dirname, 'data', 'portal_config.json');
        if (fs.existsSync(cfgFile)) {
            try { portalConfig = JSON.parse(fs.readFileSync(cfgFile, 'utf8')); } catch (e) {}
        }

        runTransaction(() => {
            // 1. Portal settings dropdown metadata
            const settingKeys = ['residencyTypes', 'caseCategories', 'caseCategoryTypes', 'deliveryTimes', 'jawArchTypes', 'jawArchCorrections', 'jawToothFormats'];
            const defaultSettings = {
                residencyTypes: { local: 'Local Resident', overseas: 'Overseas', travelling: 'Travelling / Tourist', expat: 'Expatriate Resident', gcc_national: 'GCC National' },
                caseCategories: { Aligners: 'Aligners', Retainers: 'Retainers', Refinements: 'Refinements', Nightguards: 'Nightguards', 'Sleep Apnea Splints': 'Sleep Apnea Splints' },
                caseCategoryTypes: { Dentist: 'Dentist', Orthodontist: 'Orthodontist', 'Oral Surgeon': 'Oral Surgeon' },
                deliveryTimes: { '4 hrs': '4 hrs (Emergency Rush)', '8 hrs': '8 hrs (Express)', '24 hrs': '24 hrs (Standard)', '48 hrs': '48 hrs (Economy)' },
                jawArchTypes: { 'Both Arch': 'Both Arch (Dual Arch)', 'Upper only': 'Upper Arch Only', 'Lower only': 'Lower Arch Only' },
                jawArchCorrections: { '(3-3)': 'Anterior Only (3-3)', '(5-5)': 'Premolar to Premolar (5-5)', 'Full arch correction': 'Full Arch Molar-to-Molar Correction' },
                jawToothFormats: { 'FDI Notation': 'FDI Two-Digit (ISO 3950)', 'Universal Notation': 'Universal Numbering System (1-32)', 'Palmer Notation': 'Palmer Notation' }
            };
            const insSetting = sqlite.prepare('INSERT OR REPLACE INTO portal_settings (key, value_json) VALUES (?, ?)');
            for (const k of settingKeys) {
                insSetting.run(k, JSON.stringify(portalConfig[k] || defaultSettings[k]));
            }

            // 2. Clients
            const defaultClients = [
                {
                    id: 1,
                    name: 'Wright Orthodontics Clinic',
                    company_title: 'Wright Orthodontics',
                    company_name: 'Wright Orthodontics',
                    email: 'doctor@velourcare.com',
                    phone: '+971 50 123 4567',
                    case_id_prefix: 'WRIGHT',
                    is_manufacturing_active: 'YES',
                    is_express_delivery_active: 'YES',
                    is_alphanumeric_case_id_active: 'YES',
                    is_sub_clients_allowed: 'YES',
                    last_case_number: 48,
                    country: 'United Arab Emirates',
                    login_uri: 'wright-ortho',
                    addresses: [
                        { id: 1, is_default: true, title: 'Main Practice Dubai Healthcare City', address_line_1: 'Building 64, Al Razi Medical Complex, Suite 302', city: 'Dubai', country: 'United Arab Emirates', phone: '+971 4 398 2211' }
                    ],
                    extra: { balance: 14200, currency: 'AED', sub_clients_count: 2, cases_count: 48, logo_url: '/assets/velourcare-square.png', login_image_url: '/assets/login-page-logo-BDn48l5g.jpeg' }
                },
                {
                    id: 2,
                    name: 'Emirates Smile Design Dental Center',
                    company_title: 'Emirates Smile Clinic',
                    company_name: 'Emirates Smile Design Dental Center',
                    email: 'contact@emiratessmile.ae',
                    phone: '+971 2 644 8899',
                    case_id_prefix: 'ESMILE',
                    is_manufacturing_active: 'YES',
                    is_express_delivery_active: 'YES',
                    is_alphanumeric_case_id_active: 'YES',
                    is_sub_clients_allowed: 'YES',
                    last_case_number: 36,
                    country: 'United Arab Emirates',
                    login_uri: 'emirates-smile',
                    addresses: [
                        { id: 2, is_default: true, title: 'Abu Dhabi Corniche Branch', address_line_1: 'Corniche Road, Tower A, 5th Floor', city: 'Abu Dhabi', country: 'United Arab Emirates', phone: '+971 2 644 8899' }
                    ],
                    extra: { balance: 9500, currency: 'AED', sub_clients_count: 1, cases_count: 36, logo_url: '/assets/velourcare-square.png', login_image_url: '/assets/login-page-logo-BDn48l5g.jpeg' }
                }
            ];
            const cfgClients = Array.isArray(portalConfig.clients) ? portalConfig.clients : [];
            const mergedClients = [];
            const seenIds = new Set();
            for (const dc of defaultClients) {
                const match = cfgClients.find(c => c.id === dc.id);
                const addrs = (match && (match.addresses || match.shipment_addresses)) || dc.addresses;
                mergedClients.push({
                    ...dc,
                    ...(match || {}),
                    addresses: addrs,
                    extra: { ...dc.extra, sub_clients: (match && match.sub_clients) || [] }
                });
                seenIds.add(dc.id);
            }
            for (const cc of cfgClients) {
                if (!seenIds.has(cc.id)) {
                    const addrs = cc.addresses || cc.shipment_addresses || [];
                    mergedClients.push({
                        ...cc,
                        addresses: addrs,
                        extra: { sub_clients: cc.sub_clients || [], logo_url: '/assets/velourcare-square.png' }
                    });
                }
            }
            const insClient = sqlite.prepare(`
                INSERT INTO clients (id, name, company_title, company_name, email, phone, case_id_prefix, is_manufacturing_active, is_express_delivery_active, is_alphanumeric_case_id_active, is_sub_clients_allowed, last_case_number, country, login_uri, status_json, addresses_json, extra_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `);
            for (const c of mergedClients) {
                insClient.run(
                    c.id, c.name, c.company_title || c.name, c.company_name || c.name,
                    c.email || 'clinic@velourcare.com', c.phone || '+971 4 000 0000',
                    c.case_id_prefix || 'CLI', c.is_manufacturing_active || 'YES',
                    c.is_express_delivery_active || 'NO', c.is_alphanumeric_case_id_active || 'YES',
                    c.is_sub_clients_allowed || 'NO', c.last_case_number || 0,
                    c.country || 'United Arab Emirates', c.login_uri || (c.case_id_prefix || '').toLowerCase(),
                    JSON.stringify({ label: 'Active', color: 'success', value: 'active' }),
                    JSON.stringify(c.addresses || []),
                    JSON.stringify(c.extra || {}),
                    '2026-02-10 09:00', '2026-10-24 10:00'
                );
            }

            // 3. Sub-clients
            sqlite.prepare(`
                INSERT INTO sub_clients (id, parent_client_id, name, email, phone, case_id_prefix, status_json, extra_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(1, 1, 'Wright Ortho Jumeirah Branch', 'jumeirah@wrightortho.com', '+971 4 344 1122', 'WRIGHTJ',
                JSON.stringify({ label: 'Active', color: 'success', value: 'active' }),
                JSON.stringify({ parent_client: { id: 1, name: 'Wright Orthodontics Clinic' }, cases_count: 14, is_sub_clients_allowed: 'YES' }),
                '2026-04-12 09:00'
            );

            // 4. Roles
            const seedRoles = [
                { id: 1, name: 'super-admin', label: 'Super Admin', permissions: ALL_PERMISSION_NAMES },
                { id: 2, name: 'admin', label: 'Admin', permissions: ALL_PERMISSION_NAMES.filter(p => p !== 'manage_stripe_platform') },
                { id: 3, name: 'case-coordinator', label: 'Case Coordinator', permissions: ['view_clients', 'view_sub_clients', 'view_cases', 'create_cases', 'view_case_activities', 'view_treatment_plans', 'edit_treatment_plans', 'view_invoices'] },
                { id: 4, name: 'planner', label: 'CAD Planner', permissions: ['view_clients', 'view_vendors', 'view_cases', 'edit_treatment_plans'] },
                { id: 5, name: 'client', label: 'Client / Doctor', permissions: ['view_clients', 'view_sub_clients', 'view_cases', 'create_cases', 'view_case_activities', 'view_treatment_plans', 'edit_treatment_plans', 'view_invoices'] },
                { id: 6, name: 'sub-client', label: 'Sub Client', permissions: ['view_cases', 'create_cases', 'view_case_activities', 'view_treatment_plans', 'edit_treatment_plans'] },
                { id: 7, name: 'vendor', label: 'Vendor / Lab', permissions: ['view_vendors', 'view_cases'] },
                { id: 8, name: 'accounts', label: 'Accounts', permissions: ['view_invoices', 'create_invoices', 'export_invoices', 'view_bank_accounts'] }
            ];
            const insRole = sqlite.prepare('INSERT INTO roles (id, name, label, permissions_json, created_at) VALUES (?, ?, ?, ?, ?)');
            for (const r of seedRoles) {
                insRole.run(r.id, r.name, r.label, JSON.stringify(r.permissions), '2026-01-01');
            }

            // 5. Users (each gets an independent random cryptographic salt!)
            const seedUsers = [
                {
                    id: 1, name: 'VelourCare Super Administrator', first_name: 'VelourCare', last_name: 'Super Administrator',
                    username: 'admin', email: 'admin@velourcare.com', phone: '+971 4 800 8356', role_slug: 'super-admin',
                    gender: 'female', is_super_admin: 1, client_id: 1, see_only_own_uploads: 0,
                    profile_pic_url: '/assets/velourcare-square.png', permissions: ALL_PERMISSION_NAMES,
                    integrations: { waveatp: true, smile_inspector: true },
                    assigned_role_modal: { id: 1, name: 'VelourCare Orthodontics HQ', company_name: 'VC Connect', login_uri: 'velourcare', login_image_url: '/assets/login-page-logo-BDn48l5g.jpeg', navigation_logo_url: '/assets/vc-connect-logo-v2.png', logo_url: '/assets/vc-connect-square-v2.png' }
                },
                {
                    id: 2, name: 'Dr. Alexander Wright, DDS, MS', first_name: 'Alexander', last_name: 'Wright',
                    username: 'doctor', email: 'doctor@velourcare.com', phone: '+971 50 123 4567', role_slug: 'client',
                    gender: 'male', is_super_admin: 0, client_id: 1, see_only_own_uploads: 0,
                    profile_pic_url: '/assets/vc-connect-square-v2.png',
                    permissions: ['view_clients', 'view_sub_clients', 'view_cases', 'create_cases', 'view_case_activities', 'view_treatment_plans', 'edit_treatment_plans', 'view_invoices'],
                    integrations: { waveatp: true, smile_inspector: true },
                    assigned_role_modal: { id: 2, name: 'Wright Orthodontic Clinic', company_name: 'VC Connect', login_uri: 'wright-ortho', login_image_url: '/assets/login-page-logo-BDn48l5g.jpeg', navigation_logo_url: '/assets/vc-connect-logo-v2.png', logo_url: '/assets/vc-connect-square-v2.png', sub_client_feature_access: { step_files: true, invoices: true, chat: true } }
                },
                {
                    id: 3, name: 'Sarah Miller (Senior CAD Planner)', first_name: 'Sarah', last_name: 'Miller',
                    username: 'planner', email: 'planner@velourcare.com', phone: '+971 4 800 8358', role_slug: 'planner',
                    gender: 'female', is_super_admin: 0, client_id: null, see_only_own_uploads: 0,
                    profile_pic_url: '/assets/vc-connect-square-v2.png',
                    permissions: ['view_clients', 'view_vendors', 'view_cases', 'edit_treatment_plans'],
                    integrations: { waveatp: true, smile_inspector: true },
                    assigned_role_modal: { id: 3, name: 'VelourCare Digital Planning Studio', company_name: 'VC Connect', navigation_logo_url: '/assets/vc-connect-logo-v2.png' }
                },
                {
                    id: 4, name: 'VelourCare Aligner Lab', first_name: 'Production', last_name: 'Lab',
                    username: 'lab', email: 'lab@velourcare.com', phone: '+971 4 800 8359', role_slug: 'vendor',
                    gender: 'other', is_super_admin: 0, client_id: null, see_only_own_uploads: 0,
                    profile_pic_url: '/assets/vc-connect-square-v2.png',
                    permissions: ['view_vendors', 'view_cases'],
                    integrations: { waveatp: true, smile_inspector: true },
                    assigned_role_modal: { id: 4, name: 'VelourCare 3D Production Lab', company_name: 'VC Connect', navigation_logo_url: '/assets/vc-connect-logo-v2.png' }
                },
                {
                    id: 5, name: 'Kareem Haddad (Billing & Accounts)', first_name: 'Kareem', last_name: 'Haddad',
                    username: 'accounts', email: 'accounts@velourcare.com', phone: '+971 4 800 8355', role_slug: 'accounts',
                    gender: 'male', is_super_admin: 0, client_id: null, see_only_own_uploads: 0,
                    profile_pic_url: '/assets/vc-connect-square-v2.png',
                    permissions: ['view_invoices', 'create_invoices', 'export_invoices', 'view_bank_accounts'],
                    integrations: { waveatp: false, smile_inspector: false },
                    assigned_role_modal: { id: 5, name: 'VelourCare Finance & Accounts', company_name: 'VC Connect', navigation_logo_url: '/assets/vc-connect-logo-v2.png' }
                },
                {
                    id: 6, name: 'Dr. Elena Rostova (Clinic B)', first_name: 'Elena', last_name: 'Rostova',
                    username: 'doctor_b', email: 'doctor_b@velourcare.com', phone: '+971 2 644 8899', role_slug: 'client',
                    gender: 'female', is_super_admin: 0, client_id: 2, see_only_own_uploads: 0,
                    profile_pic_url: '/assets/velourcare-square.png',
                    permissions: ['view_clients', 'view_sub_clients', 'view_cases', 'create_cases', 'view_case_activities', 'view_treatment_plans', 'edit_treatment_plans', 'view_invoices'],
                    integrations: { waveatp: true, smile_inspector: true },
                    assigned_role_modal: { id: 6, name: 'Emirates Smile Design Dental Center', company_name: 'Emirates Smile Design Center', login_uri: 'emirates-smile', login_image_url: '/assets/login-page-logo-BDn48l5g.jpeg', navigation_logo_url: '/assets/vc-connect-logo-v2.png', logo_url: '/assets/vc-connect-square-v2.png' }
                },
                {
                    id: 7, name: 'Unassigned Staff (Pending Role)', first_name: 'Unassigned', last_name: 'User',
                    username: 'new_user', email: 'unassigned@velourcare.com', phone: '+971 4 000 0000', role_slug: 'none',
                    gender: 'other', is_super_admin: 0, client_id: null, see_only_own_uploads: 0,
                    profile_pic_url: '/assets/vc-connect-square-v2.png',
                    permissions: [], integrations: {}, assigned_role_modal: null
                },
                {
                    id: 8, name: 'Dr. Emily Watson (Associate)', first_name: 'Emily', last_name: 'Watson',
                    username: 'doctor_associate', email: 'associate@wrightortho.com', phone: '+971 4 398 2212', role_slug: 'client',
                    gender: 'female', is_super_admin: 0, client_id: 1, see_only_own_uploads: 1,
                    profile_pic_url: '/assets/vc-connect-square-v2.png',
                    permissions: ['view_clients', 'view_sub_clients', 'view_cases', 'create_cases', 'view_case_activities', 'view_treatment_plans', 'edit_treatment_plans', 'view_invoices'],
                    integrations: { waveatp: true, smile_inspector: true },
                    assigned_role_modal: { id: 2, name: 'Wright Orthodontic Clinic', company_name: 'Wright Orthodontics', login_uri: 'wright-ortho', login_image_url: '/assets/login-page-logo-BDn48l5g.jpeg', navigation_logo_url: '/assets/vc-connect-logo-v2.png', logo_url: '/assets/vc-connect-square-v2.png' }
                }
            ];
            const insUser = sqlite.prepare(`
                INSERT INTO users (id, name, full_name, first_name, last_name, username, email, phone, role_slug, gender, is_super_admin, client_id, see_only_own_uploads, status_value, status_json, profile_pic_url, password_hash, password_salt, permissions_json, integrations_json, assigned_role_modal_json, extra_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, '2026-01-01 09:00')
            `);
            for (const u of seedUsers) {
                const { hash, salt } = hashPasswordSync(bootstrapPassword);
                insUser.run(
                    u.id, u.name, u.name, u.first_name, u.last_name, u.username, u.email, u.phone,
                    u.role_slug, u.gender, u.is_super_admin, u.client_id, u.see_only_own_uploads,
                    JSON.stringify({ label: 'Active', value: 'active', color: 'success' }),
                    u.profile_pic_url, hash, salt,
                    JSON.stringify(u.permissions), JSON.stringify(u.integrations),
                    u.assigned_role_modal ? JSON.stringify(u.assigned_role_modal) : null,
                    JSON.stringify({})
                );
            }

            // 6. Vendors & Bank Accounts
            sqlite.prepare(`
                INSERT INTO vendors (id, name, email, phone, status_json, services_json, extra_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
                1, 'VelourCare Advanced 3D Fabrication Facility', 'production@velourcare.com', '+971 4 800 8350',
                JSON.stringify({ label: 'Active', color: 'success', value: 'active' }),
                JSON.stringify([
                    { id: 1, name: '3D Aligner Model Printing (Dental Resin)', price: 35.00, status: 'active' },
                    { id: 2, name: 'Multi-Layer Thermoforming & Laser Trimming', price: 65.00, status: 'active' },
                    { id: 3, name: 'Laser Tooth Number & Patient ID Marking', price: 10.00, status: 'active' }
                ]),
                JSON.stringify({ services_count: 3, allocated_clients_count: 12 }),
                '2026-01-10 08:00'
            );

            sqlite.prepare(`
                INSERT INTO bank_accounts (id, bank_name, account_name, account_number, iban, swift_code, currency, branch, is_default)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(1, 'Emirates NBD Bank', 'VelourCare Orthodontics Medical LLC', '1012398745601', 'AE0702600001012398745601', 'EBILAEADXXX', 'AED', 'Downtown Dubai Corporate Branch', 1);

            // 7. Cases (1..6)
            const seedCases = [
                {
                    id: 1, case_id: 'VELOUR-0001', patient_name: 'Fatima Al-Nuaimi', patient_age: 26, patient_gender: 'Female',
                    patient_email: 'fatima.nuaimi@example.ae', patient_phone: '+971 55 987 6543', patient_dob: '2000-05-14',
                    doctor_name: 'Dr. Alexander Wright', doctor_id: 2, uploader_id: 2, created_by: 2, doctor_email: 'doctor@velourcare.com',
                    client_id: 1, client_name: 'Wright Orthodontics Clinic', vendor_id: null, category: 'New Case', category_type: 'Aligners',
                    status: { value: 'review-treatment-plan', label: 'Review Treatment Plan', color: 'info' },
                    deadline: '2026-11-05', upper_aligners: 22, lower_aligners: 18,
                    chief_complaint: 'Anterior crowding and midline shift', malocclusion: 'Class I Malocclusion with severe upper anterior crowding',
                    clinical: {
                        siCaseCode: 'SI-9921', waveatpPtId: 'WAVE-4820',
                        jawArchType: 'Dual Arch (Upper & Lower)', jawArchCorrection: 'Both Arches', jawToothFormat: 'FDI Two-Digit (ISO 3950)',
                        needsIpr: 'Yes (1.20mm Total IPR Protocol)', needsAttachments: 'Yes (Standard Optimized Attachments)', needsExtraction: 'No Extraction Required',
                        treatmentPlan: 'VelourCare Clear Aligners 22 Upper / 18 Lower with Staged IPR Protocol',
                        planningDuration: { deliveryTime: '48h SLA', isTimerPaused: false, lastHoldAt: null, deadline: { iso_date: '2026-11-05T18:00:00Z' }, completedAt: null }
                    },
                    batches: [
                        { id: 1, batch_number: 'BATCH-01', aligners_range: '01 to 10', status: 'delivered', tracking_number: 'DHL-98421092' },
                        { id: 2, batch_number: 'BATCH-02', aligners_range: '11 to 22', status: 'in-production', tracking_number: null }
                    ],
                    created_at: '2026-10-15 09:30', updated_at: '2026-10-24 14:15'
                },
                {
                    id: 2, case_id: 'VELOUR-0002', patient_name: 'Marcus Vance', patient_age: 34, patient_gender: 'Male',
                    patient_email: 'marcus.v@example.com', patient_phone: '+971 50 321 9876', patient_dob: '1992-08-19',
                    doctor_name: 'Dr. Alexander Wright', doctor_id: 2, uploader_id: 2, created_by: 2, doctor_email: 'doctor@velourcare.com',
                    client_id: 1, client_name: 'Wright Orthodontics Clinic', vendor_id: null, category: 'New Case', category_type: 'Aligners',
                    status: { value: 'in-planning', label: 'In Planning', color: 'primary' },
                    deadline: '2026-11-02', upper_aligners: 28, lower_aligners: 24,
                    chief_complaint: 'Deep overbite and spacing in lower arch', malocclusion: 'Class II Division 2 with 80% deep bite',
                    clinical: { siCaseCode: 'SI-9922', waveatpPtId: 'WAVE-4821', planningDuration: { deliveryTime: '24h SLA', isTimerPaused: false, lastHoldAt: null, deadline: { iso_date: '2026-11-02T12:00:00Z' }, completedAt: null } },
                    batches: [], created_at: '2026-10-18 11:20', updated_at: '2026-10-25 16:40'
                },
                {
                    id: 3, case_id: 'REF1-VELOUR-0003', patient_name: 'Zainab Rashid', patient_age: 22, patient_gender: 'Female',
                    patient_email: 'zainab.r@example.com', patient_phone: '+971 52 444 1100', patient_dob: '2004-02-11',
                    doctor_name: 'Dr. Alexander Wright', doctor_id: 2, uploader_id: 2, created_by: 2, doctor_email: 'doctor@velourcare.com',
                    client_id: 1, client_name: 'Wright Orthodontics Clinic', vendor_id: 4, category: 'Refinements', category_type: 'Aligners',
                    status: { value: 'in-manufacturing', label: 'In Manufacturing', color: 'secondary' },
                    deadline: '2026-10-31', upper_aligners: 8, lower_aligners: 6,
                    chief_complaint: 'Minor rotational refinement of tooth 12 and 22', malocclusion: 'Finishing refinement stage 1',
                    clinical: { siCaseCode: 'SI-9890', waveatpPtId: 'WAVE-4750', manufacturingDuration: { deliveryTime: '36h SLA', startedAt: '2026-10-24T08:00:00Z', isTimerPaused: false, lastHoldAt: null, deadline: { iso_date: '2026-10-31T17:00:00Z' }, completedAt: null } },
                    batches: [], created_at: '2026-10-10 14:00', updated_at: '2026-10-25 08:30'
                },
                {
                    id: 4, case_id: 'VELOUR-RET-0001', patient_name: 'Tariq Mansoor', patient_age: 41, patient_gender: 'Male',
                    patient_email: 'tariq.mansoor@example.com', patient_phone: '+971 50 777 8899', patient_dob: '1985-03-04',
                    doctor_name: 'Dr. Elena Rostova', doctor_id: 6, uploader_id: 6, created_by: 6, doctor_email: 'doctor_b@velourcare.com',
                    client_id: 2, client_name: 'Emirates Smile Design Dental Center', vendor_id: 4, category: 'Retainers', category_type: 'Retainers',
                    status: { value: 'plan-step-files-ready', label: 'Step Files Ready', color: 'success' },
                    deadline: '2026-10-28', upper_aligners: 3, lower_aligners: 3,
                    chief_complaint: 'Post-orthodontic clear retention sets', malocclusion: 'Post-treatment retention',
                    clinical: { siCaseCode: 'SI-9940', waveatpPtId: 'WAVE-4830', stepsDuration: { deliveryTime: 'Ready', startedAt: '2026-10-22T10:00:00Z', isTimerPaused: false, lastHoldAt: null, deadline: { iso_date: '2026-10-28T18:00:00Z' }, completedAt: { iso_date: '2026-10-25T17:00:00Z' } } },
                    batches: [], created_at: '2026-10-21 16:15', updated_at: '2026-10-25 17:00'
                },
                {
                    id: 5, case_id: 'VELOUR-0004', patient_name: 'Elena Rostova', patient_age: 29, patient_gender: 'Female',
                    patient_email: 'elena.r@example.com', patient_phone: '+971 55 112 3344', patient_dob: '1997-07-22',
                    doctor_name: 'Dr. Emily Watson', doctor_id: 8, uploader_id: 8, created_by: 8, doctor_email: 'associate@wrightortho.com',
                    client_id: 1, client_name: 'Wright Orthodontics Clinic', vendor_id: null, category: 'New Case', category_type: 'Aligners',
                    status: { value: 'newly-created', label: 'Newly Created', color: 'warning' },
                    deadline: '2026-11-10', upper_aligners: 0, lower_aligners: 0,
                    chief_complaint: 'Diastema closure between central incisors', malocclusion: 'Class I with 2.5mm upper midline diastema',
                    clinical: {}, batches: [], created_at: '2026-10-25 18:00', updated_at: '2026-10-25 18:00'
                },
                {
                    id: 6, case_id: 'VELOUR-0006', patient_name: 'Yusuf Al-Hashemi', patient_age: 31, patient_gender: 'Male',
                    patient_email: 'yusuf.h@example.com', patient_phone: '+971 56 890 1234', patient_dob: '1995-11-30',
                    doctor_name: 'Dr. Elena Rostova', doctor_id: 6, uploader_id: 6, created_by: 6, doctor_email: 'doctor_b@velourcare.com',
                    client_id: 2, client_name: 'Emirates Smile Design Dental Center', vendor_id: null, category: 'New Case', category_type: 'Aligners',
                    status: { value: 'in-planning', label: 'In Planning', color: 'info' },
                    deadline: '2026-11-15', upper_aligners: 14, lower_aligners: 14,
                    chief_complaint: 'Moderate lower anterior crowding and rotation', malocclusion: 'Class I Malocclusion',
                    clinical: { siCaseCode: 'SI-9945', waveatpPtId: 'WAVE-4845', planningDuration: { deliveryTime: '48h SLA', isTimerPaused: false, lastHoldAt: null, deadline: { iso_date: '2026-11-15T18:00:00Z' }, completedAt: null } },
                    batches: [], created_at: '2026-10-23 09:15', updated_at: '2026-10-25 14:00'
                }
            ];
            const insCase = sqlite.prepare(`
                INSERT INTO cases (id, case_id, patient_name, patient_age, patient_gender, patient_email, patient_phone, patient_dob, patient_residency_type, doctor_name, doctor_id, uploader_id, created_by, doctor_email, client_id, client_name, vendor_id, category, category_type, status_value, status_json, is_draft, version, is_archived, deadline, upper_aligners, lower_aligners, chief_complaint, malocclusion, clinical_json, shipment_batches_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'local', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `);
            for (const c of seedCases) {
                insCase.run(
                    c.id, c.case_id, c.patient_name, c.patient_age, c.patient_gender, c.patient_email, c.patient_phone, c.patient_dob,
                    c.doctor_name, c.doctor_id, c.uploader_id, c.created_by, c.doctor_email,
                    c.client_id, c.client_name, c.vendor_id, c.category, c.category_type,
                    c.status.value, JSON.stringify(c.status), c.deadline, c.upper_aligners, c.lower_aligners,
                    c.chief_complaint, c.malocclusion, JSON.stringify(c.clinical || {}), JSON.stringify(c.batches || []),
                    c.created_at, c.updated_at
                );
            }

            // 8. Treatment Plan #1 on Case 1 (starts pending-review so doctor can approve cleanly)
            const planDoc = {
                header: { aligners_upper: '22', aligners_lower: '18', days_upper: '10', days_lower: '10', worn_days: '10', workdays: '5', show_worn_note: true, show_days_upper: true, show_days_lower: true, show_elastic: false },
                ipr_contacts: [
                    { slot: 15, pair: '11-21', width_mm: 0.3, after_step: 3 },
                    { slot: 16, pair: '21-22', width_mm: 0.2, after_step: 3 },
                    { slot: 14, pair: '12-11', width_mm: 0.2, after_step: 5 },
                    { slot: 31, pair: '31-41', width_mm: 0.2, after_step: 2 },
                    { slot: 32, pair: '41-42', width_mm: 0.3, after_step: 4 }
                ],
                attachment_points: [{ slot: 13, step: 1 }, { slot: 23, step: 1 }, { slot: 33, step: 2 }, { slot: 43, step: 2 }],
                pressure_points: [], pontic_steps: [], tooth_annotations: {},
                movement_chart: {
                    title: 'MOVEMENT CHART',
                    upper: [
                        { tooth: '11', mesial_distal: 0.4, buccal_lingual: 0.8, intrusion_extrusion: -0.2, torque: 2.1, tip: 1.5, rotation: -4.2 },
                        { tooth: '21', mesial_distal: -0.3, buccal_lingual: 0.7, intrusion_extrusion: -0.2, torque: 1.9, tip: -1.2, rotation: 3.8 }
                    ],
                    lower: [
                        { tooth: '31', mesial_distal: 0.2, buccal_lingual: 0.5, intrusion_extrusion: 0.0, torque: 1.0, tip: 0.8, rotation: 2.1 },
                        { tooth: '41', mesial_distal: -0.2, buccal_lingual: 0.4, intrusion_extrusion: 0.0, torque: 1.1, tip: -0.7, rotation: -1.9 }
                    ]
                },
                pdf_pages: { include_vto_intro: false, include_movement_chart: true, include_smile_summary: true, include_smile_summary_upload: false, include_ipr_summary: true, header_logo_source: 'none' }
            };
            sqlite.prepare(`
                INSERT INTO treatment_plans (id, case_id, title, has_plan_document, upper_aligner_count, lower_aligner_count, status_value, status_json, ipr_chart_file_url, container_file_url, zip_file_url, simulation_link, description, plan_document_json, review_json, created_at)
                VALUES (?, ?, ?, 1, 22, 18, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
                1, 1, 'Plan 1 - Non-Extraction IPR Protocol', 'pending-review',
                JSON.stringify({ value: 'pending-review', label: 'Pending Review', color: 'info' }),
                '/uploads/velourcare-ipr-chart-sample.pdf',
                '/uploads/sample-treatment-container.o3c',
                '/uploads/sample-treatment-models.zip',
                '/simulation/1',
                'VelourCare Precision Aligner Protocol. 22 upper / 18 lower aligners.',
                JSON.stringify(planDoc),
                JSON.stringify(null),
                '2026-10-24 14:00'
            );

            // 9. Step Files & Seed Attachments on Case 1
            sqlite.prepare(`
                INSERT INTO step_files (id, case_id, client_id, uploader_id, v_tratransfer_link, description, disk_filename, zip_file_url, zip_file_name, status_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
                1, 1, 1, 3,
                'https://wetransfer.com/downloads/velourcare-step-files-001',
                '<p><strong>Steps 01-22 STL Models</strong>. Precision thermoforming models trimmed at gingival margin + 0.5mm scallop.</p>',
                'sample-treatment-models.zip',
                '/uploads/sample-treatment-models.zip',
                'case-0001-aligner-steps.zip',
                JSON.stringify({ value: 'approved', label: 'Approved', color: 'success' }),
                '2026-10-23 11:00', '2026-10-23 11:00'
            );

            sqlite.prepare(`
                INSERT INTO case_attachments (case_id, client_id, uploader_id, disk_filename, original_name, file_url, file_size, mime_type, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(1, 1, 2, 'sample-treatment-container.o3c', 'Treatment_Setup_Case_0001.o3c', '/uploads/sample-treatment-container.o3c', '1.1 KB', 'application/zip', '2026-10-15 09:42');

            // 10. Comments
            sqlite.prepare(`
                INSERT INTO case_comments (id, case_id, user_id, user_name, user_role, user_pic, content, attachments_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(1, 1, 1, 'VelourCare Super Administrator', 'super-admin', '/assets/velourcare-square.png', 'Treatment plan uploaded. Initial anterior alignment staging completed.', '[]', '2026-10-24 14:20');

            // 11. Invoices (Consistent 5% UAE VAT-exclusive accounting, integer fils)
            const insInv = sqlite.prepare(`
                INSERT INTO invoices (id, invoice_number, client_id, client_name, case_id, plan_id, patient_name, billing_period_start, billing_period_end, document_status, document_status_label, payment_status, payment_status_label, subtotal_fils, discount_fils, tax_fils, total_fils, amount_paid_fils, balance_due_fils, currency, is_locked, due_date, issued_at, created_at, notes, items_json)
                VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, 'issued', 'Issued', ?, ?, ?, 0, ?, ?, ?, ?, 'AED', 1, ?, ?, ?, '', ?)
            `);
            insInv.run(
                1, 'INV-VELOUR-2026-001', 1, 'Wright Orthodontics Clinic', 1, 'Fatima Al-Nuaimi',
                '2026-10-01', '2026-10-31', 'paid', 'Paid',
                485000, 24250, 509250, 509250, 0,
                '2026-11-15', '2026-10-15', '2026-10-15',
                JSON.stringify([
                    { description: 'VelourCare Comprehensive Clear Aligner Treatment (Case #VELOUR-0001)', quantity: 1, unit_price: 4200, unit_amount: 4200, total: 4200, total_amount: 4200 },
                    { description: 'Digital Treatment Setup & 3D Staging Fee', quantity: 1, unit_price: 650, unit_amount: 650, total: 650, total_amount: 650 }
                ])
            );
            insInv.run(
                2, 'INV-VELOUR-2026-002', 2, 'Emirates Smile Design Dental Center', 4, 'Tariq Mansoor',
                '2026-10-01', '2026-10-31', 'paid', 'Paid',
                125000, 6250, 131250, 131250, 0,
                '2026-10-30', '2026-10-01', '2026-10-01',
                JSON.stringify([
                    { description: 'VelourCare Dual Arch Clear Retainers (3 Sets)', quantity: 1, unit_price: 1250, unit_amount: 1250, total: 1250, total_amount: 1250 }
                ])
            );
            insInv.run(
                3, 'INV-VELOUR-2026-003', 1, 'Wright Orthodontics Clinic', 2, 'Marcus Vance',
                '2026-10-15', '2026-11-15', 'unpaid', 'Pending Payment',
                450000, 22500, 472500, 0, 472500,
                '2026-11-20', '2026-10-20', '2026-10-20',
                JSON.stringify([
                    { description: 'VelourCare Clear Aligner Package (Case #VELOUR-0002)', quantity: 1, unit_price: 4500, unit_amount: 4500, total: 4500, total_amount: 4500 }
                ])
            );

            // 12. Chat messages
            const insChat = sqlite.prepare('INSERT INTO chat_messages (sender_id, receiver_id, message, is_read, created_at) VALUES (?, ?, ?, 1, ?)');
            insChat.run(2, 1, 'Hello, has the IPR chart been finalized for Case #VELOUR-0001?', '2026-10-25 14:15');
            insChat.run(1, 2, 'Yes, Dr. Wright. The IPR chart is attached to Treatment Plan #1.', '2026-10-25 14:20');

            // 13. Sequence counters
            sqlite.prepare('INSERT INTO counters (name, value) VALUES (?, ?)').run('invoice_sequence', 200);
        });
    }

    seedIfEmpty();

    function getNextInvoiceNumber() {
        const update = sqlite.prepare('UPDATE counters SET value = value + 1 WHERE name = ? RETURNING value').get('invoice_sequence');
        const nextVal = update ? Number(update.value) : 201;
        const year = new Date().getFullYear();
        return `INV-VELOUR-${year}-${String(nextVal).padStart(4, '0')}`;
    }

    function insertAuditLog({ user, action, resourceType = null, resourceId = null, details = null, ip = '127.0.0.1' }) {
        try {
            const ts = new Date().toISOString();
            const username = user ? (user.username || user.email) : 'anonymous';
            const role = user ? (user.role_slug || 'guest') : 'guest';
            const clientId = user ? (user.client_id || (user.client && user.client.id) || null) : null;
            const res = sqlite.prepare(`
                INSERT INTO audit_logs (timestamp, user_id, username, role, client_id, action, resource_type, resource_id, details, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
                ts, user ? user.id : null, username, role, clientId, action,
                resourceType || null, resourceId !== null && resourceId !== undefined ? String(resourceId) : null,
                details || null, ip || '127.0.0.1'
            );
            return {
                id: Number(res.lastInsertRowid),
                timestamp: ts,
                user_id: user ? user.id : null,
                username,
                role,
                client_id: clientId,
                action,
                resource_type: resourceType || null,
                resource_id: resourceId || null,
                details: details || null,
                ip_address: ip || '127.0.0.1'
            };
        } catch (e) {
            console.error('Audit log insert error:', e.message);
            return null;
        }
    }

    function queryAuditLogs({ action = null, username = null, limit = 100, offset = 0 } = {}) {
        const where = [];
        const params = [];
        if (action) {
            where.push('LOWER(action) = LOWER(?)');
            params.push(action);
        }
        if (username) {
            where.push('LOWER(username) = LOWER(?)');
            params.push(username);
        }
        const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';
        const total = sqlite.prepare(`SELECT COUNT(*) AS cnt FROM audit_logs ${whereSql}`).get(...params).cnt;
        const rows = sqlite.prepare(`SELECT * FROM audit_logs ${whereSql} ORDER BY id DESC LIMIT ? OFFSET ?`).all(...params, limit, offset).map(plain);
        return { total, rows };
    }

    function findFileOwnership(diskFilename) {
        const att = sqlite.prepare('SELECT case_id, client_id, uploader_id FROM case_attachments WHERE disk_filename = ?').get(diskFilename);
        if (att) return { ...att, source: 'attachment' };
        const step = sqlite.prepare('SELECT case_id, client_id, uploader_id FROM step_files WHERE disk_filename = ?').get(diskFilename);
        if (step) return { ...step, source: 'step_file' };
        const likePattern = `%/${diskFilename}`;
        const plan = sqlite.prepare(`
            SELECT tp.case_id, c.client_id, c.uploader_id
            FROM treatment_plans tp JOIN cases c ON c.id = tp.case_id
            WHERE tp.ipr_chart_file_url LIKE ? OR tp.container_file_url LIKE ? OR tp.zip_file_url LIKE ?
        `).get(likePattern, likePattern, likePattern);
        if (plan) return { ...plan, source: 'treatment_plan' };
        return null;
    }

    function caseHasFile(caseId, diskFilename) {
        const att = sqlite.prepare('SELECT 1 FROM case_attachments WHERE case_id = ? AND disk_filename = ?').get(caseId, diskFilename);
        if (att) return true;
        const step = sqlite.prepare('SELECT 1 FROM step_files WHERE case_id = ? AND disk_filename = ?').get(caseId, diskFilename);
        if (step) return true;
        const likePattern = `%/${diskFilename}`;
        const plan = sqlite.prepare(`
            SELECT 1 FROM treatment_plans
            WHERE case_id = ? AND (ipr_chart_file_url LIKE ? OR container_file_url LIKE ? OR zip_file_url LIKE ?)
        `).get(caseId, likePattern, likePattern, likePattern);
        return Boolean(plan);
    }

    function pruneExpired(nowMs = Date.now()) {
        sqlite.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(nowMs);
        sqlite.prepare('DELETE FROM idempotency_keys WHERE expires_at <= ?').run(nowMs);
    }

    function exportSnapshot({ includeAuthSecrets = false } = {}) {
        const clients = sqlite.prepare('SELECT * FROM clients ORDER BY id ASC').all().map(mapClientRow);
        const users = sqlite.prepare('SELECT * FROM users ORDER BY id ASC').all().map(r => {
            const mapped = mapUserRow(r);
            return includeAuthSecrets ? mapped : serializeUser(mapped);
        });
        const cases = sqlite.prepare('SELECT * FROM cases ORDER BY id ASC').all().map(mapCaseRow);
        const invoices = sqlite.prepare('SELECT * FROM invoices ORDER BY id ASC').all().map(r => mapInvoiceRow(r));
        const auditLogs = sqlite.prepare('SELECT * FROM audit_logs ORDER BY id ASC').all().map(plain);
        return { clients, users, cases, invoices, auditLogs };
    }

    // shortcut: verifies JSON snapshot record counts and backfills empty audit_logs rather than wiping/replacing all relational tables; upgrade to SQLite `VACUUM INTO` binary backups for full point-in-time disaster recovery.
    function restoreSnapshot(snapshot = {}) {
        return runTransaction(() => {
            if (Array.isArray(snapshot.auditLogs)) {
                const existing = sqlite.prepare('SELECT COUNT(*) AS cnt FROM audit_logs').get().cnt;
                if (existing === 0) {
                    const ins = sqlite.prepare('INSERT INTO audit_logs (timestamp, user_id, username, role, client_id, action, resource_type, resource_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
                    for (const l of snapshot.auditLogs) {
                        ins.run(l.timestamp, l.user_id ?? null, l.username || 'system', l.role || 'guest', l.client_id ?? null, l.action || 'RESTORED', l.resource_type ?? null, l.resource_id ? String(l.resource_id) : null, l.details ?? null, l.ip_address || '127.0.0.1');
                    }
                }
            }
            const casesRestored = Array.isArray(snapshot.cases) ? snapshot.cases.length : sqlite.prepare('SELECT COUNT(*) AS cnt FROM cases').get().cnt;
            const invoicesRestored = Array.isArray(snapshot.invoices) ? snapshot.invoices.length : sqlite.prepare('SELECT COUNT(*) AS cnt FROM invoices').get().cnt;
            return { casesRestored, invoicesRestored };
        });
    }

    function getPortalSettingsObj() {
        const out = {};
        const rows = sqlite.prepare('SELECT key, value_json FROM portal_settings').all();
        for (const r of rows) {
            out[r.key] = parseJson(r.value_json, {});
        }
        out.clients = sqlite.prepare('SELECT * FROM clients ORDER BY id ASC').all().map(mapClientRow);
        return out;
    }

    return {
        sqlite,
        dbPath,
        runTransaction,
        mapClientRow,
        mapUserRow,
        mapCaseRow,
        mapPlanRow,
        mapAttachmentRow,
        mapStepFileRow,
        mapInvoiceRow,
        serializeUser,
        getNextInvoiceNumber,
        insertAuditLog,
        queryAuditLogs,
        findFileOwnership,
        caseHasFile,
        pruneExpired,
        exportSnapshot,
        restoreSnapshot,
        getPortalSettingsObj,
        parseJson,
        plain
    };
}

module.exports = {
    ALL_PERMISSION_NAMES,
    PERMISSION_MATRIX,
    hashPasswordSync,
    hashPasswordAsync,
    verifyPasswordAsync,
    serializeUser,
    createDatabase
};
