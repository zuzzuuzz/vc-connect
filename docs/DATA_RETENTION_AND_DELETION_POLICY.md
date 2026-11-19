# VelourCare Ortho Cloud — Data Retention, Archival & Deletion Policy
**Document Ref:** VC-LEG-004  
**Category:** Regulatory Compliance & Records Governance

---

## 1. Overview
As a cloud platform supporting orthodontic clinics, CAD digital planning studios, and clear aligner manufacturing labs, VelourCare must balance statutory medical record retention mandates with patient privacy rights (including GDPR Article 17 "Right to Erasure").

## 2. Retention Schedules
| Data Category | Retention Period | Rationale & Regulatory Basis | Default Action at Expiry |
|---|---|---|---|
| **Active Patient Case Data (STL, Photos, Treatment Plans)** | Active Treatment Duration + **7 Years** post-completion | Statutory medical/dental record retention requirements under UAE DHA/DoH regulations and international dental boards. | Soft-archive; moved to deep cold storage with cryptographic lock. |
| **Orthodontic Invoices & Financial Records** | **10 Years** from date of issuance | Commercial and tax compliance mandates (UAE Federal Tax Authority & VAT audit requirements). | Permanent encrypted archive. |
| **Audit Logs & Access History** | **3 Years** rolling window | Security forensics and HIPAA Security Rule (§ 164.312(b)) audit trail obligations. | Automated backup snapshot and secure roll-off. |
| **Temporary Uploads & Failed Drafts** | **30 Days** | Scratch storage cleanup; prevention of data hoarding. | Automated permanent deletion. |
| **Session Tokens & Expired Password Reset Tokens** | Immediate expiration on use or **15-30 minutes** TTL | Session hygiene and credential protection. | Immediate garbage collection from memory/cache. |

## 3. Case Deletion & Archiving Protocol (Soft Delete)
- Direct deletion (`DELETE /api/cases/:id`) is restricted exclusively to **Super Administrators**.
- To prevent accidental loss of medical history or orphaned invoice records, deletion is implemented as **Soft Delete / Archival**:
  - `is_archived: true`, `archived_at: ISO_TIMESTAMP`, `archived_by: USER_ID`.
  - Archived cases are suppressed from standard search results, dropdowns, and daily dashboards.
  - Linked financial records, invoices, and audit history are permanently preserved.
- **Hard Deletion (Cryptographic Shredding):** Executed only upon formal legal request or patient data erasure court order verified by the Data Protection Officer, overwriting physical disk storage blocks.
