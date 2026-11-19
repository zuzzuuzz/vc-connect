# VelourCare Ortho Cloud — Health Privacy & Cross-Border Regulatory Guide
**Document Ref:** VC-LEG-001  
**Target Standards:** UAE Federal Health Data Law No. 2 of 2019, HIPAA (45 CFR § 164), GDPR / UK GDPR (Art. 9 Special Category Data), Pakistan PDPL

---

## 1. Executive Summary & Applicable Frameworks
VelourCare Ortho Cloud processes orthodontic patient digital impressions (STL/PLY/OBJ/O3C), treatment plans, interproximal reduction (IPR) specifications, cephalometric radiographs, intraoral photography, and clinical invoicing. Because digital files and prescriptions contain Protected Health Information (PHI) and Personally Identifiable Information (PII), strict cross-border regulatory compliance must be maintained.

### Regulatory Map:
1. **UAE Health Data Law (Federal Law No. 2 of 2019):**
   - Applies to all healthcare and orthodontic entities operating within the United Arab Emirates (Dubai Healthcare City, Abu Dhabi DoH, DHA).
   - Requires health data to originate, be stored, and be processed within sovereign UAE data centers unless explicit Ministry permission is granted.
   - Enforces data minimization, patient consent, and auditability.
2. **United States HIPAA (Health Insurance Portability and Accountability Act):**
   - Applies whenever orthodontic cases or scans originate from US-based dental clinics or doctors.
   - Requires execution of Business Associate Agreements (BAAs) prior to ingestion.
   - Strict adherence to the HIPAA Security Rule (Administrative, Physical, and Technical Safeguards) and Privacy Rule.
3. **EU / UK GDPR (General Data Protection Regulation):**
   - Health and dental biometric records are classified under **Article 9** as "Special Category Data".
   - Explicit informed consent and Standard Contractual Clauses (SCCs) are mandated for international data transfers.
   - Patient rights guaranteed: Right of Access, Right to Rectification, Right to Erasure ("Right to be Forgotten" subject to statutory clinical record retention).
4. **Pakistan Data Protection Considerations:**
   - In accordance with Section 8 of the Security QA Checklist, Pakistani legal counsel must formally verify cross-border data handling when remote CAD designers or technical planners access case files from Pakistan.
   - All remote planning sessions must operate via secured zero-footprint web interfaces with downloads prohibited to personal devices.

---

## 2. Technical Safeguards Implemented
- **Encryption in Transit:** Mandatory TLS 1.3 / HTTPS across all public and internal communications with HSTS (`max-age=31536000; includeSubDomains`).
- **Encryption at Rest:** AES-256 GCM encryption for all digital assets, 3D step files, and relational databases.
- **Access Control & Least Privilege:** Role-Based Access Control (RBAC) separating Super Admin, CAD Planners, Lab Production Technicians, Billing/Accounts, and Clinic Doctors.
- **IDOR Prevention:** Server-side verification ensures Clinic Doctors cannot access cases or invoices of another clinic under any circumstance.
- **Immutable Audit Logging:** Every read, creation, modification, deletion, plan approval, and export is recorded with user identity, client ID, timestamp, and IP address.
- **Session Security:** Cryptographically random session tokens, 30-minute idle session timeouts, and HttpOnly/SameSite cookie attributes.

---

## 3. Administrative Safeguards & Clinic Agreements
- Every onboarded clinic must execute the **VelourCare Master Service Agreement (MSA)** and **Business Associate Agreement (BAA) / Data Processing Addendum (DPA)** before case submission.
- Clinics are responsible for securing patient informed consent for clear aligner orthodontic treatment and digital file processing.
- Staff offboarding protocols mandate same-day identity deactivation and instantaneous session invalidation.
