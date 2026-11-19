# VelourCare Ortho Cloud — Third-Party Data Processors Registry
**Document Ref:** VC-LEG-003  
**Review Cadence:** Semi-Annual | **Status:** Active & Approved

This register documents every external service, cloud infrastructure provider, and third-party API provider that handles, stores, or processes patient health data (PHI), clinical files, or billing records on behalf of VelourCare Ortho Cloud.

| Service Name | Provider & Jurisdiction | Data Processed | Purpose / Scope | Encryption & Security Controls | BAA / DPA Status |
|---|---|---|---|---|---|
| **AWS S3 / Wasabi Storage** | Amazon Web Services (UAE Region / eu-central) | Digital intraoral scans (STL, PLY, OBJ, O3C), Ceph X-rays, Treatment container archives | Encrypted cloud object storage for heavy orthodontic scan files | AES-256 Server-Side Encryption (SSE-KMS), TLS 1.3, Signed URLs (15-min TTL) | **Signed BAA & DPA on file** |
| **Stripe Connect & Platform** | Stripe Inc. (US / EU) | Doctor billing contact, payment method tokens, invoice payment amounts | Clear aligner manufacturing invoice settlement and clinic payments | PCI-DSS Level 1 Certified, end-to-end tokenization; zero raw card data stored on VelourCare servers | **Signed DPA & Standard Contractual Clauses** |
| **Transactional Email (SMTP/SES)** | Amazon SES / Mandrill (EU/UAE) | Clinician email addresses, system notifications, password reset links | Case status alerts, treatment approval notices, password reset links | TLS in transit, SPF/DKIM/DMARC authenticated; PHI redacted in email bodies (opaque Case IDs only) | **Signed DPA on file** |
| **Real-time WebSockets (Pusher / Local Gateway)** | Self-hosted Gateway / Pusher | Case stage change events, status update notifications | Real-time frontend portal updates for planners and clinics | WSS (WebSocket Secure) over TLS 1.3; ephemeral message payloads containing IDs only, no raw patient names | **Compliant** |
| **Self-Hosted Application Hosting** | Dedicated Sovereign Cloud (UAE Data Center) | Relational database, user accounts, audit logs, active session store | Core application backend and API server | Private VPC, no public DB access, daily encrypted automated snapshots, firewall ingress rules | **Direct Provider Agreement & BAA** |

### Data Transfer Principle:
No third-party service receives patient health information beyond what is strictly necessary to perform its bounded technical function ("Data Minimization" principle under GDPR Art. 5(1)(c) and HIPAA 45 CFR § 164.502(b)).
