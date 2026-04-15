# SOC 2 evidence report (automated)

**Generated:** 2026-04-15 14:11 UTC
**Environment label:** yuno-production-snapshot
**Evidence source:** local_fixture: compliant.json

## Executive summary

We looked at **3** Security-type controls using the JSON snapshot on disk.
- **Pass:** 3
- **Fail:** 0
- **Partial:** 0
- **Review (yellow flag):** 0
- **Needs human judgement:** 0

**How to read this:** *Fail* is for items we treat as objectively out of policy. *Needs human* means the file was too thin to grade fairly. *Review* is the middle ground—nothing exploded in automation, but a real person should still read the notes.

Evidence blocks below are **redacted** (ARNs shortened, emails removed) so the report is safer to email.

## Glossary (for people who do not live in AWS)

| Term | Plain language |
|------|----------------|
| **IAM** | The gatekeeper for cloud APIs: who is allowed to do what, and on which resources. |
| **Least-privilege** | Only handing out the permissions someone truly needs—not handing them the master keys "just in case". |
| **S3 bucket** | A shared drive in the sky. Customer uploads, backups, and logs often land here. |
| **RDS** | A managed database where rows of business data live. |
| **CloudTrail** | A flight recorder for API calls—who changed what, and when. |
| **Encryption at rest** | Data is stored encrypted on disk so a lost volume or copied snapshot is not automatically readable. |

## Per-control results

### CC6.1 — Logical access to in-scope assets

**Category:** Security (Common Criteria)  
**Result:** PASS (`compliant`)

**Why this matters:**
IAM is the front door to the cloud API. Auditors want to see that everyday access is narrow, privileged access is rare, and MFA exists for humans (or an IdP you can prove covers the same risk).

**What the script actually checked:**
We look for obvious administrative wildcards, service-wide `s3:*` style shortcuts, and the few MFA facts the JSON snapshot actually contains. Anything missing is called out instead of silently passing.

**Evidence excerpt (redacted JSON):**
```json
{
  "policy_count": 2,
  "policy_names": [
    "AppRuntimeS3Read",
    "RDSConnectLimited"
  ],
  "root_mfa_enabled": true,
  "human_users_included": true,
  "human_user_count": 2
}
```

**Mapped frameworks (only when you asked for them on the CLI):**
- **SOC2:** CC6.1

**Must fix:** none flagged automatically.

**Review queue:** empty.

---

### CC6.7 — Encryption of data at rest

**Category:** Security (Common Criteria)  
**Result:** PASS (`compliant`)

**Why this matters:**
Disks walk away, buckets get mis-shared, and backups linger for years. Encryption at rest is the cheap insurance policy everyone expects to see switched on.

**What the script actually checked:**
S3 and RDS are stand-ins for 'data at rest'. We fail closed on missing encryption, nudge you on SSE-S3 vs KMS, and we refuse to invent a value when public access flags are absent.

**Evidence excerpt (redacted JSON):**
```json
{
  "s3_bucket_count": 2,
  "s3_buckets": [
    {
      "name": "yuno-prod-customer-data",
      "encryption": {
        "enabled": true,
        "algorithm": "aws:kms",
        "kms_key_id": "arn:aws:\u2026(redacted)"
      }
    },
    {
      "name": "yuno-prod-cloudtrail-logs",
      "encryption": {
        "enabled": true,
        "algorithm": "aws:kms",
        "kms_key_id": "arn:aws:\u2026(redacted)"
      }
    }
  ],
  "s3_buckets_truncated": false,
  "rds_count": 1,
  "rds": [
    {
      "identifier": "orders-primary",
      "storage_encrypted": true
    }
  ]
}
```

**Mapped frameworks (only when you asked for them on the CLI):**
- **SOC2:** CC6.7

**Must fix:** none flagged automatically.

**Review queue:** empty.

---

### CC7.2 — Security monitoring and detection

**Category:** Security (Common Criteria)  
**Result:** PASS (`compliant`)

**Why this matters:**
If nobody logged the API call, the investigation stops cold. CloudTrail (or an equivalent) is how you prove someone did—or did not—touch production settings.

**What the script actually checked:**
CloudTrail is our proxy for 'do we have an audit log of API activity'. If the JSON is thin, we say so instead of pretending everything is fine.

**Evidence excerpt (redacted JSON):**
```json
{
  "regions_required": [
    "us-east-1",
    "eu-west-1"
  ],
  "regions": {
    "us-east-1": {
      "enabled": true,
      "is_logging": true
    },
    "eu-west-1": {
      "enabled": true,
      "is_logging": true
    }
  },
  "multi_region_trail": true,
  "log_archive_bucket_configured": true
}
```

**Mapped frameworks (only when you asked for them on the CLI):**
- **SOC2:** CC7.2

**Must fix:** none flagged automatically.

**Review queue:** empty.

---

## Honest limitations

This is still a **point-in-time** JSON snapshot. SOC 2 Type II wants proof over months, which means ticketing, change history, sampled log queries, and interviews—not just one file.