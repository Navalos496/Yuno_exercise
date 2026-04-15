# SOC 2 evidence report (automated)

**Generated:** 2026-04-15 14:11 UTC
**Environment label:** yuno-legacy-audit-drill
**Evidence source:** local_fixture: violations.json

## Executive summary

We looked at **3** Security-type controls using the JSON snapshot on disk.
- **Pass:** 0
- **Fail:** 3
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
**Result:** FAIL (`non_compliant`)

**Why this matters:**
IAM is the front door to the cloud API. Auditors want to see that everyday access is narrow, privileged access is rare, and MFA exists for humans (or an IdP you can prove covers the same risk).

**What the script actually checked:**
We look for obvious administrative wildcards, service-wide `s3:*` style shortcuts, and the few MFA facts the JSON snapshot actually contains. Anything missing is called out instead of silently passing.

**Evidence excerpt (redacted JSON):**
```json
{
  "policy_count": 2,
  "policy_names": [
    "AdminAccess",
    "S3DangerousWildcard"
  ],
  "root_mfa_enabled": false,
  "human_users_included": true,
  "human_user_count": 1
}
```

**Mapped frameworks (only when you asked for them on the CLI):**
- **SOC2:** CC6.1

**Must fix (automation treated these as hard failures):**
- Policy 'AdminAccess': Allow grants Action * on Resource * (classic full-admin pattern).
- Root user MFA is off. Auditors treat that as an easy win to fix.
- User 'contractor-temp' is modeled as a person without MFA. Service accounts should live under `roles`, not this list.

**Review queue (missing data, judgement calls, softer risks):**
- Policy 'S3DangerousWildcard': Service-level wildcard action 's3:*' (many auditors ask for a narrower action list).

**What we would do next:**
- Remove *:* style policies except true emergency roles, and guard them with approval + logging.
- Turn MFA on for root and every human principal; enforce with `aws iam update-account-password-policy`.
- Attach a short note for the QSA: who collects IAM/SSO evidence, how often, and where break-glass lives.

---

### CC6.7 — Encryption of data at rest

**Category:** Security (Common Criteria)  
**Result:** FAIL (`non_compliant`)

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
        "enabled": false
      }
    },
    {
      "name": "yuno-dev-logs",
      "encryption": {
        "enabled": false
      }
    }
  ],
  "s3_buckets_truncated": false,
  "rds_count": 1,
  "rds": [
    {
      "identifier": "legacy-mysql",
      "storage_encrypted": false
    }
  ]
}
```

**Mapped frameworks (only when you asked for them on the CLI):**
- **SOC2:** CC6.7

**Must fix (automation treated these as hard failures):**
- Bucket `yuno-prod-customer-data` is not using default bucket encryption.
- Bucket `yuno-prod-customer-data` does not have Block Public Access fully on. Even with encryption, public reads/writes are a separate nightmare.
- Bucket `yuno-dev-logs` is not using default bucket encryption.
- Bucket `yuno-dev-logs` does not have Block Public Access fully on. Even with encryption, public reads/writes are a separate nightmare.
- RDS `legacy-mysql` is running without storage encryption.

**Review queue:** empty.

**What we would do next:**
- Turn on default encryption for every bucket; fix any bucket that still shows `encryption: false`.
- Encrypt RDS storage and document which KMS key backs customer data.

---

### CC7.2 — Security monitoring and detection

**Category:** Security (Common Criteria)  
**Result:** FAIL (`non_compliant`)

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
      "is_logging": false
    },
    "eu-west-1": {
      "enabled": false,
      "is_logging": false
    }
  },
  "multi_region_trail": false,
  "log_archive_bucket_configured": false
}
```

**Mapped frameworks (only when you asked for them on the CLI):**
- **SOC2:** CC7.2

**Must fix (automation treated these as hard failures):**
- Region `us-east-1` has a trail object, yet `is_logging` is false. That is the same as having a smoke detector with the battery pulled out.
- Region `eu-west-1` does not show an enabled trail.

**Review queue (missing data, judgement calls, softer risks):**
- `log_archive_bucket_configured` is false. Logs might still exist, but you will be asked where they land and who can delete them.

**What we would do next:**
- Enable logging in every in-scope region, or ship an org trail with proof it covers the regions you promise customers.
- Add one paragraph to the audit packet: trail home region, log bucket ARN pattern, retention days, and who can edit bucket policies.

---

## Honest limitations

This is still a **point-in-time** JSON snapshot. SOC 2 Type II wants proof over months, which means ticketing, change history, sampled log queries, and interviews—not just one file.