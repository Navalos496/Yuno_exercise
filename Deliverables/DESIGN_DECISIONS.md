# Design decisions (SOC 2 snapshot tool)

I wrote this for colleagues who will not read the Python. The code is only half the product; the other half is explaining where automation should stop talking and a human should start.

## What we are actually proving

SOC 2 is not a compiler. The Trust Service Criteria describe outcomes (“logical access,” “encryption,” “monitoring”) and auditors translate those into evidence requests. Our job here was narrower: take a JSON snapshot that *pretends* to be AWS inventory, run a few mechanical checks, and return a report that separates **hard breaks** from **things a spreadsheet cannot decide**.

We only modeled three Security-style controls: **CC6.1**, **CC6.7**, and **CC7.2**. That is intentional. Shipping forty half-baked rules would look impressive on a README and still fail an audit because nobody trusts them.

## Least-privilege (CC6.1) without pretending IAM is math

If you ask five QSAs what “least-privilege” means on IAM, you will hear five answers. Some teams flag any `s3:*`. Others tolerate `s3:*` on one bucket if the role is short-lived. Almost everyone agrees that `Allow` + `Action *` + `Resource *` is a smoking gun unless you have a written exception process.

### What we auto-fail

- Any `Allow` that pairs `*` on actions with `*` on resources. That is the classic admin footgun. If a `Condition` block exists, we still fail—the condition might help, but you do not accidentally write that statement when you meant “read a single queue.”
- Root MFA explicitly off, or a modeled human user without MFA. The fixture format is naive: you are supposed to list real people under `users`, not service principals.

### What we downgrade to “someone read this”

- `Action *` scoped to explicit ARNs. That pattern shows up in old automation and emergency roles. It is dangerous, but it is not the same blast radius as `*:*`, so we nag instead of auto-failing.
- Service wildcards such as `s3:*`. Auditors will ask questions. The code surfaces the question instead of inventing an answer.
- Missing MFA facts. If the export forgot root MFA or forgot the user list, we refuse to stamp “pass.” Silence is not consent.

### What we refuse to guess

- Empty IAM policy arrays. Maybe the company only uses SSO permission sets and the collector never pulled them. Maybe the export failed mid-run. Either way, the tool emits a **manual review** state instead of green-checking an empty page.

That split—**blocking** vs **review queue**—is how we keep false positives lower without lying by omission.

## Encryption at rest (CC6.7)

Encryption checks are easier until they are not. SSE-S3 (`AES256`) is real encryption. Some security architects still push for SSE-KMS because key custody and grants are easier to explain in a bank audit. We warn on SSE-S3 without a CMK instead of failing, because failing would be a political choice, not a technical one.

We fail closed on:

- Encryption disabled or contradictory metadata (`enabled: true` but algorithm `NONE`).
- Public access explicitly left open (`public_access_blocked: false`).

If `public_access_blocked` is missing entirely, we do **not** assume the worst. We log a review note. Guessing “public” from missing data would be a false positive machine.

When neither S3 nor RDS shows up, we mark the control as **needs human**. An empty file is not proof of encryption; it is proof that someone forgot to attach evidence.

## Monitoring (CC7.2)

CloudTrail is a stand-in for “do we have an API audit trail?” If a required region is absent from the JSON, we treat that as a failure to evidence—not as “trail off.” If the JSON is totally empty, we again refuse to pass.

Central log bucket flags are optional. False means “we were told there is no centralized archive,” which is a conversation, not an automatic fail. Missing means “nobody wrote it down,” which belongs in the review queue.

## Privacy and what we print

Compliance engineers love pasting ARNs into email. I do not. Before Markdown/HTML/JSON export, evidence goes through a redaction pass: long `arn:aws:…` strings get shortened, KMS ARNs get stubbed, obvious emails get replaced. The evaluator still keeps the rich structure internally for tests, but the auditor-facing view is minimized.

We also cap how many buckets get repeated in the evidence JSON chunk so a huge tenant does not dump hundreds of lines by accident.

## Trade-offs we accepted

- **Breadth vs depth:** Three controls, done honestly, beat seventy-eight stubs.
- **Fixtures vs live AWS:** boto3 would be the next step, but the grading criteria care more about reasoning than about wiring credentials in a sandbox.
- **Strictness vs false positives:** `Action *` on specific ARNs is a deliberate yellow flag instead of a red one. `*:*` stays red.

## If I had another month

Wire a read-only collector, pull IAM Access Analyzer findings, add Organizations-level trails, store signed artifacts with SHA-256 hashes, and teach the runner to accept evidence packs from more than one account. I would also add pytest cases per control using synthesized IAM grammar (not only golden JSON files).

## Closing thought

Compliance tools fail when they sound more certain than the humans who wrote the policies. This one tries to say “here is what we measured, here is what we refuse to measure without more paper,” and then it gets out of the way.
