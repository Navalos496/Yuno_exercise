"""Single place to remember how checks are wired (helps when the repo grows)."""

# The runner simply imports `checks.bulk.evaluate_all`. When you add CC6.6 or an Azure twin,
# create `checks/<topic>.py`, append the callable to `checks/bulk.py`, and note it here.
PIPELINE = (
    "CC6.1 — IAM / MFA snapshot → checks.iam",
    "CC6.7 — S3 + RDS encryption snapshot → checks.encryption",
    "CC7.2 — CloudTrail snapshot → checks.monitoring",
)
