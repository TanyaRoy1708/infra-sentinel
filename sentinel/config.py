import os

SCAN_REGIONS: list[str] = [
    r.strip()
    for r in os.environ.get("SCAN_REGIONS", "us-east-1").split(",")
    if r.strip()
]

REPORT_BUCKET_NAME: str = os.environ.get("REPORT_BUCKET_NAME", "")

# Comma-separated s3:// paths to TF state files; merged before drift reconciliation
TF_STATE_PATHS: list[str] = [
    path.strip()
    for path in os.environ.get("TF_STATE_PATHS", "").split(",")
    if path.strip()
]

IDLE_CPU_THRESHOLD_PCT: float = float(os.environ.get("IDLE_CPU_THRESHOLD_PCT", "5.0"))
IDLE_AGE_THRESHOLD_DAYS: int = int(os.environ.get("IDLE_AGE_THRESHOLD_DAYS", "3"))
