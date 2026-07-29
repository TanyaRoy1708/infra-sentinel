import boto3
from .base import BaseAuditor, check_ttl_expired, get_tag


class RDSAuditor(BaseAuditor):
    """
    Scans for RDS instances that are stopped.
    Also flags instances whose TTL tag has expired.

    Why this matters:
    - A stopped RDS instance still charges you for storage.
    - AWS automatically RESTARTS a stopped RDS instance after 7 days.
      This means a forgotten stopped instance will silently resume billing
      for compute at full price after that window.
    """

    def _scan(self, region: str) -> list:
        rds = boto3.client("rds", region_name=region)
        findings = []

        paginator = rds.get_paginator("describe_db_instances")
        page_iterator = paginator.paginate()

        for page in page_iterator:
            for db in page.get("DBInstances", []):

                db_id = db.get("DBInstanceIdentifier")
                db_class = db.get("DBInstanceClass")
                engine = db.get("Engine")
                allocated_storage = db.get("AllocatedStorage")
                created_at = db.get("InstanceCreateTime")

                # Skip if intentionally excluded
                if get_tag(db, "sentinel:exclude"):
                    continue

                # TTL check — instance promised to be gone by now
                # This applies regardless of whether the instance is stopped or running
                if check_ttl_expired(db, created_at=created_at):
                    findings.append({
                        "resource_id": db_id,
                        "finding_type": "TTL_EXPIRED",
                        "severity": "Warning",
                        "confidence": 100,
                        "reasons": [
                            f"RDS instance '{db_id}' is still present past its TTL tag expiry.",
                            f"Engine: {engine}, Class: {db_class}",
                        ],
                    })
                    continue

                # Only flag stopped instances for the auto-restart risk
                if db.get("DBInstanceStatus") != "stopped":
                    continue

                findings.append({
                    "resource_id": db_id,
                    "finding_type": "RDS_AUTO_RESTART",
                    "severity": "Warning",
                    "confidence": 100,
                    "reasons": [
                        f"RDS instance '{db_id}' is stopped ({engine}, {db_class}).",
                        f"Storage is still being billed: {allocated_storage} GB.",
                        "AWS will automatically restart this instance after 7 days of being stopped.",
                    ],
                })

        return findings
