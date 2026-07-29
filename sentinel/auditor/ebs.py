import boto3
from .base import BaseAuditor, check_ttl_expired, get_tag


class EBSAuditor(BaseAuditor):
    """
    Scans for EBS volumes that are detached (not attached to any instance).
    Also flags volumes whose TTL tag has expired.
    Detached volumes still cost money every month based on their size.
    """

    def _scan(self, region: str) -> list:
        ec2 = boto3.client("ec2", region_name=region)
        findings = []

        # 'available' status means the volume is not attached to any instance
        paginator = ec2.get_paginator("describe_volumes")
        page_iterator = paginator.paginate(
            Filters=[{"Name": "status", "Values": ["available"]}]
        )

        for page in page_iterator:
            for volume in page.get("Volumes", []):
                vol_id = volume.get("VolumeId")
                size_gb = volume.get("Size")
                vol_type = volume.get("VolumeType")

                # Skip if intentionally excluded
                if get_tag(volume, "sentinel:exclude"):
                    continue

                # TTL check — volume promised to be gone by now
                if check_ttl_expired(volume, created_at=volume.get("CreateTime")):
                    findings.append({
                        "resource_id": vol_id,
                        "finding_type": "TTL_EXPIRED",
                        "severity": "Warning",
                        "confidence": 100,
                        "reasons": [
                            f"Volume {vol_id} is still present past its TTL tag expiry.",
                            f"Size: {size_gb} GB, Type: {vol_type}",
                        ],
                    })
                    continue  # TTL expiry is the finding — skip the generic one

                findings.append({
                    "resource_id": vol_id,
                    "finding_type": "UNATTACHED_EBS_VOLUME",
                    "severity": "Medium",
                    "reasons": [
                        "Volume is not attached to any instance.",
                        f"Size: {size_gb} GB, Type: {vol_type}",
                    ],
                })

        return findings
