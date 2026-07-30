import boto3
from .base import BaseAuditor, check_ttl_expired, get_tag
from ..findings.model import Finding


class EBSAuditor(BaseAuditor):

    def _scan(self, region: str) -> list:
        ec2 = boto3.client("ec2", region_name=region)
        findings = []

        paginator = ec2.get_paginator("describe_volumes")
        page_iterator = paginator.paginate(
            Filters=[{"Name": "status", "Values": ["available"]}]
        )

        for page in page_iterator:
            for volume in page.get("Volumes", []):
                vol_id = volume.get("VolumeId")
                size_gb = volume.get("Size")
                vol_type = volume.get("VolumeType")

                if get_tag(volume, "sentinel:exclude"):
                    continue

                if check_ttl_expired(volume, created_at=volume.get("CreateTime")):
                    findings.append(Finding(
                        resource_id=vol_id,
                        finding_type="TTL_EXPIRED",
                        severity="Warning",
                        confidence=100,
                        region=region,
                        reasons=[
                            f"Volume {vol_id} is still present past its TTL tag expiry.",
                            f"Size: {size_gb} GB, Type: {vol_type}",
                        ],
                    ))
                    continue

                findings.append(Finding(
                    resource_id=vol_id,
                    finding_type="UNATTACHED_EBS_VOLUME",
                    severity="Medium",
                    region=region,
                    reasons=[
                        "Volume is not attached to any instance.",
                        f"Size: {size_gb} GB, Type: {vol_type}",
                    ],
                ))

        return findings
