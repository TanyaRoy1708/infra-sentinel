import boto3
from .base import BaseAuditor, check_ttl_expired, get_tag


class NetworkingAuditor(BaseAuditor):
    """
    Scans for two types of networking waste:
    1. Unassociated EIPs — allocated but not attached to anything (~$3.60/month each).
    2. Active NAT Gateways — charged 24/7 (~$32/month each) regardless of traffic.
    Also flags either resource type if its TTL tag has expired.
    """

    def _scan(self, region: str) -> list:
        ec2 = boto3.client("ec2", region_name=region)
        findings = []

        # --- 1. Find unassociated EIPs ---
        response = ec2.describe_addresses()
        for eip in response.get("Addresses", []):

            # Skip if attached to something
            if eip.get("AssociationId"):
                continue

            # Skip if intentionally excluded
            if get_tag(eip, "sentinel:exclude"):
                continue

            public_ip = eip.get("PublicIp")
            allocation_id = eip.get("AllocationId", public_ip)

            # EIPs have no creation timestamp — TTL must be an absolute date (e.g. "2026-08-01")
            if check_ttl_expired(eip):
                findings.append({
                    "resource_id": allocation_id,
                    "finding_type": "TTL_EXPIRED",
                    "severity": "Warning",
                    "confidence": 100,
                    "reasons": [
                        f"EIP {public_ip} is still allocated past its TTL tag expiry.",
                    ],
                })
                continue

            findings.append({
                "resource_id": allocation_id,
                "finding_type": "UNASSOCIATED_EIP",
                "severity": "Medium",
                "reasons": [
                    f"EIP {public_ip} is allocated but not attached to any resource.",
                ],
            })

        # --- 2. Find active NAT Gateways ---
        paginator = ec2.get_paginator("describe_nat_gateways")
        page_iterator = paginator.paginate(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )

        for page in page_iterator:
            for nat in page.get("NatGateways", []):

                # Skip if intentionally excluded
                if get_tag(nat, "sentinel:exclude"):
                    continue

                nat_id = nat.get("NatGatewayId")
                vpc_id = nat.get("VpcId")
                subnet_id = nat.get("SubnetId")

                # NAT Gateways do have a CreateTime
                if check_ttl_expired(nat, created_at=nat.get("CreateTime")):
                    findings.append({
                        "resource_id": nat_id,
                        "finding_type": "TTL_EXPIRED",
                        "severity": "Warning",
                        "confidence": 100,
                        "reasons": [
                            f"NAT Gateway {nat_id} is still running past its TTL tag expiry.",
                            f"VPC: {vpc_id}, Subnet: {subnet_id}",
                        ],
                    })
                    continue

                reasons = [
                    f"NAT Gateway is running in VPC {vpc_id}, subnet {subnet_id}.",
                    "NAT Gateways are billed ~$32/month plus data transfer costs.",
                ]

                env = get_tag(nat, "Environment")
                if env in ("dev", "personal", "test"):
                    reasons.append(f"Environment tag is '{env}' — a NAT Gateway may not be needed here.")

                findings.append({
                    "resource_id": nat_id,
                    "finding_type": "ACTIVE_NAT_GATEWAY",
                    "severity": "Low",
                    "reasons": reasons,
                })

        return findings