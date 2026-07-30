import boto3
from .base import BaseAuditor, check_ttl_expired, get_tag
from ..findings.model import Finding


class NetworkingAuditor(BaseAuditor):

    def _scan(self, region: str) -> list:
        ec2 = boto3.client("ec2", region_name=region)
        findings = []

        # Unassociated EIPs
        response = ec2.describe_addresses()
        for eip in response.get("Addresses", []):

            if eip.get("AssociationId"):
                continue

            if get_tag(eip, "sentinel:exclude"):
                continue

            public_ip = eip.get("PublicIp")
            allocation_id = eip.get("AllocationId", public_ip)

            # EIPs have no creation timestamp so TTL must be an absolute date
            if check_ttl_expired(eip):
                findings.append(Finding(
                    resource_id=allocation_id,
                    finding_type="TTL_EXPIRED",
                    severity="Warning",
                    confidence=100,
                    region=region,
                    reasons=[
                        f"EIP {public_ip} is still allocated past its TTL tag expiry.",
                    ],
                ))
                continue

            findings.append(Finding(
                resource_id=allocation_id,
                finding_type="UNASSOCIATED_EIP",
                severity="Medium",
                region=region,
                reasons=[
                    f"EIP {public_ip} is allocated but not attached to any resource.",
                ],
            ))

        # Active NAT Gateways
        paginator = ec2.get_paginator("describe_nat_gateways")
        page_iterator = paginator.paginate(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )

        for page in page_iterator:
            for nat in page.get("NatGateways", []):

                if get_tag(nat, "sentinel:exclude"):
                    continue

                nat_id = nat.get("NatGatewayId")
                vpc_id = nat.get("VpcId")
                subnet_id = nat.get("SubnetId")

                if check_ttl_expired(nat, created_at=nat.get("CreateTime")):
                    findings.append(Finding(
                        resource_id=nat_id,
                        finding_type="TTL_EXPIRED",
                        severity="Warning",
                        confidence=100,
                        region=region,
                        reasons=[
                            f"NAT Gateway {nat_id} is still running past its TTL tag expiry.",
                            f"VPC: {vpc_id}, Subnet: {subnet_id}",
                        ],
                    ))
                    continue

                reasons = [
                    f"NAT Gateway is running in VPC {vpc_id}, subnet {subnet_id}.",
                    "NAT Gateways are billed ~$32/month plus data transfer costs.",
                ]

                env = get_tag(nat, "Environment")
                if env in ("dev", "personal", "test"):
                    reasons.append(f"Environment tag is '{env}' - a NAT Gateway may not be needed here.")

                findings.append(Finding(
                    resource_id=nat_id,
                    finding_type="ACTIVE_NAT_GATEWAY",
                    severity="Low",
                    region=region,
                    reasons=reasons,
                ))

        return findings