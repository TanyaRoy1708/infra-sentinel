import boto3
from datetime import datetime, timedelta
from .base import BaseAuditor, check_ttl_expired, get_tag
from ..findings.model import Finding
from ..findings.scorer import severity_from_score


def get_avg_cpu(instance_id, cloudwatch, hours):
    now = datetime.utcnow()
    response = cloudwatch.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=now - timedelta(hours=hours),
        EndTime=now,
        Period=int(hours * 3600),
        Statistics=["Average"],
        Unit="Percent",
    )
    datapoints = response.get("Datapoints", [])
    if not datapoints:
        return 0.0
    return datapoints[0].get("Average", 0.0)


def is_in_asg(instance):
    return get_tag(instance, "aws:autoscaling:groupName") is not None


class EC2Auditor(BaseAuditor):

    def _scan(self, region: str) -> list:
        ec2 = boto3.client("ec2", region_name=region)
        cloudwatch = boto3.client("cloudwatch", region_name=region)
        findings = []

        paginator = ec2.get_paginator("describe_instances")
        page_iterator = paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        )

        for page in page_iterator:
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):

                    if get_tag(instance, "sentinel:exclude"):
                        continue

                    if check_ttl_expired(instance, created_at=instance.get("LaunchTime")):
                        findings.append(Finding(
                            resource_id=instance["InstanceId"],
                            finding_type="TTL_EXPIRED",
                            severity="Warning",
                            confidence=100,
                            region=region,
                            reasons=[
                                f"Instance {instance['InstanceId']} is still running past its TTL tag expiry.",
                            ],
                        ))
                        continue

                    finding = score_idle_ec2(instance, cloudwatch, region)
                    if finding:
                        findings.append(finding)

        return findings


def score_idle_ec2(instance, cloudwatch, region=""):
    score = 0
    reasons = []
    now = datetime.utcnow()
    instance_id = instance["InstanceId"]

    cpu_avg = get_avg_cpu(instance_id, cloudwatch, hours=4)
    if cpu_avg < 5:
        score += 35
        reasons.append(f"CPU avg {cpu_avg:.1f}% over last 4 hours")

    age_days = (now - instance["LaunchTime"].replace(tzinfo=None)).days
    if age_days > 3:
        score += 20
        reasons.append(f"Running for {age_days} days")

    if not get_tag(instance, "Owner"):
        score += 20
        reasons.append("No Owner tag")

    env = get_tag(instance, "Environment")
    if env in ("dev", "personal", "test"):
        score += 15
        reasons.append(f"Environment tag is '{env}'")

    if not is_in_asg(instance):
        score += 10
        reasons.append("Not part of an Auto Scaling Group")

    if not reasons:
        return None

    return Finding(
        resource_id=instance_id,
        finding_type="IDLE_EC2",
        severity=severity_from_score(score),
        confidence=score,
        region=region,
        reasons=reasons,
    )
