import boto3
from datetime import datetime, timedelta
from .base import BaseAuditor, check_ttl_expired, get_tag


def get_avg_cpu(instance_id, cloudwatch, hours):
    """Return the average CPU % for an instance over the last N hours."""
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
    """Return True if the instance belongs to an Auto Scaling Group."""
    return get_tag(instance, "aws:autoscaling:groupName") is not None


def severity_from_score(score):
    """Map a 0–100 confidence score to a severity label."""
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"


# --- Auditor class ---

class EC2Auditor(BaseAuditor):
    """
    Scans EC2 instances for signs of being idle/unused.
    Also flags instances whose TTL tag has expired.
    """

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

                    # Skip intentionally excluded instances
                    if get_tag(instance, "sentinel:exclude"):
                        continue

                    # TTL check — instance promised to be gone by now
                    if check_ttl_expired(instance, created_at=instance.get("LaunchTime")):
                        findings.append({
                            "resource_id": instance["InstanceId"],
                            "finding_type": "TTL_EXPIRED",
                            "severity": "Warning",
                            "confidence": 100,
                            "reasons": [
                                f"Instance {instance['InstanceId']} is still running past its TTL tag expiry.",
                            ],
                        })
                        continue  # No need to score idle — TTL expiry is the finding

                    # Score the instance for idleness
                    finding = score_idle_ec2(instance, cloudwatch)
                    if finding:
                        findings.append(finding)

        return findings


def score_idle_ec2(instance, cloudwatch):
    """
    Score an EC2 instance for idleness.
    Returns a finding dict if any idle signals are triggered, or None if none are.
    """
    score = 0
    reasons = []
    now = datetime.utcnow()
    instance_id = instance["InstanceId"]

    # Signal 1: Low CPU usage
    cpu_avg = get_avg_cpu(instance_id, cloudwatch, hours=4)
    if cpu_avg < 5:
        score += 35
        reasons.append(f"CPU avg {cpu_avg:.1f}% over last 4 hours")

    # Signal 2: Instance has been running for a while
    age_days = (now - instance["LaunchTime"].replace(tzinfo=None)).days
    if age_days > 3:
        score += 20
        reasons.append(f"Running for {age_days} days")

    # Signal 3: No Owner tag
    if not get_tag(instance, "Owner"):
        score += 20
        reasons.append("No Owner tag")

    # Signal 4: Non-production environment
    env = get_tag(instance, "Environment")
    if env in ("dev", "personal", "test"):
        score += 15
        reasons.append(f"Environment tag is '{env}'")

    # Signal 5: Not managed by an ASG
    if not is_in_asg(instance):
        score += 10
        reasons.append("Not part of an Auto Scaling Group")

    # No signals triggered — instance looks healthy, nothing to report
    if not reasons:
        return None

    return {
        "resource_id": instance_id,
        "finding_type": "IDLE_EC2",
        "severity": severity_from_score(score),
        "confidence": score,
        "reasons": reasons,
    }
