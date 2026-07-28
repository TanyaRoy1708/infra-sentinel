from datetime import tzinfo
import typing_extensions
from datetime import timedelta, datetime
import boto3

# Helper function to safely extract EC2 tags
def get_tag_value(instance, tag_key):
    tags = instance.get('Tags', [])
    for tag in tags:
        if tag.get('Key') == tag_key:
            return tag.get('Value')
    return None

def get_cloudwatch_avg_cpu(instance_id, cloudwatch_client, hours):
    now = datetime.utcnow()
    
    response = cloudwatch_client.get_metric_statistics(
        Namespace='AWS/EC2',
        MetricName='CPUUtilization',
        Dimensions=[
            {
                'Name': 'InstanceId',
                'Value': instance_id
            },
        ],
        StartTime=now - timedelta(hours=hours),
        EndTime=now,
        Period=int(hours * 3600),  # Single datapoint for the entire duration
        Statistics=['Average'],
        Unit='Percent'
    )
    
    datapoints = response.get('Datapoints', [])
    if not datapoints:
        return 0.0
        
    return datapoints[0].get('Average', 0.0)

def is_in_asg(instance):
    # Using our new helper function
    return get_tag_value(instance, 'aws:autoscaling:groupName') is not None

def severity_from_score(score):
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"

class Finding:
    def __init__(self, resource_id, finding_type, severity, confidence, reasons):
        self.resource_id = resource_id
        self.finding_type = finding_type
        self.severity = severity
        self.confidence = confidence
        self.reasons = reasons

def score_idle_ec2(instance, cloudwatch_client) -> Finding:
    score = 0
    reasons = []
    now = datetime.utcnow() # Calculate 'now' fresh for every evaluation

    # Explicit exclusion tag overrides everything (check this first to save API calls)
    if get_tag_value(instance, 'sentinel:exclude'):
        return None  # Skip — intentionally excluded

    cpu_avg = get_cloudwatch_avg_cpu(instance['InstanceId'], cloudwatch_client, hours=4)
    if cpu_avg < 5:
        score += 35
        reasons.append(f"CPU avg {cpu_avg:.1f}% over 4h")

    age_days = (now - instance['LaunchTime'].replace(tzinfo=None)).days
    if age_days > 3:
        score += 20
        reasons.append(f"Age: {age_days}d")

    if not get_tag_value(instance, 'Owner'):
        score += 20
        reasons.append("No Owner tag")

    if get_tag_value(instance, 'Environment') in ('dev', 'personal', 'test'):
        score += 15
        reasons.append("Environment=dev")

    if not is_in_asg(instance):
        score += 10
        reasons.append("Not part of ASG")

    return Finding(
        resource_id=instance['InstanceId'],
        finding_type="IDLE_EC2",
        severity=severity_from_score(score),
        confidence=score,   # 0-100
        reasons=reasons
    )
