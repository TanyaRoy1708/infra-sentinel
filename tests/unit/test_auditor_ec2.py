import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

from sentinel.auditor.ec2 import EC2Auditor, score_idle_ec2
from sentinel.findings.model import Finding


def make_instance(instance_id, launch_days_ago=1, tags=None):
    return {
        "InstanceId": instance_id,
        "InstanceType": "t3.micro",
        "LaunchTime": datetime.utcnow() - timedelta(days=launch_days_ago),
        "State": {"Name": "running"},
        "Tags": tags or [],
    }


class TestScoreIdleEC2:

    def test_idle_instance_no_owner_dev_env(self):
        instance = make_instance("i-test001", launch_days_ago=10, tags=[
            {"Key": "Environment", "Value": "dev"},
        ])
        cw = MagicMock()
        cw.get_metric_statistics.return_value = {
            "Datapoints": [{"Average": 1.2}]
        }

        finding = score_idle_ec2(instance, cw, region="us-east-1")

        assert finding is not None
        assert isinstance(finding, Finding)
        assert finding.finding_type == "IDLE_EC2"
        assert finding.confidence > 0
        assert "CPU avg" in finding.reasons[0]

    def test_healthy_instance_returns_none(self):
        instance = make_instance("i-healthy", launch_days_ago=1, tags=[
            {"Key": "Owner", "Value": "team-infra"},
            {"Key": "Environment", "Value": "production"},
            {"Key": "aws:autoscaling:groupName", "Value": "prod-asg"},
        ])
        cw = MagicMock()
        cw.get_metric_statistics.return_value = {
            "Datapoints": [{"Average": 55.0}]
        }

        finding = score_idle_ec2(instance, cw)

        assert finding is None

    def test_severity_scales_with_confidence(self):
        instance = make_instance("i-all-signals", launch_days_ago=30, tags=[
            {"Key": "Environment", "Value": "dev"},
        ])
        cw = MagicMock()
        cw.get_metric_statistics.return_value = {
            "Datapoints": [{"Average": 0.5}]
        }

        finding = score_idle_ec2(instance, cw)

        # CPU(35) + age(20) + no_owner(20) + env(15) + no_asg(10) = 100
        assert finding.confidence == 100
        assert finding.severity == "Critical"


class TestEC2Auditor:

    @patch("sentinel.auditor.ec2.boto3")
    def test_excluded_instances_are_skipped(self, mock_boto3):
        ec2_client = MagicMock()
        cw_client = MagicMock()
        mock_boto3.client.side_effect = lambda svc, **kw: (
            ec2_client if svc == "ec2" else cw_client
        )

        ec2_client.get_paginator.return_value.paginate.return_value = [{
            "Reservations": [{
                "Instances": [
                    make_instance("i-excluded", tags=[
                        {"Key": "sentinel:exclude", "Value": "true"},
                    ]),
                ]
            }]
        }]

        findings = EC2Auditor().scan("us-east-1")
        assert len(findings) == 0

    @patch("sentinel.auditor.ec2.boto3")
    def test_ttl_expired_instance_flagged(self, mock_boto3):
        ec2_client = MagicMock()
        cw_client = MagicMock()
        mock_boto3.client.side_effect = lambda svc, **kw: (
            ec2_client if svc == "ec2" else cw_client
        )

        ec2_client.get_paginator.return_value.paginate.return_value = [{
            "Reservations": [{
                "Instances": [
                    make_instance("i-ttl", launch_days_ago=10, tags=[
                        {"Key": "TTL", "Value": "3d"},
                    ]),
                ]
            }]
        }]

        findings = EC2Auditor().scan("us-east-1")
        assert len(findings) == 1
        assert findings[0].finding_type == "TTL_EXPIRED"
        assert findings[0].confidence == 100
