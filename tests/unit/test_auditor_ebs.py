import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

from sentinel.auditor.ebs import EBSAuditor
from sentinel.findings.model import Finding


def make_volume(vol_id, size=50, vol_type="gp2", days_ago=10, tags=None):
    return {
        "VolumeId": vol_id,
        "Size": size,
        "VolumeType": vol_type,
        "State": "available",
        "CreateTime": datetime.utcnow() - timedelta(days=days_ago),
        "Tags": tags or [],
    }


class TestEBSAuditor:

    @patch("sentinel.auditor.ebs.boto3")
    def test_detached_volume_flagged(self, mock_boto3):
        client = MagicMock()
        mock_boto3.client.return_value = client

        client.get_paginator.return_value.paginate.return_value = [{
            "Volumes": [make_volume("vol-001")]
        }]

        findings = EBSAuditor().scan("us-east-1")

        assert len(findings) == 1
        assert isinstance(findings[0], Finding)
        assert findings[0].finding_type == "UNATTACHED_EBS_VOLUME"
        assert findings[0].resource_id == "vol-001"

    @patch("sentinel.auditor.ebs.boto3")
    def test_excluded_volume_skipped(self, mock_boto3):
        client = MagicMock()
        mock_boto3.client.return_value = client

        client.get_paginator.return_value.paginate.return_value = [{
            "Volumes": [make_volume("vol-excluded", tags=[
                {"Key": "sentinel:exclude", "Value": "true"},
            ])]
        }]

        findings = EBSAuditor().scan("us-east-1")
        assert len(findings) == 0

    @patch("sentinel.auditor.ebs.boto3")
    def test_ttl_expired_volume_flagged(self, mock_boto3):
        client = MagicMock()
        mock_boto3.client.return_value = client

        client.get_paginator.return_value.paginate.return_value = [{
            "Volumes": [make_volume("vol-ttl", days_ago=10, tags=[
                {"Key": "TTL", "Value": "3d"},
            ])]
        }]

        findings = EBSAuditor().scan("us-east-1")

        assert len(findings) == 1
        assert findings[0].finding_type == "TTL_EXPIRED"
        assert findings[0].confidence == 100

    @patch("sentinel.auditor.ebs.boto3")
    def test_multiple_volumes_returns_multiple_findings(self, mock_boto3):
        client = MagicMock()
        mock_boto3.client.return_value = client

        client.get_paginator.return_value.paginate.return_value = [{
            "Volumes": [
                make_volume("vol-a", size=50),
                make_volume("vol-b", size=100),
            ]
        }]

        findings = EBSAuditor().scan("us-east-1")
        assert len(findings) == 2
