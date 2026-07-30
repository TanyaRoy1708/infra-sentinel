import os
import json
import logging
import boto3
from datetime import datetime, timezone

from sentinel.auditor.ec2 import EC2Auditor
from sentinel.auditor.ebs import EBSAuditor
from sentinel.auditor.networking import NetworkingAuditor
from sentinel.auditor.database import RDSAuditor

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s - %(message)s")
logger = logging.getLogger(__name__)


def lambda_handler(event, context):
    scan_regions = os.environ.get("SCAN_REGIONS", "us-east-1").split(",")
    report_bucket = os.environ.get("REPORT_BUCKET_NAME")

    if not report_bucket:
        raise ValueError("REPORT_BUCKET_NAME environment variable is not set")

    logger.info(f"Starting Sentinel audit across regions: {scan_regions}")

    all_findings = []

    for region in scan_regions:
        region = region.strip()
        logger.info(f"[{region}] Scanning...")
        all_findings.extend(EC2Auditor().scan(region))
        all_findings.extend(EBSAuditor().scan(region))
        all_findings.extend(NetworkingAuditor().scan(region))
        all_findings.extend(RDSAuditor().scan(region))

    logger.info(f"Audit complete. Total findings: {len(all_findings)}")

    report = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "regions_scanned": scan_regions,
        "total_findings": len(all_findings),
        "findings": [f.__dict__ for f in all_findings],
    }

    s3_key = f"reports/{datetime.now(timezone.utc).strftime('%Y/%m/%d')}/sentinel-report.json"
    s3 = boto3.client("s3")
    s3.put_object(
        Bucket=report_bucket,
        Key=s3_key,
        Body=json.dumps(report, indent=2, default=str),
        ContentType="application/json",
    )

    logger.info(f"Report uploaded to s3://{report_bucket}/{s3_key}")

    return {
        "statusCode": 200,
        "body": f"Audit complete. {len(all_findings)} findings. Report: s3://{report_bucket}/{s3_key}",
    }
