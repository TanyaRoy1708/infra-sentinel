"""
BaseAuditor provides a common scanning framework for all AWS resource auditors.

How it works:
1. Child auditor classes (e.g., EC2Auditor, S3Auditor) inherit from BaseAuditor.
2. Each child implements the private `_scan(region)` method with service-specific
   scanning logic.
3. The public `scan(region)` method acts as a wrapper around `_scan()` and
   provides common functionality for every auditor:
      - Handles AWS ClientError exceptions.
      - Skips regions where access is denied instead of crashing.
      - Retries once after a short backoff if AWS rate limits the request.
      - Skips regions that are disabled or unreachable.
      - Logs warnings for troubleshooting.

Design Pattern:
- Uses the Template Method pattern.
- `_scan()` defines the customizable behavior (implemented by subclasses).
- `scan()` defines the fixed workflow (error handling, retries, logging).

Every auditor automatically gets consistent retry logic, logging, and exception
handling without duplicating code in each AWS service auditor.
"""

import time
import logging
from  botocore.exceptions import ClientError, EndpointResolutionError

logger = logging.getLogger(__name__)
backoff = 2

class BaseAuditor:
    def _scan(self, region: str) -> list:
        raise NotImplementedError

    def scan(self, region: str) -> list:
        try:
            return self._scan(region)
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                logger.warning(f"[{region}] AccessDenied Skipping -{self.__class__.__name__}")
                return []
            elif e.response["Error"]["Code"] == "RequestLimitExceeded":
                time.sleep(backoff)
                return self._scan(region)
        except EndpointResolutionError:
            logger.warning(f"{region} Region unreachable or invalid - skipping")
            return []
