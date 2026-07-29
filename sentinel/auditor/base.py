import re
import time
import logging
from datetime import datetime, timedelta
from botocore.exceptions import ClientError, EndpointResolutionError

logger = logging.getLogger(__name__)

RETRY_WAIT_SECONDS = 2


# --------------------------------------------------------------------------- #
# Tag helper — works for both EC2/EBS/NAT (Tags) and RDS (TagList)            #
# --------------------------------------------------------------------------- #

def get_tag(resource, key):
    """
    Return the value of a tag by key, or None if not found.
    Checks both 'Tags' (EC2, EBS, EIP, NAT) and 'TagList' (RDS).
    """
    for tag_list_key in ("Tags", "TagList"):
        for tag in resource.get(tag_list_key, []):
            if tag.get("Key") == key:
                return tag.get("Value")
    return None


# --------------------------------------------------------------------------- #
# TTL tag support                                                              #
#                                                                              #
# Engineers tag a resource with a TTL to declare its expected lifespan:       #
#   TTL = "72h"        → expires 72 hours after the resource was created      #
#   TTL = "7d"         → expires 7 days after the resource was created        #
#   TTL = "2026-08-01" → expires on that specific date                        #
#                                                                              #
# If the TTL has passed and the resource still exists → TTL_EXPIRED finding.  #
# --------------------------------------------------------------------------- #

def parse_ttl(ttl_value, created_at):
    """
    Convert a TTL tag value into an expiry datetime.

    - Duration format ("72h", "7d"): expiry = created_at + duration
    - Absolute date format ("2026-08-01"): expiry = that date at midnight UTC
    - Anything unparseable: returns datetime.max (safe — will never expire)
    """
    ttl_value = ttl_value.strip()

    # Duration: "72h" or "7d"
    match = re.fullmatch(r"(\d+)([hd])", ttl_value, re.IGNORECASE)
    if match:
        amount = int(match.group(1))
        unit = match.group(2).lower()
        if unit == "h":
            return created_at + timedelta(hours=amount)
        elif unit == "d":
            return created_at + timedelta(days=amount)

    # Absolute date: "2026-08-01"
    try:
        return datetime.strptime(ttl_value, "%Y-%m-%d")
    except ValueError:
        pass

    # Unrecognised format — treat as never expired (safe default)
    logger.warning(f"Could not parse TTL value '{ttl_value}' — skipping TTL check")
    return datetime.max


def check_ttl_expired(resource, created_at=None):
    """
    Return True if the resource has a TTL tag that has already passed.
    Returns False if there is no TTL tag or the TTL is still in the future.

    created_at: the datetime the resource was created.
                AWS returns timezone-aware datetimes — we strip tzinfo for
                comparison since datetime.utcnow() is naive.
    """
    ttl_value = get_tag(resource, "TTL")
    if not ttl_value:
        return False

    if created_at is None:
        created_at = datetime.utcnow()

    # Strip timezone info if present (AWS datetimes are tz-aware)
    if hasattr(created_at, "tzinfo") and created_at.tzinfo is not None:
        created_at = created_at.replace(tzinfo=None)

    expiry = parse_ttl(ttl_value, created_at)
    return datetime.utcnow() > expiry


# --------------------------------------------------------------------------- #
# Base auditor class                                                           #
# --------------------------------------------------------------------------- #

class BaseAuditor:
    """
    Base class for all auditors.
    Subclasses implement _scan(region) with their own logic.
    This class handles errors and retries so each auditor doesn't have to.
    """

    def _scan(self, region: str) -> list:
        # Subclasses must override this method
        raise NotImplementedError

    def scan(self, region: str) -> list:
        try:
            return self._scan(region)

        except ClientError as e:
            error_code = e.response["Error"]["Code"]

            if error_code == "AccessDenied":
                logger.warning(f"[{region}] Access denied — skipping {self.__class__.__name__}")
                return []

            elif error_code == "RequestLimitExceeded":
                logger.warning(f"[{region}] Rate limited — retrying after {RETRY_WAIT_SECONDS}s")
                time.sleep(RETRY_WAIT_SECONDS)
                return self._scan(region)

            return []

        except EndpointResolutionError:
            logger.warning(f"[{region}] Region is disabled or unreachable — skipping")
            return []
