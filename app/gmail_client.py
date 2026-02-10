from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from .auth import credentials_from_tokens
import logging
import time
import random

logger = logging.getLogger(__name__)


def build_gmail_service(token_dict: dict):
    creds = credentials_from_tokens(token_dict)
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def execute_request(func, max_retries: int = 5, backoff_factor: float = 2.0):
    """Execute a Gmail API call with retries on transient errors (429, 5xx).

    `func` should be a zero-arg callable that executes the request (eg: lambda: req.execute()).
    """
    attempt = 0
    while True:
        try:
            return func()
        except HttpError as e:
            status = None
            try:
                status = int(getattr(e, 'resp', None).status)
            except Exception:
                try:
                    status = int(getattr(e, 'status_code', 0) or 0)
                except Exception:
                    status = None

            # Retry on rate limit or server errors
            if status in (429, 500, 502, 503, 504) and attempt < max_retries:
                sleep = backoff_factor * \
                    (2 ** attempt) + random.uniform(0, 0.5)
                logger.warning(
                    "Transient Gmail API error %s, retrying after %.2fs (attempt %d)", status, sleep, attempt + 1)
                time.sleep(sleep)
                attempt += 1
                continue
            logger.exception("Gmail API error: %s", e)
            raise


def list_threads(service, user_id="me", q=None, page_token=None, max_results=100):
    return execute_request(lambda: service.users().threads().list(userId=user_id, q=q, pageToken=page_token, maxResults=max_results).execute())


def get_thread(service, thread_id, user_id="me"):
    return execute_request(lambda: service.users().threads().get(userId=user_id, id=thread_id, format="full").execute())


def parse_list_unsubscribe(headers):
    """Parse List-Unsubscribe headers, return dict with https/mailto if present."""
    methods = {"mailto": [], "https": []}
    if not headers:
        return methods
    # headers is a list of dicts with 'name' and 'value'
    for h in headers:
        if h.get("name", "").lower() == "list-unsubscribe":
            val = h.get("value", "")
            parts = [p.strip() for p in val.split(",")]
            for p in parts:
                if p.startswith("<") and p.endswith(">"):
                    p = p[1:-1]
                if p.startswith("mailto:"):
                    methods["mailto"].append(p)
                elif p.startswith("http://") or p.startswith("https://"):
                    methods["https"].append(p)
    return methods


def list_messages(service, user_id="me", q=None, label_ids=None, page_token=None, max_results=100):
    """List messages (not threads) with optional query and labels."""
    params = {
        "userId": user_id,
        "maxResults": max_results
    }
    if q:
        params["q"] = q
    if label_ids:
        params["labelIds"] = label_ids
    if page_token:
        params["pageToken"] = page_token
    return execute_request(lambda: service.users().messages().list(**params).execute())


def get_message(service, message_id, user_id="me", format="full"):
    """Get a single message by ID."""
    return execute_request(lambda: service.users().messages().get(userId=user_id, id=message_id, format=format).execute())


def batch_delete_messages(service, message_ids, user_id="me"):
    """Move multiple messages to trash in one batch request.

    Note: message_ids list should not exceed 1000 items per Gmail API limits.
    Uses batchModify to add TRASH label, which is reversible within 30 days.
    """
    if not message_ids:
        return {"success": True, "count": 0}

    # Gmail API allows up to 1000 message IDs per batchModify call
    if len(message_ids) > 1000:
        logger.warning(
            f"Attempting to trash {len(message_ids)} messages, will split into batches of 1000")

    results = []
    for i in range(0, len(message_ids), 1000):
        batch = message_ids[i:i+1000]
        try:
            # Use batchModify to add TRASH label instead of permanent delete
            execute_request(lambda: service.users().messages().batchModify(
                userId=user_id,
                body={
                    "ids": batch,
                    "addLabelIds": ["TRASH"],
                    "removeLabelIds": ["INBOX"]
                }
            ).execute())
            results.append({"success": True, "count": len(batch)})
            logger.info(f"Successfully moved {len(batch)} messages to trash")
        except HttpError as e:
            # Check for permission errors
            if e.resp.status == 403 and 'insufficientPermissions' in str(e):
                logger.error(
                    f"Insufficient permissions to trash messages. User needs to re-authenticate.")
                return {"success": False, "count": 0, "error": "insufficient_permissions",
                        "message": "Please log out and log back in to grant email management permissions."}
            logger.error(
                f"Failed to trash batch of {len(batch)} messages: {e}")
            results.append({"success": False, "count": 0, "error": str(e)})
        except Exception as e:
            logger.error(
                f"Failed to trash batch of {len(batch)} messages: {e}")
            results.append({"success": False, "count": 0, "error": str(e)})

    total_trashed = sum(r["count"] for r in results)
    return {"success": all(r["success"] for r in results), "count": total_trashed, "batches": results}
