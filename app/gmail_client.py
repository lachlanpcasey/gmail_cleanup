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


def execute_request(func, max_retries: int = 3, backoff_factor: float = 1.0):
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
