from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from .auth import credentials_from_tokens
import logging

logger = logging.getLogger(__name__)


def build_gmail_service(token_dict: dict):
    creds = credentials_from_tokens(token_dict)
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def list_threads(service, user_id="me", q=None, page_token=None, max_results=100):
    try:
        return service.users().threads().list(userId=user_id, q=q, pageToken=page_token, maxResults=max_results).execute()
    except HttpError as e:
        logger.exception("Gmail API error listing threads")
        raise


def get_thread(service, thread_id, user_id="me"):
    try:
        return service.users().threads().get(userId=user_id, id=thread_id, format="full").execute()
    except HttpError as e:
        logger.exception("Gmail API error fetching thread %s", thread_id)
        raise


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
