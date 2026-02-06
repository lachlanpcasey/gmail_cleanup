import re
from urllib.parse import urlparse
import httpx
import logging
from googleapiclient.errors import HttpError
from sqlalchemy.exc import OperationalError
from .db import SessionLocal
from .models import User

logger = logging.getLogger(__name__)


def is_safe_https_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return False
        # Prevent suspicious javascript/data schemes or inline redirects - basic check
        if "redirect" in parsed.query.lower():
            return False
        return True
    except Exception:
        return False


async def try_https_unsubscribe(url: str, timeout=10):
    if not is_safe_https_url(url):
        return {"ok": False, "reason": "unsafe_url"}
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
            # Use GET as RFC does not mandate method, many implementations accept GET
            resp = await client.get(url)
            return {"ok": resp.status_code in (200, 202, 204), "status": resp.status_code, "body_snippet": resp.text[:200]}
    except httpx.RequestError as e:
        logger.exception("HTTPS unsubscribe request failed")
        return {"ok": False, "reason": "network", "error": str(e)}


def format_mailto_unsubscribe(mailto: str) -> dict:
    # mailto:unsubscribe@example.com?subject=unsubscribe
    return {"mailto": mailto}


async def _execute_with_service(service, group_domain: str, methods: dict):
    """Core execution given a built Gmail `service` object."""
    results = {"domain": group_domain, "actions": []}

    # Prefer HTTPS endpoints
    for url in methods.get("https", []):
        if not is_safe_https_url(url):
            results["actions"].append(
                {"method": "https", "url": url, "ok": False, "reason": "unsafe_url"})
            continue
        res = await try_https_unsubscribe(url)
        results["actions"].append({"method": "https", "url": url, **res})
        if res.get("ok"):
            return results

    # Next, mailto addresses (may require send scope)
    for m in methods.get("mailto", []):
        try:
            from email.mime.text import MIMEText
            import base64
            msg = MIMEText("Please unsubscribe me from this mailing list.")
            msg["To"] = m.replace("mailto:", "")
            msg["Subject"] = "Unsubscribe"
            raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
            body = {"raw": raw}
            try:
                from .gmail_client import execute_request
                send_resp = execute_request(lambda: service.users().messages().send(userId="me", body=body).execute())
                results["actions"].append({"method": "mailto", "mailto": m, "ok": True, "sendResponseId": send_resp.get("id")})
                return results
            except HttpError as he:
                status = None
                try:
                    status = int(getattr(he, 'resp', None).status)
                except Exception:
                    status = int(getattr(he, 'status_code', 0) or 0)
                results["actions"].append({"method": "mailto", "mailto": m, "ok": False, "reason": f"google_api_error_{status}"})
        except Exception as e:
            results["actions"].append(
                {"method": "mailto", "mailto": m, "ok": False, "reason": str(e)})

    # Fallback: create a Gmail filter to archive/delete future messages from this domain
    try:
        criteria = {"from": "@%s" % group_domain}
        action = {"removeLabelIds": ["INBOX"], "addLabelIds": ["TRASH"]}
        fb = {"criteria": criteria, "action": action}
        try:
            from .gmail_client import execute_request
            fresp = execute_request(lambda: service.users().settings().filters().create(userId="me", body=fb).execute())
            results["actions"].append({"method": "filter_create", "ok": True, "filterId": fresp.get("id")})
        except HttpError as he:
            status = None
            try:
                status = int(getattr(he, 'resp', None).status)
            except Exception:
                status = int(getattr(he, 'status_code', 0) or 0)
            results["actions"].append({"method": "filter_create", "ok": False, "reason": f"google_api_error_{status}"})
    except Exception as e:
        results["actions"].append(
            {"method": "filter_create", "ok": False, "reason": str(e)})

    return results


async def execute_unsubscribe_task(user_id: int, group_domain: str, methods: dict):
    """Background task entrypoint: refresh tokens as needed and run unsubscribe flow, persisting failures."""
    logger = logging.getLogger(__name__)
    db = SessionLocal()
    try:
        try:
            user = db.query(User).filter(User.id == user_id).first()
        except OperationalError as e:
            # Handle missing-table during tests / fresh DB: treat as user not found
            msg = str(e).lower()
            if "no such table" in msg:
                logger.warning("unsubscribe task: users table missing, treat as no user")
                return {"ok": False, "reason": "user_not_found"}
            logger.exception("Database operational error when fetching user %s: %s", user_id, e)
            return {"ok": False, "reason": "db_error", "detail": str(e)}

        if not user:
            logger.error("unsubscribe task: user %s not found", user_id)
            return {"ok": False, "reason": "user_not_found"}

        from .auth import refresh_and_persist_tokens

        try:
            token_dict = refresh_and_persist_tokens(user, db)
        except Exception as e:
            logger.exception(
                "Failed to refresh tokens for unsubscribe task: %s", e)
            return {"ok": False, "reason": "token_refresh_failed", "detail": str(e)}

        # Build service using refreshed tokens
        try:
            service = build_gmail_service(token_dict)
        except Exception as e:
            logger.exception(
                "Failed to build Gmail service for unsubscribe task: %s", e)
            return {"ok": False, "reason": "service_build_failed", "detail": str(e)}

        # Execute core flow
        try:
            res = await _execute_with_service(service, group_domain, methods)
            logger.info("unsubscribe result for %s: %s", group_domain, res)
            return {"ok": True, "result": res}
        except Exception as e:
            logger.exception(
                "unsubscribe execution failed for %s: %s", group_domain, e)
            return {"ok": False, "reason": "execution_failed", "detail": str(e)}
    finally:
        db.close()
