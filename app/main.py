import os
from fastapi import FastAPI, Request, Depends, Form, BackgroundTasks
from fastapi.responses import RedirectResponse, HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from dotenv import load_dotenv
from .db import init_db, SessionLocal
from . import auth, gmail_client, unsubscribe, scanner
from .models import User, SubscriptionGroup, SubscriptionMessage, ScanProgress, PromotionsDomain, PromotionsScanProgress
from sqlalchemy.orm import Session
import uvicorn
import logging

# Configure logging to print all logs to the console
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(name)s: %(message)s')

logger = logging.getLogger(__name__)

load_dotenv()

# Allow OAuth over HTTP for local development (DO NOT use in production)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = FastAPI()
templates = Jinja2Templates(directory=os.path.join(
    os.path.dirname(__file__), "..", "templates"))


# Persistent authentication middleware
class PersistentAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip for auth endpoints
        if request.url.path in ["/login", "/oauth2callback", "/logout"]:
            return await call_next(request)

        # If session doesn't have user, check for persistent auth cookie
        if "user" not in request.session:
            auth_email = request.cookies.get("gmail_cleanup_auth")
            if auth_email:
                # Try to restore session from database
                db = SessionLocal()
                try:
                    user = db.query(User).filter(
                        User.email == auth_email).first()
                    if user and user.encrypted_tokens:
                        # Verify tokens are still valid by attempting refresh
                        try:
                            auth.refresh_and_persist_tokens(user, db)
                            # Restore session
                            request.session["user"] = {"email": user.email}
                        except Exception:
                            # Tokens expired or invalid, clear cookie
                            pass
                finally:
                    db.close()

        response = await call_next(request)
        return response


# Add middleware in correct order: SessionMiddleware must be added LAST so it runs FIRST
app.add_middleware(PersistentAuthMiddleware)
app.add_middleware(SessionMiddleware, secret_key=os.environ.get(
    "SESSION_SECRET") or "dev-secret", https_only=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
def startup():
    init_db()
    # Reset any stale scanning states from interrupted scans
    db = SessionLocal()
    try:
        # Reset subscription scans
        stale_scans = db.query(ScanProgress).filter(
            ScanProgress.is_scanning == True).all()
        if stale_scans:
            for scan in stale_scans:
                scan.is_scanning = False
            db.commit()
            logging.info(
                f"Reset {len(stale_scans)} stale subscription scanning state(s)")

        # Reset promotions scans
        stale_promo_scans = db.query(PromotionsScanProgress).filter(
            PromotionsScanProgress.is_scanning == True).all()
        if stale_promo_scans:
            for scan in stale_promo_scans:
                scan.is_scanning = False
            db.commit()
            logging.info(
                f"Reset {len(stale_promo_scans)} stale promotions scanning state(s)")
    finally:
        db.close()


@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    user = request.session.get("user")
    unsubscribed_count = 0
    failed_count = 0
    emails_deleted = 0
    if user:
        db_user = db.query(User).filter(
            User.email == user.get("email")).first()
        if db_user:
            unsubscribed_count = db.query(SubscriptionGroup).filter(
                SubscriptionGroup.user_id == db_user.id,
                SubscriptionGroup.unsubscribed == 1
            ).count()
            failed_count = db.query(SubscriptionGroup).filter(
                SubscriptionGroup.user_id == db_user.id,
                SubscriptionGroup.unsubscribe_failed == 1
            ).count()
            emails_deleted = db_user.emails_deleted or 0
    return templates.TemplateResponse("index.html", {
        "request": request,
        "user": user,
        "unsubscribed_count": unsubscribed_count,
        "failed_count": failed_count,
        "emails_deleted": emails_deleted
    })


@app.get("/login")
def login(request: Request):
    flow = auth.make_flow(request)
    auth_url, state = flow.authorization_url(
        access_type="offline", include_granted_scopes="true", prompt="consent")
    request.session["oauth_state"] = state
    return RedirectResponse(auth_url)


@app.get("/oauth2callback")
async def oauth2callback(request: Request, db: Session = Depends(get_db)):
    import logging
    import sys
    logger = logging.getLogger("gmail_cleanup.oauth2callback")

    # Log that we received the callback
    print(f"=== CALLBACK RECEIVED === URL: {request.url}", flush=True)
    logger.info(f"OAuth2 callback received: {request.url}")

    try:
        print("=== OAuth2 Callback Start ===", flush=True)
        sys.stdout.flush()
        state = request.session.get("oauth_state")
        print(f"Step 1: Got state from session: {state}", flush=True)

        flow = auth.make_flow(request)
        print("Step 2: Created OAuth flow", flush=True)

        print(f"Step 3: Fetching token with URL: {request.url}", flush=True)
        flow.fetch_token(authorization_response=str(request.url))
        print("Step 4: Token fetched successfully", flush=True)

        creds = flow.credentials
        print(
            f"Step 5: Got credentials, token exists: {bool(creds.token)}", flush=True)

        # minimal userinfo: email from id_token if present
        email = None
        if creds.id_token:
            import jwt
            try:
                info = jwt.decode(creds.id_token, options={
                                  "verify_signature": False})
                email = info.get("email")
                print(f"Step 6: Decoded email from JWT: {email}", flush=True)
            except Exception as e:
                logger.error(f"JWT decode failed: {e}")
                print(f"Step 6 ERROR: JWT decode failed: {e}", flush=True)
                email = None
        if not email:
            email = "unknown"
            print("Step 7: No email found, using 'unknown'", flush=True)

        print("Step 8: Encrypting tokens...", flush=True)
        encrypted = auth.encrypt_tokens({
            "token": creds.token,
            "refresh_token": creds.refresh_token,
            "id_token": creds.id_token,
        })
        print("Step 9: Tokens encrypted successfully", flush=True)

        # upsert user
        print(f"Step 10: Querying for user with email: {email}", flush=True)
        user = db.query(User).filter(User.email == email).first()
        if not user:
            print("Step 11: Creating new user", flush=True)
            user = User(email=email, encrypted_tokens=encrypted)
            db.add(user)
        else:
            print("Step 12: Updating existing user", flush=True)
            user.encrypted_tokens = encrypted

        print("Step 13: Committing to database...", flush=True)
        db.commit()
        print("Step 14: Database commit successful", flush=True)

        request.session["user"] = {"email": email}
        print("Step 15: Session updated, redirecting to /", flush=True)

        # Create response with persistent auth cookie
        response = RedirectResponse("/")
        # Set cookie that lasts 30 days
        response.set_cookie(
            key="gmail_cleanup_auth",
            value=email,
            max_age=30 * 24 * 60 * 60,  # 30 days
            httponly=True,
            samesite="lax"
        )
        return response
    except Exception as e:
        logger.error(f"OAuth2 callback failed: {e}", exc_info=True)
        print(f"=== EXCEPTION in OAuth2 Callback: {e} ===", flush=True)
        import traceback
        tb = traceback.format_exc()
        print(tb, flush=True)
        return HTMLResponse(
            f"<h2>Internal Server Error</h2>"
            f"<h3>Error: {e}</h3>"
            f"<pre>{tb}</pre>",
            status_code=500
        )


@app.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    request.session.clear()
    response = RedirectResponse("/")
    # Clear the persistent auth cookie
    response.delete_cookie("gmail_cleanup_auth")
    return response


@app.get("/subscriptions", response_class=HTMLResponse)
def subscriptions(request: Request, db: Session = Depends(get_db)):
    user_sess = request.session.get("user")
    if not user_sess:
        return RedirectResponse("/login")
    # load detected subscription groups from DB (only active subscriptions)
    user = db.query(User).filter(User.email == user_sess.get("email")).first()
    groups = []
    if user:
        groups = db.query(SubscriptionGroup).filter(
            SubscriptionGroup.user_id == user.id,
            SubscriptionGroup.unsubscribed == 0,
            SubscriptionGroup.unsubscribe_failed == 0
        ).order_by(SubscriptionGroup.confidence_score.desc()).all()

    return templates.TemplateResponse("subscriptions.html", {
        "request": request,
        "groups": groups
    })


@app.get("/failed", response_class=HTMLResponse)
def failed_unsubscribes(request: Request, db: Session = Depends(get_db)):
    user_sess = request.session.get("user")
    if not user_sess:
        return RedirectResponse("/login")
    user = db.query(User).filter(User.email == user_sess.get("email")).first()
    failed_groups = []
    if user:
        failed_groups = db.query(SubscriptionGroup).filter(
            SubscriptionGroup.user_id == user.id,
            SubscriptionGroup.unsubscribe_failed == 1
        ).order_by(SubscriptionGroup.sender_domain).all()

    return templates.TemplateResponse("failed.html", {
        "request": request,
        "failed_groups": failed_groups
    })


@app.get("/successful", response_class=HTMLResponse)
def successful_unsubscribes(request: Request, db: Session = Depends(get_db)):
    user_sess = request.session.get("user")
    if not user_sess:
        return RedirectResponse("/login")
    user = db.query(User).filter(User.email == user_sess.get("email")).first()
    unsubscribed_groups = []
    if user:
        unsubscribed_groups = db.query(SubscriptionGroup).filter(
            SubscriptionGroup.user_id == user.id,
            SubscriptionGroup.unsubscribed == 1
        ).order_by(SubscriptionGroup.sender_domain).all()

    return templates.TemplateResponse("successful.html", {
        "request": request,
        "unsubscribed_groups": unsubscribed_groups
    })


@app.post("/execute_unsubscribe")
async def execute_unsubscribe(request: Request, background: BackgroundTasks, db: Session = Depends(get_db)):
    data = await request.json()
    # data expected: { "groups": [group_id, ...] }
    group_ids = data.get("groups", [])
    user_sess = request.session.get("user")
    if not user_sess:
        return {"ok": False, "error": "not_authenticated"}
    user = db.query(User).filter(User.email == user_sess.get("email")).first()
    if not user:
        return {"ok": False, "error": "user_not_found"}

    # Validate ownership of group ids
    valid_groups = db.query(SubscriptionGroup).filter(
        SubscriptionGroup.user_id == user.id, SubscriptionGroup.id.in_(group_ids)).all()
    if not valid_groups:
        return {"ok": False, "error": "no_valid_groups"}

    # Decrypt tokens
    from .auth import decrypt_tokens
    token_dict = decrypt_tokens(
        user.encrypted_tokens) if user.encrypted_tokens else {}
    service = None
    try:
        service = gmail_client.build_gmail_service(token_dict)
    except Exception:
        service = None

    results = []
    for g in valid_groups:
        # aggregate methods from recent messages
        msgs = db.query(SubscriptionMessage).filter(
            SubscriptionMessage.group_id == g.id).limit(10).all()
        agg_methods = {"mailto": [], "https": []}
        for m in msgs:
            um = m.unsubscribe_methods or {}
            for k in ("mailto", "https"):
                agg_methods[k].extend(um.get(k, []))

        # schedule execution in background: pass user id so tokens can be refreshed/persisted inside task
        background.add_task(unsubscribe.execute_unsubscribe_task,
                            user.id, g.sender_domain, agg_methods)
        results.append(
            {"group_id": g.id, "domain": g.sender_domain, "status": "queued"})

    return {"ok": True, "results": results}


@app.post("/remove_from_list")
async def remove_from_list(request: Request, db: Session = Depends(get_db)):
    """Remove subscription groups from list without unsubscribing."""
    data = await request.json()
    group_ids = data.get("groups", [])
    user_sess = request.session.get("user")
    if not user_sess:
        return {"ok": False, "error": "not_authenticated"}
    user = db.query(User).filter(User.email == user_sess.get("email")).first()
    if not user:
        return {"ok": False, "error": "user_not_found"}

    # Validate ownership and delete groups
    deleted = db.query(SubscriptionGroup).filter(
        SubscriptionGroup.user_id == user.id,
        SubscriptionGroup.id.in_(group_ids)
    ).delete(synchronize_session=False)
    db.commit()

    return {"ok": True, "deleted": deleted}


@app.get("/subscription_details/{group_id}")
def get_subscription_details(group_id: int, request: Request, db: Session = Depends(get_db)):
    user_sess = request.session.get("user")
    if not user_sess:
        return {"ok": False, "error": "not_authenticated"}
    user = db.query(User).filter(User.email == user_sess.get("email")).first()
    if not user:
        return {"ok": False, "error": "user_not_found"}

    # Get the subscription group and verify ownership
    group = db.query(SubscriptionGroup).filter(
        SubscriptionGroup.id == group_id,
        SubscriptionGroup.user_id == user.id
    ).first()

    if not group:
        return {"ok": False, "error": "group_not_found"}

    # Get subscription messages with unsubscribe methods
    messages = db.query(SubscriptionMessage).filter(
        SubscriptionMessage.group_id == group_id
    ).all()

    # Extract unique unsubscribe URLs
    https_urls = set()
    for msg in messages:
        if msg.unsubscribe_methods and isinstance(msg.unsubscribe_methods, dict):
            https_value = msg.unsubscribe_methods.get("https")
            if https_value:
                # Handle both string and list formats
                if isinstance(https_value, list):
                    https_urls.update(https_value)
                elif isinstance(https_value, str):
                    https_urls.add(https_value)

    return {
        "ok": True,
        "group": {
            "sender_name": group.sender_name,
            "sender_domain": group.sender_domain,
            "frequency_score": group.frequency_score,
            "example_subjects": group.example_subjects or []
        },
        "unsubscribe_urls": list(https_urls)
    }


@app.get("/subscription_details")
def get_subscription_details_by_domain(domain: str, request: Request, db: Session = Depends(get_db)):
    user_sess = request.session.get("user")
    if not user_sess:
        return {"ok": False, "error": "not_authenticated"}
    user = db.query(User).filter(User.email == user_sess.get("email")).first()
    if not user:
        return {"ok": False, "error": "user_not_found"}

    # Get the subscription group by domain and verify ownership
    group = db.query(SubscriptionGroup).filter(
        SubscriptionGroup.sender_domain == domain,
        SubscriptionGroup.user_id == user.id
    ).first()

    if not group:
        return {"ok": False, "error": "group_not_found"}

    # Get subscription messages with unsubscribe methods
    messages = db.query(SubscriptionMessage).filter(
        SubscriptionMessage.group_id == group.id
    ).all()

    # Extract unique unsubscribe URLs
    https_urls = set()
    for msg in messages:
        if msg.unsubscribe_methods and isinstance(msg.unsubscribe_methods, dict):
            https_value = msg.unsubscribe_methods.get("https")
            if https_value:
                # Handle both string and list formats
                if isinstance(https_value, list):
                    https_urls.update(https_value)
                elif isinstance(https_value, str):
                    https_urls.add(https_value)

    return {
        "ok": True,
        "sender_name": group.sender_name,
        "sender_domain": group.sender_domain,
        "frequency_score": group.frequency_score,
        "example_subjects": group.example_subjects or [],
        "unsubscribe_urls": list(https_urls)
    }


@app.post("/start_scan")
def start_scan(request: Request, background: BackgroundTasks, db: Session = Depends(get_db)):
    user_sess = request.session.get("user")
    if not user_sess:
        return {"ok": False, "error": "not_authenticated"}
    user = db.query(User).filter(User.email == user_sess.get("email")).first()
    if not user:
        return {"ok": False, "error": "user_not_found"}
    # enqueue background scan
    background.add_task(scanner.scan_user_mailbox, user.id)
    return {"ok": True, "message": "scan_started"}


@app.get("/scan_progress")
def get_scan_progress(request: Request, db: Session = Depends(get_db)):
    user_sess = request.session.get("user")
    if not user_sess:
        return {"ok": False, "error": "not_authenticated"}
    user = db.query(User).filter(User.email == user_sess.get("email")).first()
    if not user:
        return {"ok": False, "error": "user_not_found"}

    scan_progress = db.query(ScanProgress).filter(
        ScanProgress.user_id == user.id).first()
    if not scan_progress:
        return {"ok": True, "is_scanning": False, "current": 0, "total": 0, "percent": 0, "new_subscriptions": 0, "total_scanned": 0}

    percent = 0
    if scan_progress.estimated_total > 0:
        percent = min(100, int((scan_progress.current_message /
                      scan_progress.estimated_total) * 100))

    return {
        "ok": True,
        "is_scanning": scan_progress.is_scanning,
        "current": scan_progress.current_message,
        "total": scan_progress.estimated_total,
        "percent": percent,
        "started_at": scan_progress.started_at.isoformat() if scan_progress.started_at else None,
        "new_subscriptions": scan_progress.new_subscriptions_found or 0,
        "total_scanned": scan_progress.total_messages_scanned or 0
    }


@app.get("/promotions", response_class=HTMLResponse)
def promotions_page(request: Request, category: str = "promotions", db: Session = Depends(get_db)):
    """Display emails by domain with mass deletion options for specified category."""
    user_sess = request.session.get("user")
    if not user_sess:
        return RedirectResponse("/login")

    user = db.query(User).filter(User.email == user_sess.get("email")).first()
    domains = []
    if user:
        domains = db.query(PromotionsDomain).filter(
            PromotionsDomain.user_id == user.id,
            PromotionsDomain.category == category
        ).order_by(PromotionsDomain.email_count.desc()).all()

    return templates.TemplateResponse("promotions.html", {
        "request": request,
        "user": user_sess,
        "domains": domains,
        "category": category
    })


@app.post("/start_promotions_scan")
def start_promotions_scan(request: Request, background: BackgroundTasks, category: str = "promotions", db: Session = Depends(get_db)):
    """Start scanning email category for domain statistics."""
    logging.info(
        f"start_promotions_scan endpoint called for category: {category}")
    user_sess = request.session.get("user")
    if not user_sess:
        logging.warning("start_promotions_scan: not_authenticated")
        return {"ok": False, "error": "not_authenticated"}
    user = db.query(User).filter(User.email == user_sess.get("email")).first()
    if not user:
        logging.warning("start_promotions_scan: user_not_found")
        return {"ok": False, "error": "user_not_found"}

    # Check if already scanning for this category
    scan_progress = db.query(PromotionsScanProgress).filter(
        PromotionsScanProgress.user_id == user.id,
        PromotionsScanProgress.category == category
    ).first()
    if scan_progress and scan_progress.is_scanning:
        logging.warning(
            f"start_promotions_scan: scan_already_running for user {user.id}, category {category}")
        return {"ok": False, "error": "scan_already_running"}

    # Start scan in background
    from . import promotions_scanner
    logging.info(
        f"Starting background task for user {user.id}, category {category}")
    background.add_task(
        promotions_scanner.scan_promotions_for_domains, user.id, 2000, category)
    logging.info("Background task added successfully")
    return {"ok": True, "message": "scan_started"}


@app.get("/promotions_scan_progress")
def get_promotions_scan_progress(request: Request, category: str = "promotions", db: Session = Depends(get_db)):
    """Get progress of email category scan."""
    user_sess = request.session.get("user")
    if not user_sess:
        return {"ok": False, "error": "not_authenticated"}
    user = db.query(User).filter(User.email == user_sess.get("email")).first()
    if not user:
        return {"ok": False, "error": "user_not_found"}

    scan_progress = db.query(PromotionsScanProgress).filter(
        PromotionsScanProgress.user_id == user.id,
        PromotionsScanProgress.category == category
    ).first()

    if not scan_progress:
        return {
            "ok": True,
            "is_scanning": False,
            "current": 0,
            "total": 0,
            "percent": 0
        }

    percent = 0
    if scan_progress.estimated_total > 0:
        percent = min(100, int((scan_progress.current_message /
                      scan_progress.estimated_total) * 100))

    return {
        "ok": True,
        "is_scanning": scan_progress.is_scanning,
        "current": scan_progress.current_message,
        "total": scan_progress.estimated_total,
        "percent": percent,
        "started_at": scan_progress.started_at.isoformat() if scan_progress.started_at else None
    }


@app.post("/reset_promotions_scan")
def reset_promotions_scan(request: Request, db: Session = Depends(get_db)):
    """Manually reset a stuck Promotions scan."""
    user_sess = request.session.get("user")
    if not user_sess:
        return {"ok": False, "error": "not_authenticated"}
    user = db.query(User).filter(User.email == user_sess.get("email")).first()
    if not user:
        return {"ok": False, "error": "user_not_found"}

    scan_progress = db.query(PromotionsScanProgress).filter(
        PromotionsScanProgress.user_id == user.id
    ).first()

    if scan_progress:
        scan_progress.is_scanning = False
        scan_progress.page_token = None
        db.commit()
        return {"ok": True, "message": "scan_reset"}

    return {"ok": True, "message": "no_scan_to_reset"}


@app.post("/delete_domain_emails")
async def delete_domain_emails(request: Request, background: BackgroundTasks, db: Session = Depends(get_db)):
    """Move all emails from a specific domain in a category to trash."""
    data = await request.json()
    domain = data.get("domain")
    category = data.get("category", "promotions")

    user_sess = request.session.get("user")
    if not user_sess:
        return {"ok": False, "error": "not_authenticated"}
    user = db.query(User).filter(User.email == user_sess.get("email")).first()
    if not user:
        return {"ok": False, "error": "user_not_found"}

    if not domain:
        return {"ok": False, "error": "domain_required"}

    # Verify this domain belongs to the user with the correct category
    domain_record = db.query(PromotionsDomain).filter(
        PromotionsDomain.user_id == user.id,
        PromotionsDomain.domain == domain,
        PromotionsDomain.category == category
    ).first()

    if not domain_record:
        return {"ok": False, "error": "domain_not_found"}

    # Map category to Gmail label
    category_labels = {
        "promotions": "CATEGORY_PROMOTIONS",
        "social": "CATEGORY_SOCIAL",
        "updates": "CATEGORY_UPDATES",
        "inbox": "INBOX"
    }
    label_id = category_labels.get(category, "CATEGORY_PROMOTIONS")

    # Test deletion permissions by attempting to delete a single message first
    try:
        from .auth import decrypt_tokens
        tokens = decrypt_tokens(
            user.encrypted_tokens) if user.encrypted_tokens else {}
        service = gmail_client.build_gmail_service(tokens)

        # Get one message to test delete permissions
        query = f"from:@{domain}"
        test_result = gmail_client.list_messages(
            service,
            q=query,
            label_ids=[label_id],
            max_results=1
        )

        messages = test_result.get("messages", [])
        if messages:
            # Try to trash this one message as a permission test
            test_delete = gmail_client.batch_delete_messages(
                service, [messages[0]["id"]])

            if not test_delete.get("success"):
                error_type = test_delete.get("error", "unknown")
                if error_type == "insufficient_permissions":
                    return {"ok": False, "error": "insufficient_permissions"}
                return {"ok": False, "error": f"trash_test_failed: {error_type}"}

        # Permission test passed, schedule the full trash operation in background
        background.add_task(delete_promotions_by_domain_task,
                            user.id, domain, category)
        return {"ok": True, "message": "deletion_started", "domain": domain}

    except Exception as e:
        logger.error(f"Permission test failed for {domain}: {e}")
        if "insufficient" in str(e).lower() and "permission" in str(e).lower():
            return {"ok": False, "error": "insufficient_permissions"}
        return {"ok": False, "error": f"permission_test_failed: {str(e)}"}


def delete_promotions_by_domain_task(user_id: int, domain: str, category: str = "promotions"):
    """Background task to move all emails from a specific domain/category to trash."""
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            logger.error(f"User {user_id} not found")
            return

        # Build Gmail service
        from .auth import decrypt_tokens
        tokens = decrypt_tokens(
            user.encrypted_tokens) if user.encrypted_tokens else {}
        service = gmail_client.build_gmail_service(tokens)

        # Map category to Gmail label
        category_labels = {
            "promotions": "CATEGORY_PROMOTIONS",
            "social": "CATEGORY_SOCIAL",
            "updates": "CATEGORY_UPDATES",
            "inbox": "INBOX"
        }
        label_id = category_labels.get(category, "CATEGORY_PROMOTIONS")

        # Search for all messages from this domain in the specified category
        query = f"from:@{domain}"
        logger.info(f"Searching for emails from {domain} in {category}")

        message_ids = []
        page_token = None

        while True:
            result = gmail_client.list_messages(
                service,
                q=query,
                label_ids=[label_id],
                page_token=page_token,
                max_results=500
            )

            messages = result.get("messages", [])
            if not messages:
                break

            message_ids.extend([msg["id"] for msg in messages])

            page_token = result.get("nextPageToken")
            if not page_token:
                break

        if message_ids:
            logger.info(
                f"Found {len(message_ids)} messages from {domain}, moving to trash...")
            result = gmail_client.batch_delete_messages(service, message_ids)
            logger.info(f"Trash result: {result}")

            # Check for permission errors
            if not result.get("success") and result.get("error") == "insufficient_permissions":
                logger.error(
                    f"Permission error trashing from {domain}: {result.get('message')}")
                # Don���t delete the domain record if permissions failed
                return

            # Update domain record only if trashing was successful
            if result.get("success"):
                # Update user's emails_deleted counter
                user.emails_deleted = (
                    user.emails_deleted or 0) + len(message_ids)

                domain_record = db.query(PromotionsDomain).filter(
                    PromotionsDomain.user_id == user_id,
                    PromotionsDomain.domain == domain,
                    PromotionsDomain.category == category
                ).first()
                if domain_record:
                    db.delete(domain_record)
                db.commit()
                logger.info(
                    f"Updated user emails_deleted count: {user.emails_deleted}")
        else:
            logger.info(f"No messages found from {domain}")

    except Exception as e:
        logger.error(
            f"Error moving emails from {domain} to trash: {e}", exc_info=True)
    finally:
        db.close()


@app.post("/delete_all_promotions")
async def delete_all_promotions(request: Request, background: BackgroundTasks, db: Session = Depends(get_db)):
    """Move all emails from all scanned Promotions domains to trash."""
    user_sess = request.session.get("user")
    if not user_sess:
        return {"ok": False, "error": "not_authenticated"}
    user = db.query(User).filter(User.email == user_sess.get("email")).first()
    if not user:
        return {"ok": False, "error": "user_not_found"}

    # Get all domains for this user
    domains = db.query(PromotionsDomain).filter(
        PromotionsDomain.user_id == user.id
    ).all()

    if not domains:
        return {"ok": False, "error": "no_domains_found"}

    # Schedule deletion for all domains
    for domain_record in domains:
        background.add_task(delete_promotions_by_domain_task,
                            user.id, domain_record.domain)

    return {"ok": True, "message": "deletion_started", "count": len(domains)}


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=int(
        os.environ.get("PORT", 8000)), reload=True)
