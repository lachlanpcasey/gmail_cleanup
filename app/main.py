import os
from fastapi import FastAPI, Request, Depends, Form, BackgroundTasks
from fastapi.responses import RedirectResponse, HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from dotenv import load_dotenv
from .db import init_db, SessionLocal
from . import auth, gmail_client, unsubscribe, scanner
from .models import User, SubscriptionGroup, SubscriptionMessage, ScanProgress
from sqlalchemy.orm import Session
import uvicorn
import logging

# Configure logging to print all logs to the console
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(name)s: %(message)s')

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
        stale_scans = db.query(ScanProgress).filter(
            ScanProgress.is_scanning == True).all()
        if stale_scans:
            for scan in stale_scans:
                scan.is_scanning = False
            db.commit()
            logging.info(f"Reset {len(stale_scans)} stale scanning state(s)")
    finally:
        db.close()


@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    user = request.session.get("user")
    unsubscribed_count = 0
    failed_count = 0
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
    return templates.TemplateResponse("index.html", {
        "request": request,
        "user": user,
        "unsubscribed_count": unsubscribed_count,
        "failed_count": failed_count
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


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=int(
        os.environ.get("PORT", 8000)), reload=True)
