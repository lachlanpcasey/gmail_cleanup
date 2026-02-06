import os
from fastapi import FastAPI, Request, Depends, Form, BackgroundTasks
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv
from .db import init_db, SessionLocal
from . import auth, gmail_client, unsubscribe, scanner
from .models import User
from sqlalchemy.orm import Session
import uvicorn

load_dotenv()

app = FastAPI()
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "..", "templates"))

app.add_middleware(SessionMiddleware, secret_key=os.environ.get("SESSION_SECRET") or "dev-secret", https_only=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
def startup():
    init_db()


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    user = request.session.get("user")
    return templates.TemplateResponse("index.html", {"request": request, "user": user})


@app.get("/login")
def login(request: Request):
    flow = auth.make_flow(request)
    auth_url, state = flow.authorization_url(access_type="offline", include_granted_scopes=True, prompt="consent")
    request.session["oauth_state"] = state
    return RedirectResponse(auth_url)


@app.get("/oauth2callback")
def oauth2callback(request: Request, db: Session = Depends(get_db)):
    state = request.session.get("oauth_state")
    flow = auth.make_flow(request)
    flow.fetch_token(authorization_response=str(request.url))
    creds = flow.credentials
    # minimal userinfo: email from id_token if present
    email = None
    if creds.id_token:
        import jwt
        try:
            info = jwt.decode(creds.id_token, options={"verify_signature": False})
            email = info.get("email")
        except Exception:
            email = None
    if not email:
        email = "unknown"

    encrypted = auth.encrypt_tokens({
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "id_token": creds.id_token,
    })

    # upsert user
    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(email=email, encrypted_tokens=encrypted)
        db.add(user)
    else:
        user.encrypted_tokens = encrypted
    db.commit()
    request.session["user"] = {"email": email}
    return RedirectResponse("/")


@app.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    request.session.clear()
    return RedirectResponse("/")


@app.get("/subscriptions", response_class=HTMLResponse)
def subscriptions(request: Request, db: Session = Depends(get_db)):
    user_sess = request.session.get("user")
    if not user_sess:
        return RedirectResponse("/login")
    # load detected subscription groups from DB
    user = db.query(User).filter(User.email == user_sess.get("email")).first()
    groups = []
    if user:
        groups = db.query(SubscriptionGroup).filter(SubscriptionGroup.user_id == user.id).order_by(SubscriptionGroup.confidence_score.desc()).all()
    return templates.TemplateResponse("subscriptions.html", {"request": request, "groups": groups})


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
    valid_groups = db.query(SubscriptionGroup).filter(SubscriptionGroup.user_id == user.id, SubscriptionGroup.id.in_(group_ids)).all()
    if not valid_groups:
        return {"ok": False, "error": "no_valid_groups"}

    # Decrypt tokens
    from .auth import decrypt_tokens
    token_dict = decrypt_tokens(user.encrypted_tokens) if user.encrypted_tokens else {}
    service = None
    try:
        service = gmail_client.build_gmail_service(token_dict)
    except Exception:
        service = None

    results = []
    for g in valid_groups:
        # aggregate methods from recent messages
        msgs = db.query(SubscriptionMessage).filter(SubscriptionMessage.group_id == g.id).limit(10).all()
        agg_methods = {"mailto": [], "https": []}
        for m in msgs:
            um = m.unsubscribe_methods or {}
            for k in ("mailto", "https"):
                agg_methods[k].extend(um.get(k, []))

        # schedule execution in background: pass user id so tokens can be refreshed/persisted inside task
        background.add_task(unsubscribe.execute_unsubscribe_task, user.id, g.sender_domain, agg_methods)
        results.append({"group_id": g.id, "domain": g.sender_domain, "status": "queued"})

    return {"ok": True, "results": results}


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


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), reload=True)
