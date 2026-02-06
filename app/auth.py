import os
import json
from cryptography.fernet import Fernet, InvalidToken
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest
import logging
from fastapi import Request

_FERNET_KEY = os.environ.get("FERNET_KEY")
if not _FERNET_KEY:
    # Developer convenience: generate a key if none provided (not for production)
    _FERNET_KEY = Fernet.generate_key().decode()

fernet = Fernet(_FERNET_KEY.encode())

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
]

def encrypt_tokens(token_dict: dict) -> str:
    raw = json.dumps(token_dict).encode()
    return fernet.encrypt(raw).decode()

def decrypt_tokens(ciphertext: str) -> dict:
    try:
        raw = fernet.decrypt(ciphertext.encode())
        return json.loads(raw.decode())
    except InvalidToken:
        return {}

def make_flow(request: Request):
    client_config = {
        "web": {
            "client_id": os.environ.get("GOOGLE_CLIENT_ID"),
            "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }
    flow = Flow.from_client_config(client_config=client_config, scopes=SCOPES, redirect_uri=os.environ.get("OAUTH_REDIRECT_URI"))
    return flow

def credentials_from_tokens(token_dict: dict) -> Credentials:
    return Credentials(
        token=token_dict.get("token"),
        refresh_token=token_dict.get("refresh_token"),
        id_token=token_dict.get("id_token"),
        token_uri="https://oauth2.googleapis.com/token",
        client_id=os.environ.get("GOOGLE_CLIENT_ID"),
        client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    )


def refresh_and_persist_tokens(user, db_session):
    """Ensure credentials are valid; if refresh occurs, persist updated tokens on the user row.

    Returns a token dict (token, refresh_token, id_token) or raises on irrecoverable errors.
    """
    logger = logging.getLogger(__name__)
    if not user or not user.encrypted_tokens:
        raise RuntimeError("no_tokens")
    tokens = decrypt_tokens(user.encrypted_tokens)
    creds = credentials_from_tokens(tokens)
    # If token is None but refresh_token exists, or if expired, attempt refresh
    try:
        if not creds.valid:
            request = GoogleAuthRequest()
            creds.refresh(request)
            # persist updated tokens
            new_tokens = {"token": creds.token, "refresh_token": creds.refresh_token, "id_token": creds.id_token}
            user.encrypted_tokens = encrypt_tokens(new_tokens)
            db_session.add(user)
            db_session.commit()
            return new_tokens
        return tokens
    except Exception as e:
        logger.exception("Failed to refresh tokens for user %s: %s", getattr(user, 'email', None), e)
        raise
