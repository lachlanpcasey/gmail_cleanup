import logging
from .gmail_client import build_gmail_service, parse_list_unsubscribe
from .models import User, SubscriptionGroup, SubscriptionMessage
from .db import SessionLocal
from sqlalchemy.orm import Session
from collections import defaultdict
import re

logger = logging.getLogger(__name__)

UNSUB_KEYWORDS = ["unsubscribe", "manage preferences", "opt out", "manage subscription", "preferences"]


def header_dict_from_headers(headers):
    return {h.get("name", "").lower(): h.get("value", "") for h in headers or []}


def extract_from_header_value(val: str):
    # simple parse for From header: Name <email@domain>
    if not val:
        return None, None
    m = re.match(r"(?P<name>.*)\s+<(?P<email>[^>]+)>", val)
    if m:
        return m.group("name").strip('" '), m.group("email")
    return None, val.strip()


def group_key_from_email(email: str):
    if not email:
        return ""
    return email.split("@")[-1].lower()


def compute_confidence(has_list_unsub: bool, heuristics_count: int):
    base = 50 if has_list_unsub else 10
    return min(100, base + heuristics_count * 15)


def scan_user_mailbox(user_id: int):
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            logger.error("User %s not found", user_id)
            return

        tokens = {}
        if user.encrypted_tokens:
            from .auth import decrypt_tokens

            tokens = decrypt_tokens(user.encrypted_tokens)

        service = build_gmail_service(tokens)

        page_token = None
        processed_threads = set()
        groups = defaultdict(lambda: {"count": 0, "subjects": set(), "sender_name": None, "has_list_unsub": False, "methods": []})

        # Paginate messages to limit work per run
        while True:
            resp = service.users().messages().list(userId="me", q="in:anywhere", pageToken=page_token, maxResults=200).execute()
            msgs = resp.get("messages", [])
            for m in msgs:
                try:
                    msg = service.users().messages().get(userId="me", id=m["id"], format="metadata", metadataHeaders=["From", "Subject", "List-Unsubscribe", "Precedence", "Auto-Submitted"]).execute()
                    headers = msg.get("payload", {}).get("headers", [])
                    hdrs = header_dict_from_headers(headers)
                    from_name, from_email = extract_from_header_value(hdrs.get("from"))
                    domain = group_key_from_email(from_email)
                    thread_id = msg.get("threadId")
                    if thread_id in processed_threads:
                        continue
                    processed_threads.add(thread_id)

                    methods = parse_list_unsubscribe(headers)
                    has_list_unsub = bool(methods.get("mailto") or methods.get("https"))

                    heuristics_count = 0
                    subj = hdrs.get("subject", "")
                    lower = subj.lower()
                    for k in UNSUB_KEYWORDS:
                        if k in lower:
                            heuristics_count += 1
                    if hdrs.get("precedence") and hdrs.get("precedence").lower() == "bulk":
                        heuristics_count += 1
                    if hdrs.get("auto-submitted") and hdrs.get("auto-submitted").lower() != "no":
                        heuristics_count += 1

                    grp = groups[domain]
                    grp["count"] += 1
                    if subj:
                        grp["subjects"].add(subj)
                    if from_name:
                        grp["sender_name"] = from_name
                    if has_list_unsub:
                        grp["has_list_unsub"] = True
                        grp["methods"].append(methods)

                    # persist message record for traceability if detected
                    if has_list_unsub or heuristics_count > 0:
                        # create or find group row
                        sgroup = db.query(SubscriptionGroup).filter(SubscriptionGroup.user_id == user.id, SubscriptionGroup.sender_domain == domain).first()
                        if not sgroup:
                            sgroup = SubscriptionGroup(user_id=user.id, sender_domain=domain, sender_name=from_name, frequency_score=0, confidence_score=0, example_subjects=list(grp["subjects"]))
                            db.add(sgroup)
                            db.flush()
                        else:
                            sgroup.example_subjects = list((set(sgroup.example_subjects or []) | grp["subjects"]))

                        sm = SubscriptionMessage(group_id=sgroup.id, gmail_thread_id=thread_id, unsubscribe_methods=methods, detected_headers=hdrs)
                        db.add(sm)
                        db.commit()

                except Exception:
                    logger.exception("Error processing message %s", m)
                    continue

            page_token = resp.get("nextPageToken")
            if not page_token:
                break

        # finalize groups into DB: update frequency/confidence
        for domain, d in groups.items():
            sgroup = db.query(SubscriptionGroup).filter(SubscriptionGroup.user_id == user.id, SubscriptionGroup.sender_domain == domain).first()
            if not sgroup:
                continue
            sgroup.frequency_score = d["count"]
            sgroup.confidence_score = compute_confidence(d["has_list_unsub"], len(d["subjects"]))
            sgroup.example_subjects = list(d["subjects"])[:5]
            db.add(sgroup)
        db.commit()

    finally:
        db.close()
