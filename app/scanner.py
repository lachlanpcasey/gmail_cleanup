import logging
from .gmail_client import build_gmail_service, parse_list_unsubscribe, execute_request
from .models import User, SubscriptionGroup, SubscriptionMessage, ScanProgress
from .db import SessionLocal
from sqlalchemy.orm import Session
from collections import defaultdict
import re
from datetime import datetime

logger = logging.getLogger(__name__)

UNSUB_KEYWORDS = ["unsubscribe", "manage preferences",
                  "opt out", "manage subscription", "preferences"]

# Common personal email domains to skip (not subscriptions)
PERSONAL_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
                    "icloud.com", "aol.com", "live.com", "msn.com", "me.com"}

# System senders to skip
SYSTEM_SENDERS = {"mail delivery subsystem", "mailer-daemon", "postmaster"}


def header_dict_from_headers(headers):
    return {h.get("name", "").lower(): h.get("value", "") for h in headers or []}


def extract_from_header_value(val: str):
    # simple parse for From header: Name <email@domain>
    if not val:
        return None, None
    m = re.match(r"(?P<name>.*)\s+<(?P<email>[^>]+)>", val)
    if m:
        email = m.group("email")
        # Validate email has @ sign
        if "@" in email:
            return m.group("name").strip('" '), email
    # If no angle brackets, check if the value itself is an email
    if "@" in val:
        return None, val.strip()
    # Not a valid email format
    return None, None


def group_key_from_email(email: str):
    if not email or "@" not in email:
        return None
    return email.split("@")[-1].lower()


def compute_confidence(has_list_unsub: bool, heuristics_count: int):
    base = 50 if has_list_unsub else 10
    return min(100, base + heuristics_count * 15)


def scan_user_mailbox(user_id: int, max_messages: int = 500):
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            logger.error("User %s not found", user_id)
            return

        # Build query to scan emails
        # Use empty query or broad search - Gmail will search all mail by default
        query = ""
        if user.last_scan_date:
            # Format date for Gmail query: YYYY/MM/DD
            scan_date_str = user.last_scan_date.strftime("%Y/%m/%d")
            query = f"after:{scan_date_str}"
            logger.info(f"Scanning emails after {scan_date_str}")
        else:
            logger.info("First scan - scanning all emails")

        # Initialize or update scan progress
        scan_progress = db.query(ScanProgress).filter(
            ScanProgress.user_id == user_id).first()
        if not scan_progress:
            scan_progress = ScanProgress(user_id=user_id, current_message=0,
                                         estimated_total=max_messages, is_scanning=True, started_at=datetime.utcnow(),
                                         new_subscriptions_found=0, total_messages_scanned=0)
            db.add(scan_progress)
        else:
            scan_progress.current_message = 0
            scan_progress.estimated_total = max_messages
            scan_progress.is_scanning = True
            scan_progress.started_at = datetime.utcnow()
            scan_progress.new_subscriptions_found = 0
            scan_progress.total_messages_scanned = 0
        db.commit()

        tokens = {}
        if user.encrypted_tokens:
            from .auth import decrypt_tokens

            tokens = decrypt_tokens(user.encrypted_tokens)

        service = build_gmail_service(tokens)

        # Load all domains that are already unsubscribed or failed to skip them during scan
        existing_unsubscribed = db.query(SubscriptionGroup).filter(
            SubscriptionGroup.user_id == user.id,
            (SubscriptionGroup.unsubscribed == 1) | (
                SubscriptionGroup.unsubscribe_failed == 1)
        ).all()
        skip_domains = {g.sender_domain for g in existing_unsubscribed}
        logger.info(
            f"Skipping {len(skip_domains)} already processed domains during scan")

        page_token = None
        processed_threads = set()
        groups = defaultdict(lambda: {"count": 0, "subjects": set(
        ), "sender_name": None, "has_list_unsub": False, "methods": []})

        total_processed = 0
        new_subscriptions_found = 0
        logger.info(
            f"Starting mailbox scan for user {user_id}, max messages: {max_messages}")

        # Paginate messages to limit work per run
        batch_count = 0
        while total_processed < max_messages:
            batch_count += 1
            logger.info(
                f"=== BATCH {batch_count} === total_processed={total_processed}, max={max_messages}, has_page_token={page_token is not None}")

            resp = execute_request(lambda: service.users().messages().list(
                userId="me", q=query, pageToken=page_token, maxResults=200).execute())
            msgs = resp.get("messages", [])
            next_page_token = resp.get("nextPageToken")
            result_size_estimate = resp.get("resultSizeEstimate", "unknown")

            logger.info(
                f"API Response: messages_returned={len(msgs)}, has_next_page={next_page_token is not None}, result_size_estimate={result_size_estimate}")

            if not msgs:
                logger.info(
                    f"No more messages to process. Total processed: {total_processed}")
                break

            for m in msgs:
                try:
                    total_processed += 1
                    if total_processed > max_messages:
                        logger.info(
                            f"Reached max messages limit: {max_messages}")
                        break

                    if total_processed % 100 == 0:
                        logger.info(f"Processed {total_processed} messages...")
                        # Update progress every 100 messages
                        scan_progress.current_message = total_processed
                        db.commit()

                    msg = execute_request(lambda: service.users().messages().get(userId="me", id=m["id"], format="metadata", metadataHeaders=[
                                          "From", "Subject", "List-Unsubscribe", "Precedence", "Auto-Submitted"]).execute())
                    headers = msg.get("payload", {}).get("headers", [])
                    hdrs = header_dict_from_headers(headers)
                    from_name, from_email = extract_from_header_value(
                        hdrs.get("from"))
                    domain = group_key_from_email(from_email)

                    # Skip if we couldn't extract a valid domain
                    if not domain:
                        continue

                    # Skip personal email domains and system senders
                    if domain in PERSONAL_DOMAINS:
                        continue
                    if from_name and from_name.lower() in SYSTEM_SENDERS:
                        continue

                    # Skip domains that have already been unsubscribed or failed
                    if domain in skip_domains:
                        continue

                    thread_id = msg.get("threadId")
                    if thread_id in processed_threads:
                        continue
                    processed_threads.add(thread_id)

                    methods = parse_list_unsubscribe(headers)
                    has_list_unsub = bool(methods.get(
                        "mailto") or methods.get("https"))

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
                        sgroup = db.query(SubscriptionGroup).filter(
                            SubscriptionGroup.user_id == user.id, SubscriptionGroup.sender_domain == domain).first()

                        # Skip if already unsubscribed from this domain
                        if sgroup and (sgroup.unsubscribed == 1 or sgroup.unsubscribe_failed == 1):
                            continue

                        is_new_group = not sgroup
                        if not sgroup:
                            sgroup = SubscriptionGroup(user_id=user.id, sender_domain=domain, sender_name=from_name,
                                                       frequency_score=0, confidence_score=0, example_subjects=list(grp["subjects"]), unsubscribed=0)
                            db.add(sgroup)
                            db.flush()
                            new_subscriptions_found += 1
                        else:
                            sgroup.example_subjects = list(
                                (set(sgroup.example_subjects or []) | grp["subjects"]))

                        sm = SubscriptionMessage(
                            group_id=sgroup.id, gmail_thread_id=thread_id, unsubscribe_methods=methods, detected_headers=hdrs)
                        db.add(sm)
                        db.commit()

                except Exception:
                    logger.exception("Error processing message %s", m)
                    continue

            page_token = next_page_token
            logger.info(
                f"End of batch {batch_count}: next_page_token={'EXISTS' if page_token else 'NONE'}, total_processed={total_processed}")

            if not page_token:
                logger.info("No more pages available - ending scan")
                break

            if total_processed >= max_messages:
                logger.info(
                    f"Reached max_messages limit ({max_messages}) - ending scan")
                break

        logger.info(
            f"Scan complete. Processed {total_processed} messages, found {len(groups)} potential subscription senders, {new_subscriptions_found} new subscriptions")

        # finalize groups into DB: update frequency/confidence
        for domain, d in groups.items():
            sgroup = db.query(SubscriptionGroup).filter(
                SubscriptionGroup.user_id == user.id, SubscriptionGroup.sender_domain == domain).first()

            # Skip updating groups that are already unsubscribed or failed
            if sgroup and (sgroup.unsubscribed == 1 or sgroup.unsubscribe_failed == 1):
                continue

            if not sgroup:
                # Create the group if it doesn't exist yet
                sgroup = SubscriptionGroup(
                    user_id=user.id,
                    sender_domain=domain,
                    sender_name=d["sender_name"],
                    frequency_score=0,
                    confidence_score=0,
                    example_subjects=[],
                    unsubscribed=0
                )
                db.add(sgroup)
                db.flush()
            sgroup.frequency_score = d["count"]
            sgroup.confidence_score = compute_confidence(
                d["has_list_unsub"], len(d["subjects"]))
            sgroup.example_subjects = list(d["subjects"])[:5]
            db.add(sgroup)
        db.commit()

        # Update last scan date to current time
        user.last_scan_date = datetime.utcnow()
        db.commit()

        # Mark scan as complete and save results
        scan_progress.is_scanning = False
        scan_progress.current_message = total_processed
        scan_progress.total_messages_scanned = total_processed
        scan_progress.new_subscriptions_found = new_subscriptions_found
        db.commit()

        return {"total_processed": total_processed, "new_subscriptions": new_subscriptions_found}

    except Exception as e:
        logger.exception("Error during scan")
        # Mark scan as failed/complete
        scan_progress = db.query(ScanProgress).filter(
            ScanProgress.user_id == user_id).first()
        if scan_progress:
            scan_progress.is_scanning = False
            db.commit()
        raise
    finally:
        db.close()
