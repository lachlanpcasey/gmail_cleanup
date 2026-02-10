import logging
import time
from .gmail_client import build_gmail_service, list_messages, execute_request
from .models import User, PromotionsDomain, PromotionsScanProgress
from .db import SessionLocal
from sqlalchemy.orm import Session
from collections import defaultdict
import re
from datetime import datetime
from googleapiclient.http import BatchHttpRequest
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)


def extract_domain_from_email(email: str):
    """Extract domain from an email address."""
    if not email or "@" not in email:
        return None
    return email.split("@")[-1].lower()


def extract_email_from_header(val: str):
    """Extract email from From header value."""
    if not val:
        return None, None
    # Parse From header: Name <email@domain>
    m = re.match(r"(?P<name>.*)\s+<(?P<email>[^>]+)>", val)
    if m:
        email = m.group("email")
        if "@" in email:
            return m.group("name").strip('" '), email
    # If no angle brackets, check if the value itself is an email
    if "@" in val:
        return None, val.strip()
    return None, None


def scan_promotions_for_domains(user_id: int, max_messages: int = 2000, category: str = "promotions"):
    """Scan specified Gmail category and aggregate email counts by domain.

    Args:
        user_id: User ID to scan for
        max_messages: Maximum number of messages to scan
        category: Category to scan (promotions, social, updates, inbox)
    """
    # Map category to Gmail labels
    category_labels = {
        "promotions": ["CATEGORY_PROMOTIONS"],
        "social": ["CATEGORY_SOCIAL"],
        "updates": ["CATEGORY_UPDATES"],
        "inbox": ["INBOX"]
    }

    label_ids = category_labels.get(category, ["CATEGORY_PROMOTIONS"])

    logger.info(
        f"scan_promotions_for_domains called for user_id={user_id}, category={category}, max_messages={max_messages}")
    db: Session = SessionLocal()
    scan_progress = None
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            logger.error(f"User {user_id} not found")
            return

        # Initialize or update scan progress
        scan_progress = db.query(PromotionsScanProgress).filter(
            PromotionsScanProgress.user_id == user_id,
            PromotionsScanProgress.category == category
        ).first()
        if not scan_progress:
            scan_progress = PromotionsScanProgress(
                user_id=user_id,
                category=category,
                current_message=0,
                estimated_total=max_messages,
                is_scanning=True,
                started_at=datetime.utcnow()
            )
            db.add(scan_progress)
        else:
            scan_progress.current_message = 0
            scan_progress.estimated_total = max_messages
            scan_progress.is_scanning = True
            scan_progress.started_at = datetime.utcnow()
            scan_progress.page_token = None  # Reset to start from beginning
        db.commit()

        # Build Gmail service
        tokens = {}
        if user.encrypted_tokens:
            from .auth import decrypt_tokens
            tokens = decrypt_tokens(user.encrypted_tokens)

        service = build_gmail_service(tokens)

        # Scan specified category
        logger.info(f"Starting {category} scan for user {user_id}")

        domain_data = defaultdict(lambda: {
            "count": 0,
            "sender_names": set()
        })

        page_token = scan_progress.page_token
        messages_scanned = 0

        while messages_scanned < max_messages:
            # Calculate how many messages to fetch (limit to 25 per batch to avoid rate limits)
            remaining = max_messages - messages_scanned
            batch_size = min(25, remaining)

            logger.info(
                f"Fetching up to {batch_size} messages (scanned {messages_scanned}/{max_messages})")

            try:
                result = list_messages(
                    service,
                    label_ids=label_ids,
                    page_token=page_token,
                    max_results=batch_size
                )
                # Small delay after list request to avoid rate limits
                time.sleep(0.5)
            except HttpError as e:
                if 'rateLimitExceeded' in str(e) or 'Quota exceeded' in str(e):
                    logger.warning(
                        f"Rate limit hit, pausing for 60 seconds...")
                    time.sleep(60)
                    continue
                else:
                    raise

            messages = result.get("messages", [])
            if not messages:
                logger.info("No more messages in Promotions")
                break

            logger.info(f"Processing {len(messages)} messages in batch")

            # Process messages in batch for better performance
            batch_results = []

            def create_callback(message_id):
                def callback(request_id, response, exception):
                    if exception:
                        logger.error(
                            f"Error in batch request for {message_id}: {exception}")
                        return
                    batch_results.append(response)
                return callback

            # Create batch request for this set of messages
            batch = service.new_batch_http_request()
            for msg in messages:
                batch.add(
                    service.users().messages().get(
                        userId="me",
                        id=msg["id"],
                        format="metadata",
                        metadataHeaders=["From"]
                    ),
                    callback=create_callback(msg["id"])
                )

            # Execute batch request
            try:
                batch.execute()
                # Add delay after batch execution to prevent rate limiting
                time.sleep(2.0)
            except HttpError as e:
                if 'rateLimitExceeded' in str(e) or 'Quota exceeded' in str(e):
                    logger.warning(
                        f"Rate limit hit during batch, pausing for 60 seconds...")
                    time.sleep(60)
                    # Retry this batch
                    continue
                else:
                    logger.error(f"Batch execution error: {e}")
                    continue
            except Exception as e:
                logger.error(f"Batch execution error: {e}")
                continue

            # Process batch results
            for msg_detail in batch_results:
                try:
                    headers = msg_detail.get("payload", {}).get("headers", [])

                    # Extract From header only (we don't care about subjects)
                    from_header = None
                    for h in headers:
                        if h.get("name", "").lower() == "from":
                            from_header = h.get("value", "")
                            break

                    if from_header:
                        sender_name, email = extract_email_from_header(
                            from_header)
                        if email:
                            domain = extract_domain_from_email(email)
                            if domain:
                                domain_data[domain]["count"] += 1
                                if sender_name:
                                    domain_data[domain]["sender_names"].add(
                                        sender_name)

                    messages_scanned += 1

                except Exception as e:
                    logger.error(f"Error processing batch result: {e}")
                    continue

            # Update progress after each batch
            scan_progress.current_message = messages_scanned
            db.commit()
            logger.info(
                f"Progress: {messages_scanned}/{max_messages} messages scanned")

            # Check if we've reached the limit
            if messages_scanned >= max_messages:
                logger.info(f"Reached scan limit of {max_messages} messages")
                break

            # Check for next page
            page_token = result.get("nextPageToken")
            if not page_token:
                logger.info("No more pages available")
            scan_progress.page_token = page_token
            db.commit()

        # Save domain statistics to database
        logger.info(
            f"Found {len(domain_data)} domains in {category}, saving to database")

        for domain, data in domain_data.items():
            # Get or create domain record
            domain_record = db.query(PromotionsDomain).filter(
                PromotionsDomain.user_id == user_id,
                PromotionsDomain.domain == domain,
                PromotionsDomain.category == category
            ).first()

            if not domain_record:
                domain_record = PromotionsDomain(
                    user_id=user_id,
                    domain=domain,
                    category=category,
                    email_count=data["count"],
                    sender_name=", ".join(list(data["sender_names"])[
                                          :3]) if data["sender_names"] else None,
                    example_subjects=[],
                    last_scanned=datetime.utcnow()
                )
                db.add(domain_record)
            else:
                # Update existing record
                domain_record.email_count = data["count"]
                if data["sender_names"]:
                    domain_record.sender_name = ", ".join(
                        list(data["sender_names"])[:3])
                domain_record.example_subjects = []
                domain_record.last_scanned = datetime.utcnow()

        # Mark scan as complete
        scan_progress.is_scanning = False
        scan_progress.current_message = messages_scanned
        scan_progress.page_token = None
        db.commit()

        logger.info(
            f"{category.capitalize()} scan complete. Scanned {messages_scanned} messages, found {len(domain_data)} domains")

    except Exception as e:
        logger.error(f"Error during Promotions scan: {e}", exc_info=True)
        if scan_progress:
            scan_progress.is_scanning = False
            db.commit()
    finally:
        db.close()


def get_promotion_domain_stats(user_id: int):
    """Get domain statistics for a user's Promotions."""
    db: Session = SessionLocal()
    try:
        domains = db.query(PromotionsDomain).filter(
            PromotionsDomain.user_id == user_id
        ).order_by(PromotionsDomain.email_count.desc()).all()
        return domains
    finally:
        db.close()
