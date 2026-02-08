"""Test Gmail query to see how many messages are returned"""
from app.db import SessionLocal
from app.models import User
from app.gmail_client import build_gmail_service, execute_request
from app.auth import decrypt_tokens, refresh_and_persist_tokens
import sys

db = SessionLocal()
try:
    user = db.query(User).first()
    if not user:
        print("❌ No user found in database")
        print("\nYou need to authenticate first:")
        print("1. Start server: python -m uvicorn app.main:app --log-level debug")
        print("2. Visit http://localhost:8000 and log in with Gmail")
        print("3. Run this test again")
        sys.exit(1)
    
    if not user.encrypted_tokens:
        print("❌ No tokens found - please login through the web app first")
        print("\nYou need to authenticate:")
        print("1. Start server: python -m uvicorn app.main:app --log-level debug")
        print("2. Visit http://localhost:8000 and log in with Gmail")
        print("3. Run this test again")
        sys.exit(1)
    
    print(f"✓ Testing with user: {user.email}")
    print("="*70)
    
    try:
        tokens = decrypt_tokens(user.encrypted_tokens)
        service = build_gmail_service(tokens)
    except Exception as e:
        print(f"\n❌ ERROR building Gmail service: {e}")
        print("\nTrying to refresh tokens...")
        try:
            refresh_and_persist_tokens(user, db)
            tokens = decrypt_tokens(user.encrypted_tokens)
            service = build_gmail_service(tokens)
            print("✓ Tokens refreshed successfully!")
        except Exception as refresh_error:
            print(f"❌ Token refresh failed: {refresh_error}")
            print("\nYou need to re-authenticate:")
            print("1. Start server: python -m uvicorn app.main:app --log-level debug")
            print("2. Visit http://localhost:8000 and log in again")
            print("3. Run this test again")
            sys.exit(1)
    
    # Test with empty query and pagination
    print("\n🔍 Testing Gmail API with empty query (should return ALL mail):\n")
    
    query = ""
    page_token = None
    total_count = 0
    page_num = 0
    max_pages = 5  # Only test first 5 pages
    
    while page_num < max_pages:
        page_num += 1
        print(f"📄 Page {page_num}:", end=" ")
        
        try:
            resp = execute_request(lambda: service.users().messages().list(
                userId="me", q=query, pageToken=page_token, maxResults=200).execute())
            
            msgs = resp.get("messages", [])
            result_size = resp.get("resultSizeEstimate", "unknown")
            next_token = resp.get("nextPageToken")
            
            print(f"{len(msgs)} messages, resultSizeEstimate={result_size}, hasNextPage={next_token is not None}")
            
            total_count += len(msgs)
            
            if not msgs:
                print("   ⚠️  No messages returned!")
                break
            
            if not next_token:
                print("   ℹ️  No more pages available (this is normal if you have fewer emails)")
                break
            
            page_token = next_token
            
        except Exception as e:
            print(f"\n   ❌ ERROR: {e}")
            import traceback
            traceback.print_exc()
            break
    
    print("\n" + "="*70)
    print(f"\n📊 DIAGNOSIS:")
    print(f"   Total messages retrieved: {total_count}")
    print(f"   Pages fetched: {page_num}")
    
    if total_count <= 20:
        print(f"\n⚠️  WARNING: Only {total_count} messages found!")
        print("   This means ONE of the following:")
        print("   1. Your Gmail account genuinely only has ~20 emails")
        print("   2. OAuth scopes might be limited (unlikely - we request gmail.readonly)")
        print("   3. Gmail API is restricted for this account")
        print(f"\n   📧 Check your Gmail account at https://mail.google.com")
        print("      Log in and see how many emails you actually have.")
        print(f"\n   If you have many more emails than {total_count}, the issue is:")
        print("   - The Gmail API isn't returning them (possible account restriction)")
        print("   - Or most of your emails are in trash/spam")
    elif total_count < 100:
        print(f"\n✅ Found {total_count} messages")
        print("   This is a small mailbox. Scanner should work, but won't find many")
        print("   subscriptions unless most of these are marketing emails.")
    else:
        print(f"\n✅ Found {total_count}+ messages - Gmail API is working correctly!")
        print("   The scanner will process up to 500 messages and should find subscriptions.")
        print("\n   Next step: Run a scan and check the console logs for:")
        print("   === BATCH 1 === ...")
        print("   API Response: messages_returned=...")
        
finally:
    db.close()
