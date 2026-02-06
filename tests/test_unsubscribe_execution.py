import pytest
import asyncio

from app.unsubscribe import is_safe_https_url, try_https_unsubscribe


def test_is_safe_https_url():
    assert is_safe_https_url("https://example.com/unsub")
    assert not is_safe_https_url("http://example.com/unsub")
    assert not is_safe_https_url("javascript:alert(1)")
    assert not is_safe_https_url(
        "https://example.com/unsub?redirect=http://evil.com")


@pytest.mark.asyncio
async def test_try_https_unsubscribe_monkeypatch(monkeypatch):
    class FakeResp:
        def __init__(self):
            self.status_code = 200
            self.text = 'ok'

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url):
            return FakeResp()

    monkeypatch.setattr('app.unsubscribe.httpx.AsyncClient',
                        lambda **kwargs: FakeClient())
    res = await try_https_unsubscribe('https://example.com/unsub')
    assert res.get('ok') is True


def test_execute_unsubscribe_task_no_user(monkeypatch):
    # calling task with non-existent user should return user_not_found
    import asyncio
    from app.unsubscribe import execute_unsubscribe_task

    res = asyncio.get_event_loop().run_until_complete(
        execute_unsubscribe_task(999999, 'example.com', {"https": [], "mailto": []}))
    assert res.get('ok') is False and res.get('reason') == 'user_not_found'
