from app.gmail_client import parse_list_unsubscribe


def test_parse_empty():
    assert parse_list_unsubscribe([]) == {"mailto": [], "https": []}


def test_parse_mailto_and_https():
    headers = [{"name": "List-Unsubscribe", "value": "<mailto:unsubscribe@example.com>, <https://example.com/unsub>"}]
    res = parse_list_unsubscribe(headers)
    assert "mailto" in res and res["mailto"][0].startswith("mailto:")
    assert "https" in res and res["https"][0].startswith("https://")
