from app.ai.deadline import ProductDeadlineExceeded, bounded_timeout, product_deadline, remaining_seconds, require_time


def test_deadline_contract_without_external_services():
    assert remaining_seconds() is None
    with product_deadline(30):
        remaining = require_time("controlled regression")
        assert remaining is not None
        assert 0 < remaining <= 30
        assert bounded_timeout(90, "controlled regression") <= 30


def test_expired_deadline_is_authoritative():
    with product_deadline(0):
        try:
            require_time("expired regression")
        except ProductDeadlineExceeded:
            return
    raise AssertionError("expired deadline did not block")
