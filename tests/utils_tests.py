import time
import pytest
import pytds.utils


def test_parse_server():
    assert pytds.utils.parse_server(".") == ("localhost", "")
    assert pytds.utils.parse_server("(local)") == ("localhost", "")


def test_exponential_backoff_success_first_attempt():
    """
    Test exponential backoff succeeding on first attempt
    """
    got_exception = {'value': None}

    def ex_handler(ex):
        got_exception['value'] = ex

    res = pytds.utils.exponential_backoff(
        work=lambda t: t,
        ex_handler=ex_handler,
        max_time_sec=1,
        first_attempt_time_sec=0.1,
    )
    # result should be what was returned by work lambda
    # and it should be equal to what was passed as first attempt timeout
    # since this is what is passed to work lambda and what it returns
    assert res == 0.1
    assert got_exception['value'] is None


def test_exponential_backoff_timeout():
    """
    Should perform 4 attempts with expected timeouts for each when attempts fail
    """
    context = {'attempts': 0}
    start_time = time.time()

    def work(t):
        context['attempts'] += 1
        print(f"attempt {context['attempts']}, timeout {t:0.1f}, start time {time.time() - start_time:0.1f}")
        raise RuntimeError("raising test exception")

    with pytest.raises(TimeoutError):
        pytds.utils.exponential_backoff(
            work=work,
            ex_handler=lambda ex: None,
            max_time_sec=1,
            first_attempt_time_sec=0.1,
        )
    # attempts are
    # 1: timeout 0.1, ends at 0.1
    # 2: timeout 0.2, ends at 0.3
    # 3: timeout 0.4, ends at 0.7
    # 4: timeout 0.3, ends at 1.0
    assert context['attempts'] == 4
