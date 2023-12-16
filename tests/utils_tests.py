import pytds.utils


def test_parse_server():
    assert pytds.utils.parse_server(".") == ("localhost", "")
    assert pytds.utils.parse_server("(local)") == ("localhost", "")
