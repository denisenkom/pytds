from pytds.tls import is_san_matching

def test_san():
    assert not is_san_matching("", "host.com")
    assert is_san_matching("database.com", "database.com")
    assert not is_san_matching("notdatabase.com", "database.com")
    assert is_san_matching("*.database.com", "database.com")
    assert not is_san_matching("*.database.com", "*.database.com")
    assert not is_san_matching("database.com", "*.database.com")
    assert not is_san_matching("test.*.database.com", "test.subdomain.database.com") # That star should be at first position