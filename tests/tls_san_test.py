from pytds.tls import is_san_matching


def test_san():
    assert not is_san_matching("", "host.com")
    assert is_san_matching("database.com", "database.com")
    assert not is_san_matching("notdatabase.com", "database.com")
    assert not is_san_matching("*.database.com", "database.com")
    assert is_san_matching("*.database.com", "test.database.com")
    assert not is_san_matching("database.com", "*.database.com")
    assert not is_san_matching("test.*.database.com", "test.subdomain.database.com") # That star should be at first position
    # test stripping DNS:
    assert is_san_matching("DNS:westus2-a.control.database.windows.net", "westus2-a.control.database.windows.net")
    assert is_san_matching("DNS:*.database.windows.net", "my-sql-server.database.windows.net")
    # test parsing multiple SANs
    assert is_san_matching("DNS:westus2-a.control.database.windows.net,DNS:*.database.windows.net", "my-sql-server.database.windows.net")
    assert is_san_matching("DNS:westus2-a.control.database.windows.net, DNS:*.database.windows.net", "my-sql-server.database.windows.net")
    # test that DNS: prefix removal doesn't strip uppercase letters from hostname
    assert is_san_matching("DNS:DNSSERVER.example.com", "DNSSERVER.example.com")
    assert is_san_matching("DNS:SQL-DNS-Node.database.windows.net", "SQL-DNS-Node.database.windows.net")
