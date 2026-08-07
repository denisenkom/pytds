import datetime

import OpenSSL.crypto
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pytds.tls import is_san_matching, validate_host


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
    # test that SAN matching is case insensitive, DNS names are not case sensitive
    assert is_san_matching("DATABASE.COM", "database.com")
    assert is_san_matching("database.com", "DATABASE.COM")
    assert is_san_matching("DaTaBaSe.CoM", "dAtAbAsE.cOm")
    assert is_san_matching("DNS:*.Database.Windows.Net", "my-sql-server.database.windows.net")
    assert is_san_matching("DNS:*.database.windows.net", "my-sql-server.DATABASE.WINDOWS.NET")


def _make_cert(common_name: str, san_dns_names: list[str] | None) -> OpenSSL.crypto.X509:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
    )
    if san_dns_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san_dns_names]),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    return OpenSSL.crypto.X509.from_cryptography(cert)


def test_validate_host_cn_match():
    cert = _make_cert("database.com", None)
    assert validate_host(cert, b"database.com")


def test_validate_host_no_match_without_san():
    cert = _make_cert("database.com", None)
    assert not validate_host(cert, b"other.com")


def test_validate_host_san_match():
    cert = _make_cert("database.com", ["*.database.windows.net"])
    assert validate_host(cert, b"my-sql-server.database.windows.net")


def test_validate_host_san_no_match():
    cert = _make_cert("database.com", ["other.database.windows.net"])
    assert not validate_host(cert, b"my-sql-server.database.windows.net")
