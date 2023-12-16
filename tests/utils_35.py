import os.path
import shutil
import datetime
import pathlib
import cryptography.hazmat.backends
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography import x509
import cryptography.x509.oid


class TestCA:
    def __init__(self):
        self._key_cache = {}
        backend = cryptography.hazmat.backends.default_backend()
        self._test_cache_dir = os.path.join(
            os.path.dirname(__file__), "..", ".test-cache"
        )
        os.makedirs(self._test_cache_dir, exist_ok=True)
        root_cert_path = self.cert_path("root")
        self._root_key = self.key("root")
        self._root_ca = generate_root_certificate(self._root_key)
        pathlib.Path(root_cert_path).write_bytes(
            self._root_ca.public_bytes(serialization.Encoding.PEM)
        )

    def key_path(self, name):
        return os.path.join(self._test_cache_dir, name + "key.pem")

    def cert_path(self, name):
        return os.path.join(self._test_cache_dir, name + "cert.pem")

    def key(self, name) -> rsa.RSAPrivateKey:
        if name not in self._key_cache:
            backend = cryptography.hazmat.backends.default_backend()
            key_path = self.key_path(name)
            if os.path.exists(key_path):
                bin = pathlib.Path(key_path).read_bytes()
                key = serialization.load_pem_private_key(
                    bin, password=None, backend=backend
                )
            else:
                key = generate_rsa_key()
                bin = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                pathlib.Path(key_path).write_bytes(bin)
            self._key_cache[name] = key
        return self._key_cache[name]

    def sign(self, name: str, cb: x509.CertificateBuilder) -> x509.Certificate:
        backend = cryptography.hazmat.backends.default_backend()
        cert = cb.issuer_name(self._root_ca.subject).sign(
            private_key=self._root_key, algorithm=hashes.SHA256(), backend=backend
        )
        cert_path = self.cert_path(name)
        pathlib.Path(cert_path).write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        return cert


def generate_rsa_key() -> rsa.RSAPrivateKeyWithSerialization:
    backend = cryptography.hazmat.backends.default_backend()
    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=backend
    )


def generate_root_certificate(private_key: rsa.RSAPrivateKey) -> x509.Certificate:
    backend = cryptography.hazmat.backends.default_backend()
    subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "root")])
    builder = x509.CertificateBuilder()
    return (
        builder.subject_name(subject)
        .issuer_name(subject)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .serial_number(1)
        .public_key(private_key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=private_key, algorithm=hashes.SHA256(), backend=backend)
    )
