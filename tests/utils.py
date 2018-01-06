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
        self._test_cache_dir = os.path.join(os.path.dirname(__file__), '..', '.test-cache')
        os.makedirs(self._test_cache_dir, exist_ok=True)
        root_cert_path = self.cert_path('root')
        self._root_key = self.key('root')
        self._root_ca = generate_root_certificate(self._root_key)
        pathlib.Path(root_cert_path).write_bytes(self._root_ca.public_bytes(serialization.Encoding.PEM))

    def key_path(self, name):
        return os.path.join(self._test_cache_dir, name + 'key.pem')

    def cert_path(self, name):
        return os.path.join(self._test_cache_dir, name + 'cert.pem')

    def key(self, name) -> rsa.RSAPrivateKey:
        if name not in self._key_cache:
            backend = cryptography.hazmat.backends.default_backend()
            key_path = self.key_path(name)
            if os.path.exists(key_path):
                bin = pathlib.Path(key_path).read_bytes()
                key = serialization.load_pem_private_key(bin, password=None, backend=backend)
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
        cert = cb.issuer_name(self._root_ca.subject) \
            .sign(private_key=self._root_key, algorithm=hashes.SHA256(), backend=backend)
        cert_path = self.cert_path(name)
        pathlib.Path(cert_path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return cert


def generate_rsa_key() -> rsa.RSAPrivateKeyWithSerialization:
    backend = cryptography.hazmat.backends.default_backend()
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=backend)


def generate_root_certificate(private_key: rsa.RSAPrivateKey) -> x509.Certificate:
    backend = cryptography.hazmat.backends.default_backend()
    subject = x509.Name(
        [x509.NameAttribute(
            x509.oid.NameOID.COMMON_NAME, 'root'
        )]
    )
    builder = x509.CertificateBuilder()
    return builder.subject_name(subject).issuer_name(subject)\
        .not_valid_before(datetime.datetime.utcnow())\
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))\
        .serial_number(x509.random_serial_number())\
        .public_key(private_key.public_key())\
        .add_extension(extension=x509.BasicConstraints(ca=True, path_length=1), critical=True)\
        .add_extension(extension=x509.KeyUsage(digital_signature=False,
                                               content_commitment=False,
                                               key_encipherment=False,
                                               data_encipherment=False,
                                               key_agreement=False,
                                               key_cert_sign=True,
                                               crl_sign=True,
                                               encipher_only=False,
                                               decipher_only=False,
                                               ), critical=True)\
        .sign(private_key=private_key, algorithm=hashes.SHA256(), backend=backend)


class MockSock(object):
    def __init__(self, input_packets=()):
        self.set_input(input_packets)
        self._out_packets = []
        self._closed = False

    def recv(self, size):
        if not self.is_open():
            raise Exception('Connection closed')
        if self._curr_packet >= len(self._packets):
            return b''
        if self._packet_pos >= len(self._packets[self._curr_packet]):
            self._curr_packet += 1
            self._packet_pos = 0
        if self._curr_packet >= len(self._packets):
            return b''
        res = self._packets[self._curr_packet][self._packet_pos:self._packet_pos+size]
        self._packet_pos += len(res)
        return res

    def recv_into(self, buffer, size=0):
        if not self.is_open():
            raise Exception('Connection closed')
        if size == 0:
            size = len(buffer)
        res = self.recv(size)
        buffer[0:len(res)] = res
        return len(res)

    def send(self, buf, flags=0):
        if not self.is_open():
            raise Exception('Connection closed')
        self._out_packets.append(buf)
        return len(buf)

    def sendall(self, buf, flags=0):
        if not self.is_open():
            raise Exception('Connection closed')
        self._out_packets.append(buf)

    def setsockopt(self, *args):
        pass

    def close(self):
        self._closed = True

    def is_open(self):
        return not self._closed

    def consume_output(self):
        """
        Retrieve data from output queue and then clear output queue
        @return: bytes
        """
        res = self._out_packets
        self._out_packets = []
        return b''.join(res)

    def set_input(self, packets):
        """
        Resets input queue
        @param packets: List of input packets
        """
        self._packets = packets
        self._curr_packet = 0
        self._packet_pos = 0
