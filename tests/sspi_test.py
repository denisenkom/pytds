try:
    import unittest2 as unittest
except:
    import unittest
import ctypes
from ctypes import create_string_buffer
from . import settings
import socket
import sys

@unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
class SspiTest(unittest.TestCase):
    def test_enum_security_packages(self):
        import pytds.sspi
        pytds.sspi.enum_security_packages()

    def test_credentials(self):
        return self.skipTest("this test fails when run under service account")
        import pytds.sspi
        cred = pytds.sspi.SspiCredentials('Negotiate', pytds.sspi.SECPKG_CRED_OUTBOUND)
        cred.query_user_name()
        cred.close()

    def test_make_buffers(self):
        import pytds.sspi
        buf = create_string_buffer(1000)
        bufs = [(pytds.sspi.SECBUFFER_TOKEN, buf)]
        desc = pytds.sspi._make_buffers_desc(bufs)
        self.assertEqual(desc.ulVersion, pytds.sspi.SECBUFFER_VERSION)
        self.assertEqual(desc.cBuffers, len(bufs))
        self.assertEqual(desc.pBuffers[0].cbBuffer, len(bufs[0][1]))
        self.assertEqual(desc.pBuffers[0].BufferType, bufs[0][0])
        self.assertEqual(desc.pBuffers[0].pvBuffer, ctypes.cast(bufs[0][1], pytds.sspi.PVOID).value)

    def test_sec_context(self):
        import pytds.sspi
        cred = pytds.sspi.SspiCredentials(
            'Negotiate',
            pytds.sspi.SECPKG_CRED_OUTBOUND)

        token_buf = create_string_buffer(10000)
        bufs = [(pytds.sspi.SECBUFFER_TOKEN, token_buf)]
        server = settings.HOST
        if '\\' in server:
            server, _ = server.split('\\')
        host, _, _ = socket.gethostbyname_ex(server)
        target_name = 'MSSQLSvc/{0}:1433'.format(host)
        ctx, status, bufs = cred.create_context(
            flags=pytds.sspi.ISC_REQ_CONFIDENTIALITY|pytds.sspi.ISC_REQ_REPLAY_DETECT|pytds.sspi.ISC_REQ_CONNECTION,
            byte_ordering='network',
            target_name=target_name,
            output_buffers=bufs)
        if status == pytds.sspi.Status.SEC_I_COMPLETE_AND_CONTINUE or status == pytds.sspi.Status.SEC_I_CONTINUE_NEEDED:
            ctx.complete_auth_token(bufs)

        #realbuf = create_string_buffer(10000)
        #buf = SecBuffer()
        #buf.cbBuffer = len(realbuf)
        #buf.BufferType = SECBUFFER_TOKEN
        #buf.pvBuffer = cast(realbuf, PVOID)
        #bufs = SecBufferDesc()
        #bufs.ulVersion = SECBUFFER_VERSION
        #bufs.cBuffers = 1
        #bufs.pBuffers = pointer(buf)
        #byte_ordering = 'network'
        #output_buffers = bufs
        #from pytds.sspi import _SecContext
        #ctx = _SecContext()
        #ctx._handle = SecHandle()
        #ctx._ts = TimeStamp()
        #ctx._attrs = ULONG()
        #status = sec_fn.InitializeSecurityContext(
        #        ctypes.byref(cred._handle),
        #        None,
        #        'MSSQLSvc/misha-pc:1433',
        #        ISC_REQ_CONNECTION,
        #        0,
        #        SECURITY_NETWORK_DREP if byte_ordering == 'network' else SECURITY_NATIVE_DREP,
        #        None,
        #        0,
        #        byref(ctx._handle),
        #        byref(bufs),
        #        byref(ctx._attrs),
        #        byref(ctx._ts));
        #pass
