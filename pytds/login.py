# vim: set fileencoding=utf8 :
import socket
import logging

logger = logging.getLogger(__name__)


class SspiAuth(object):
    def __init__(self, user_name='', password='', server_name='', port=None, spn=None):
        from . import sspi
        # parse username/password informations
        if '\\' in user_name:
            domain, user_name = user_name.split('\\')
        else:
            domain = ''
        if domain and user_name:
            self._identity = sspi.make_winnt_identity(
                domain,
                user_name,
                password)
        else:
            self._identity = None
        # build SPN
        if spn:
            self._sname = spn
        else:
            primary_host_name, _, _ = socket.gethostbyname_ex(server_name)
            self._sname = 'MSSQLSvc/{0}:{1}'.format(primary_host_name, port)

        # using Negotiate system will use proper protocol (either NTLM or Kerberos)
        self._cred = sspi.SspiCredentials(
            package='Negotiate',
            use=sspi.SECPKG_CRED_OUTBOUND,
            identity=self._identity)

        self._flags = sspi.ISC_REQ_CONFIDENTIALITY | sspi.ISC_REQ_REPLAY_DETECT | sspi.ISC_REQ_CONNECTION

    def create_packet(self):
        from . import sspi
        import ctypes
        buf = ctypes.create_string_buffer(4096)
        self._ctx, status, bufs = self._cred.create_context(
            flags=self._flags,
            byte_ordering='network',
            target_name=self._sname,
            output_buffers=[(sspi.SECBUFFER_TOKEN, buf)])
        if status == sspi.Status.SEC_I_COMPLETE_AND_CONTINUE:
            self._ctx.complete_auth_token(bufs)
        return bufs[0][1]

    def handle_next(self, packet):
        from . import sspi
        import ctypes
        buf = ctypes.create_string_buffer(4096)
        status, buffers = self._ctx.next(
            flags=self._flags,
            byte_ordering='network',
            target_name=self._sname,
            input_buffers=[(sspi.SECBUFFER_TOKEN, packet)],
            output_buffers=[(sspi.SECBUFFER_TOKEN, buf)])
        return buffers[0][1]

    def close(self):
        self._ctx.close()
        self._cred.close()


class NtlmAuth(object):
    def __init__(self, user_name, password):
        self._domain, self._user = user_name.split('\\', 1)
        self._password = password

    def create_packet(self):
        import ntlm
        return ntlm.create_NTLM_NEGOTIATE_MESSAGE_raw(socket.gethostname(), self._domain)

    def handle_next(self, packet):
        import ntlm
        nonce, flags = ntlm.parse_NTLM_CHALLENGE_MESSAGE_raw(packet)
        return ntlm.create_NTLM_AUTHENTICATE_MESSAGE_raw(nonce, self._user, self._domain, self._password, flags)

    def close(self):
        pass
