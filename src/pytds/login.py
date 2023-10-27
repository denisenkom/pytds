# vim: set fileencoding=utf8 :
"""
.. module:: login
   :platform: Unix, Windows, MacOSX
   :synopsis: Login classes

.. moduleauthor:: Mikhail Denisenko <denisenkom@gmail.com>
"""
import logging
import socket

logger = logging.getLogger(__name__)


class SspiAuth(object):
    """ SSPI authentication

    :platform: Windows

    Required parameters are server_name and port or spn

    :keyword user_name: User name, if not provided current security context will be used
    :type user_name: str
    :keyword password: User password, if not provided current security context will be used
    :type password: str
    :keyword server_name: MSSQL server host name
    :type server_name: str
    :keyword port: MSSQL server port
    :type port: int
    :keyword spn: Service name
    :type spn: str
    """
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
        self._ctx = None

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


class NtlmAuth(object):
    """
    This class is deprecated since `ntlm-auth` package, on which it depends, is deprecated.
    Instead use :class:`.SpnegoAuth`.

    NTLM authentication, uses Python implementation (ntlm-auth)

    For more information about NTLM authentication see https://github.com/jborean93/ntlm-auth

    :param user_name: User name
    :type user_name: str
    :param password: User password
    :type password: str
    :param ntlm_compatibility: NTLM compatibility level, default is 3(NTLMv2)
    :type ntlm_compatibility: int
    """

    def __init__(self, user_name, password, ntlm_compatibility=3):
        self._user_name = user_name
        if '\\' in user_name:
            domain, self._user = user_name.split('\\', 1)
            self._domain = domain.upper()
        else:
            self._domain = 'WORKSPACE'
            self._user = user_name
        self._password = password
        self._workstation = socket.gethostname().upper()

        try:
            from ntlm_auth.ntlm import NtlmContext
        except ImportError:
            raise ImportError("To use NTLM authentication you need to install ntlm-auth module")

        self._ntlm_context = NtlmContext(self._user, self._password, self._domain, self._workstation,
                                         ntlm_compatibility=ntlm_compatibility)

    def create_packet(self):
        return self._ntlm_context.step()

    def handle_next(self, packet):
        return self._ntlm_context.step(packet)

    def close(self):
        pass


class SpnegoAuth(object):
    """ Authentication using Negotiate protocol, uses implementation provided pyspnego package

    Takes same parameters as spnego.client function.
    """

    def __init__(self, *args, **kwargs):
        try:
            import spnego
        except ImportError:
            raise ImportError("To use spnego authentication you need to install pyspnego package")
        self._context = spnego.client(*args, **kwargs)

    def create_packet(self):
        return self._context.step()

    def handle_next(self, packet):
        return self._context.step(packet)

    def close(self):
        pass


class KerberosAuth(object):
    def __init__(self, server_principal):
        try:
            import kerberos
        except ImportError:
            import winkerberos as kerberos
        self._kerberos = kerberos
        res, context = kerberos.authGSSClientInit(server_principal)
        if res < 0:
            raise RuntimeError('authGSSClientInit failed with code {}'.format(res))
        logger.info('Initialized GSS context')
        self._context = context

    def create_packet(self):
        import base64
        res = self._kerberos.authGSSClientStep(self._context, '')
        if res < 0:
            raise RuntimeError('authGSSClientStep failed with code {}'.format(res))
        data = self._kerberos.authGSSClientResponse(self._context)
        logger.info('created first client GSS packet %s', data)
        return base64.b64decode(data)

    def handle_next(self, packet):
        import base64
        res = self._kerberos.authGSSClientStep(self._context, base64.b64encode(packet).decode('ascii'))
        if res < 0:
            raise RuntimeError('authGSSClientStep failed with code {}'.format(res))
        if res == self._kerberos.AUTH_GSS_COMPLETE:
            logger.info('GSS authentication completed')
            return b''
        else:
            data = self._kerberos.authGSSClientResponse(self._context)
            logger.info('created client GSS packet %s', data)
            return base64.b64decode(data)

    def close(self):
        pass
