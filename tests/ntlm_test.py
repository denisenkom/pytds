import binascii
from unittest import TestCase
from pytds.ntlm import *

class Test(TestCase):
    def runTest(self):

        def ByteToHex( byteStr ):
            """
            Convert a byte string to it's hex string representation e.g. for output.
            """
            return ' '.join( [ "%02X" % ord( x ) for x in byteStr ] )

        def HexToByte( hexStr ):
            """
            Convert a string hex byte values into a byte string. The Hex Byte values may
            or may not be space separated.
            """
            hexStr = ''.join( hexStr.split(" ") )

            return binascii.unhexlify(hexStr)
            
        ServerChallenge = HexToByte("01 23 45 67 89 ab cd ef")
        ClientChallenge = b'\xaa'*8
        Time = b'\x00'*8
        Workstation = "COMPUTER".encode('utf-16-le')
        ServerName = "Server".encode('utf-16-le')
        User = "User"
        Domain = "Domain"
        Password = "Password"
        RandomSessionKey = '\55'*16
        self.assertEqual(HexToByte("e5 2c ac 67 41 9a 9a 22 4a 3b 10 8f 3f a6 cb 6d"), create_LM_hashed_password_v1(Password))                  # [MS-NLMP] page 72
        self.assertEqual(HexToByte("a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52"), create_NT_hashed_password_v1(Password))    # [MS-NLMP] page 73
        self.assertEqual(HexToByte("d8 72 62 b0 cd e4 b1 cb 74 99 be cc cd f1 07 84"), create_sessionbasekey(Password))
        self.assertEqual(HexToByte("67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c 44 bd be d9 27 84 1f 94"), calc_resp(create_NT_hashed_password_v1(Password), ServerChallenge))
        self.assertEqual(HexToByte("98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88 a1 72 de f1 1c 7d 5c cd ef 13"), calc_resp(create_LM_hashed_password_v1(Password), ServerChallenge))
        
        (NTLMv1Response,LMv1Response) = ntlm2sr_calc_resp(create_NT_hashed_password_v1(Password), ServerChallenge, ClientChallenge)
        self.assertEqual(HexToByte("aa aa aa aa aa aa aa aa 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"), LMv1Response)  # [MS-NLMP] page 75
        self.assertEqual(HexToByte("75 37 f8 03 ae 36 71 28 ca 45 82 04 bd e7 ca f8 1e 97 ed 26 83 26 72 32"), NTLMv1Response)
        
        self.assertEqual(HexToByte("0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f"), create_NT_hashed_password_v2(Password, User, Domain))    # [MS-NLMP] page 76
        ResponseKeyLM = ResponseKeyNT = create_NT_hashed_password_v2(Password, User, Domain)
        (NTLMv2Response,LMv2Response) = ComputeResponse(ResponseKeyNT, ResponseKeyLM, ServerChallenge, ServerName, ClientChallenge, Time)
        self.assertEqual(HexToByte("86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa aa aa aa aa"), LMv2Response)  # [MS-NLMP] page 76
        
        # expected failure
        # According to the spec in section '3.3.2 NTLM v2 Authentication' the NTLMv2Response should be longer than the value given on page 77 (this suggests a mistake in the spec)
        self.assertNotEqual(HexToByte("68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c"), NTLMv2Response) # [MS-NLMP] page 77
