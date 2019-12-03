#CSCI5650 abenc_encrypt.py, version 2.0, Nov27 2019
#Author: Sagar Calnoor Rajashekar (sagar.calnoorrajashekar@slu.edu)
#Last Modified: Wednesday Nov 27th 2019
#Modified By: Sagar Calnoor Rajashekar
#Description: An helper class library to perform all required cipher-text policy - atrribute base encryption(CP-ABE)

from charm.toolbox.ABEnc import ABEnc
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.pairinggroup import PairingGroup,GT
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.core.math.pairing import hashPair as sha2
from math import ceil

debug = False
class HybridABEnc(ABEnc):
    """
    >>> group = PairingGroup("SS512")
    >>> cpabe = CPabe_BSW07(group)
    >>> hyb_abe = HybridABEnc(cpabe, group)
    >>> access_policy = '((four or three) and (two or one))'
    >>> msg = b"hello world this is an important message."
    >>> (master_public_key, master_key) = hyb_abe.setup()
    >>> secret_key = hyb_abe.keygen(master_public_key, master_key, ['ONE', 'TWO', 'THREE'])
    >>> cipher_text = hyb_abe.encrypt(master_public_key, msg, access_policy)
    >>> hyb_abe.decrypt(master_public_key, secret_key, cipher_text)
    b'hello world this is an important message.'
    """
    def __init__(self, scheme, groupObj):
        ABEnc.__init__(self)
        global abenc
        # check properties (TODO)
        abenc = scheme
        self.group = groupObj
            
    def setup(self):
        return abenc.setup()
    
    def keygen(self, pk, mk, object):
        return abenc.keygen(pk, mk, object)
    
    def encrypt(self, pk, M, object):
        key = self.group.random(GT)
        c1 = abenc.encrypt(pk, key, object)
        # instantiate a symmetric enc scheme from this key
        cipher = AuthenticatedCryptoAbstraction(sha2(key))
        c2 = cipher.encrypt(M)
        return { 'c1':c1, 'c2':c2 }
    
    def decrypt(self, pk, sk, ct):
        c1, c2 = ct['c1'], ct['c2']
        key = abenc.decrypt(pk, sk, c1)
        if key is False:
            raise Exception("failed to decrypt!")
        cipher = AuthenticatedCryptoAbstraction(sha2(key))
        return cipher.decrypt(c2)
    
def encrypt(message, access_policy, debug=True):
    groupObj = PairingGroup('SS512')
    cpabe = CPabe_BSW07(groupObj)
    hyb_abe = HybridABEnc(cpabe, groupObj)

    with open("p_key.txt", "rb") as pkFile:
        pk = bytesToObject(pkFile.read(), groupObj)

    with open("m_key.txt", "rb") as mkFile:
        mk = bytesToObject(mkFile.read(), groupObj)

    ct = hyb_abe.encrypt(pk, message, access_policy)
    byte_msg = objectToBytes(ct, groupObj)

    if debug: 
        print("pk => ", pk)
        print("mk => ", mk)
        with open("cipher.txt", "wb") as ctFile:
            ctFile.write(byte_msg)

    return byte_msg
