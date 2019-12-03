#CSCI5650 onboard_vocal_cpabe.py, version 4.0, Nov27 2019
#Author: Sagar Calnoor Rajashekar (sagar.calnoorrajashekar@slu.edu)
#Last Modified: Wednesday Nov 27th 2019
#Modified By: Sagar Calnoor Rajashekar
#Description:  This runs on client machine where it requests CA server with it's attributes for public key 
#              and secrete key. Once it recieves the secret and public key it saves for later decryption. 
#              Upon getting encrypted data (cipher text) which is decrypted via help of public and secrete key.

from charm.toolbox.ABEnc import ABEnc
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.pairinggroup import PairingGroup,GT
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.core.math.pairing import hashPair as sha2
from subprocess import Popen
from math import ceil
import socket
import json

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
            print ("[WARNING] key failed to decrypt, message not intented for this device.")
            return None
        cipher = AuthenticatedCryptoAbstraction(sha2(key))
        return cipher.decrypt(c2)
    
def getSecretKeyFromCA():
    msg = json.JSONEncoder().encode({"uid-attr": {"attr": "BLUE,ONE,CAMERA,REGION1"}})
    data = requestCAServer(msg)
    open("/home/ubuntu/catkin_ws/src/virtual_drone/s_keyD1_adv.txt", "wb").write(data.encode())

def getPublicKeyFromCA():
    msg = json.JSONEncoder().encode({"uid-pk": "None"})
    data = requestCAServer(msg)
    open("/home/ubuntu/catkin_ws/src/virtual_drone/p_key_adv.txt", "wb").write(data.encode())

def requestCAServer(msg):
    CHUNK_SIZE = 8*1024
    sock = socket.socket()
    sock.connect(("192.168.1.146", 12346))
    chunk = sock.send(msg.encode())
    data = ""
    while chunk:
        chunk = sock.recv(CHUNK_SIZE)
        data += chunk.decode()
    sock.close()
    return data

cmd_list = ['takeoff', 'figure eight', 'square']
def main():
    groupObj = PairingGroup('SS512')
    cpabe = CPabe_BSW07(groupObj)
    hyb_abe = HybridABEnc(cpabe, groupObj)

    getPublicKeyFromCA()
    with open("/home/ubuntu/catkin_ws/src/virtual_drone/p_key_adv.txt", "rb") as pkFile:
        pk = bytesToObject(pkFile.read(), groupObj)

    getSecretKeyFromCA()
    with open("/home/ubuntu/catkin_ws/src/virtual_drone/s_keyD1_adv.txt", "rb") as skFile:
        sk = bytesToObject(skFile.read(), groupObj)

    if debug: print("pk => ", pk)
    if debug: print("sk => ", sk)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    client.bind(("", 37020))
    while True:
        data, addr = client.recvfrom(65535)
        if data is not None:
            ct = bytesToObject(data.decode(), groupObj)
            msg = hyb_abe.decrypt(pk, sk, ct)
            if msg != None:
                jsonData = json.loads(msg.decode())
                cmd = jsonData["uid-bcast"]["cmd"]
                if cmd in cmd_list:
                    if 'takeoff' in cmd.lower():
                        print('[onboard-vocal-cpabe]: command take-off detected.')
                        Popen("/home/ubuntu/catkin_ws/src/virtual_drone/mavros_offboard_takeoff_land.py", shell=True)
                    elif 'figure eight' in cmd.lower():
                        print('[flask-run]: command figure-eight detected.')
                        Popen("/home/ubuntu/catkin_ws/src/virtual_drone/mavros_offboard_figure_eight.py", shell=True)
                    elif 'square' in cmd.lower():
                        print('[flask-run]: command square detected.')
                        Popen("/home/ubuntu/catkin_ws/src/virtual_drone/mavros_offboard_square.py", shell=True)
                else:
                    print('[flask-run]: command does not match.')

if __name__ == "__main__":
    debug = True
    main()
