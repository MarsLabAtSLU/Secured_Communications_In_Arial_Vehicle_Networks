#CSCI5650 vocal_cpabe.py, version 2.0, Nov27 2019
#Author: Sagar Calnoor Rajashekar (sagar.calnoorrajashekar@slu.edu)
#Last Modified: Wednesday Nov 27th 2019
#Modified By: Sagar Calnoor Rajashekar
#Description: This file when triggered will enable microphone for voice detection and process speech to text.
#             It also maps vocal intent to attribute based policy encryption.


import speech_recognition as s_recog
from abenc_encrypt import encrypt
import pyttsx3
import socket
import json
import sys
import bz2

engine = pyttsx3.init()
srecog = s_recog.Recognizer()
mic_status = s_recog.Microphone.list_microphone_names()

access_policy_dict = {'AP0': '((red or blue) and (region1))',
        'AP1': '((blue and one) and (camera or region1))', 
        'AP2': '((red and one) and (camera or region1))'
        }

cmd = ['takeoff', 'take off', 'figure 8', 'square']
unit=['unit one', 'unit two']
interface=['camera', 'audio']
region=['region one', 'region two']
logic_cond=['and', 'or']
team = ['blue', 'red']

def bcast_command(message):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server.bind(("192.168.1.146", 44444))
    server.settimeout(0.2)
    server.sendto(message, ('192.168.1.120', 37020))
    server.sendto(message, ('192.168.1.114', 37020))

def main():
    print(mic_status)
    _mic = s_recog.Microphone(device_index=0)
    with _mic as _src:
        srecog.adjust_for_ambient_noise(_src)
        audio = srecog.listen(_src)

    _str = srecog.recognize_google(audio)
    r_str = _str.lower()
    print(r_str)

    _reqCmd =''
    for _cmd in cmd:
        if _cmd in r_str:
            _reqCmd = _cmd
            break

    _actionCmd=''
    if cmd[0] in _reqCmd:
        _actionCmd = _reqCmd
    elif cmd[1] in _reqCmd:
        _actionCmd = cmd[0]
    elif cmd[2] in _reqCmd:
        _actionCmd = 'figure eight'
    elif cmd[3] in _reqCmd:
        _actionCmd =_reqCmd
    else:
        print('No matching command for user requested action. Please try again ...')
        sys.exit()
        
    jsonData = {"uid-bcast": {"cmd": ""}}
    jsonData["uid-bcast"]["cmd"] = _actionCmd
    message = json.JSONEncoder().encode(jsonData)
    print (message)

    ap = None
    if (team[1] in r_str) and (team[0] in r_str):
        if logic_cond[0] and logic_cond[1] in r_str:
            if region[0] in r_str:
                ap=access_policy_dict['AP0']
        
        if ap == None:
            print ('blue and red team, no such attributes exists');
            sys.exit()

        if debug: 
            print ('action command: ' + _actionCmd + '; team: ' + team[0])
            print ("blue and read team access policy: %s" % ap)

        cipher = encrypt(message, ap)
        bcast_command(cipher)
    elif team[0] in r_str:
        if logic_cond[0] in r_str:
            if unit[0] in r_str:
                if interface[0] in r_str:
                    ap=access_policy_dict['AP1']

        if ap == None:
            print ('blue team, no such attributes exists');
            sys.exit()

        if debug: 
            print ('action command: ' + _actionCmd + '; team: ' + team[0])
            print ("blue team access policy: %s" % ap)

        cipher = encrypt(message, ap)
        bcast_command(cipher)
    elif team[1] in r_str:
        if logic_cond[0] in r_str:
            if unit[0] in r_str:
                if interface[1] in r_str:
                    ap=access_policy_dict['AP2']

        if ap == None:
            print ('red team, no such attributes exists');
            sys.exit()

        if debug:
            print ('action command: ' + _actionCmd + '; team: ' + team[1])
            print ("red team access policy: %s" % ap)

        cipher = encrypt(message, ap)
        bcast_command(cipher)
    else:
        if debug: print ('action command, not subscribed to any teams.')
        sys.exit()

if __name__ == '__main__':
    debug = True
    main()
