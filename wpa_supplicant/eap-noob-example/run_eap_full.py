#!/usr/bin/python3
import subprocess
import signal
import os
import time
import sqlite3
import argparse
import atexit
import base64
import hashlib
import json
from datetime import datetime
import tkinter as tk

# Constants
db_path_peer = "/tmp/noob_peer.db"

# tkinter
root = tk.Tk()
txb = tk.Text(root,height=2,width=140)
txb.pack()
root.title("OOB-Message")
root.withdraw()

def copyClick():
    root.clipboard_clear()
    root.clipboard_append(txb.get('1.0',tk.END))
def regenerateClick():
   # txb.delete('1.0',tk.END)
    oob = generate_oob()    
    insert_oob(oob)
    print_oob_message(oob)


tk.Button(root,text="Copy to clipboard",command=lambda:copyClick()).pack()
tk.Button(root,text="Renerate Oob", command=lambda:regenerateClick()).pack()

## DB funcs

def exec_query(query, db_path, args=[]):
    conn = sqlite3.connect(db_path)

    out = []
    c = conn.cursor()
    c.execute(query, args)
    conn.commit()
    # Should be changed if we want to handle all peers
    out = c.fetchone()
    conn.close()
    return out

def get_peers():
    """Retrieve PeerIds and SSIDs for peers that are ready for OOB transfer"""

    query = 'SELECT Ssid, PeerId from EphemeralState WHERE PeerState=1 AND Z IS NOT NULL'
    data = exec_query(query, db_path_peer)
    return data

def insert_oob(oob):
    if oob is None:
        return
    # Insert the OOB data into the peer database
    query = 'INSERT INTO EphemeralNoob (Ssid, PeerId, NoobId, Noob, Hoob, sent_time) VALUES (?, ?, ?, ?, ?, ?)'
    args = [oob["ssid"], oob["peer_id"], oob["noob_id"], oob["noob"], oob["hoob"], oob["sent_time"]]
    exec_query(query, db_path_peer, args)

## OOB generation

def compute_noob_id(noob_b64):
    """Compute identifier for the OOB message"""

    noob_id = 'NoobId' + noob_b64
    noob_id = noob_id.encode('utf-8')
    noob_id = hashlib.sha256(noob_id).digest()
    noob_id_b64 = base64.urlsafe_b64encode(noob_id[0:16])
    noob_id_b64 = str(noob_id_b64, 'utf-8').strip('=')
    return noob_id_b64

def gen_noob():
    noob = os.urandom(16)
    noob_64 = base64.urlsafe_b64encode(noob)
    noob_64 = str(noob_64,'utf-8').strip('=')
    return noob_64

def compute_hoob(peer_id, noob):
    """Compute 16-byte fingerprint from all exchanged parameters"""

    query = 'SELECT MacInput FROM EphemeralState WHERE PeerId=?'

    data = exec_query(query, db_path_peer, [peer_id])
    if data is None:
        print('Query returned None in gen_noob')
        return None

    hoob_array = json.loads(data[0])
    hoob_array[len(hoob_array) - 1] = noob
    hoob_str = json.dumps(hoob_array, separators=(',', ':')).encode()
    hoob = hashlib.sha256(hoob_str).digest()
    hoob_b64 = base64.urlsafe_b64encode(hoob[0:16]).decode('ascii').strip('=')
    return hoob_b64


def generate_oob():
    result = None
    try:
        peer = get_peers()
        noob = gen_noob()
        noob_id = compute_noob_id(noob)
        hoob = compute_hoob(peer[1], noob)
        sent_time = int(datetime.utcnow().timestamp())
        result = {
            "ssid":peer[0],
            "peer_id":peer[1],
            "noob":noob,
            "noob_id":noob_id,
            "hoob":hoob,
            "sent_time":sent_time
        }
    except:
        print("Can't generate oob")
    return result 

def get_pid(arg):
    pid_list = []
    pname = arg.encode(encoding='UTF-8')
    p = runbash(b"ps -A | grep "+pname)
    if None == p:
        return None
    for line in p.splitlines():
        if pname in line:
            pid = int(line.split(None,1)[0])
            pid_list.append(pid)
    return pid_list

def runbash(cmd):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    out = p.stdout.read().strip()
    return out

def kill_existing_supplicants():
    pid = get_pid('wpa_supplicant')
    for item in pid:
        os.kill(int(item),signal.SIGKILL)

def check_result():
    res = runbash(b"sudo -S ./wpa_cli status | grep 'EAP state=SUCCESS'")
    if res == b"EAP state=SUCCESS":
        return True
    return False

def print_oob_message(oob):  
    if oob is None:
        return

    oobString = json.dumps(oob)
    message_bytes = oobString.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    query = "SELECT ServerInfo from EphemeralState WHERE SSID like '" + oob["ssid"] + "'"
    data = exec_query(query, db_path_peer)

    if not data:
        return
    serverInfo = json.loads(data[0])

    printMessage = serverInfo["Url"] + "/" + base64_message
    print("OOB-MESSAGE: To complete the OOB process please use device whithin the host network to navigate to this URL: " + printMessage + "\n")
    txb.delete('1.0',tk.END)
    txb.insert('1.0',printMessage)
    root.update()
    root.deiconify()
        

def loop_check_result(oob,wpa_process,elapsed):

    loopTime = 5000
    result = check_result()
    if loopTime >= 60000:
        print ("OOB-MESSAGE: Elapsed " + str(loopTime) + " seconds. Renewing OOB")
        oob = None
        elapsed = 0
        
    if  not result and oob is None:
        oob = generate_oob()    
        insert_oob(oob)
        print_oob_message(oob)

    if not result:
        root.after(loopTime,lambda: loop_check_result(oob,wpa_process,loopTime))
    else:  
        root.withdraw()
    


def main():    
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface',help='Name of the wireless interface')
    args = parser.parse_args()

    kill_existing_supplicants()
   
    print("Starting wpa_supplicant...")
    cmd = "./wpa_supplicant -i "+args.interface+" -c wpa_supplicant.conf -Dnl80211 -d | egrep 'EAP:|EAP-NOOB'"
    wpa_process = subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)    

    oob = None
    loop_check_result(oob,wpa_process,0)

def onExit():
    kill_existing_supplicants()

if __name__=='__main__':
    atexit.register(onExit)
    root.after(500,lambda: main())
    root.lift()
    root.mainloop()


