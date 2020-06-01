# Script to simulate the transferral of OOB data
# for the EAP-NOOB method.
# Copyright (c) 2020, Max Crone <max@maxcrone.org>

import base64
from collections import OrderedDict
from datetime import datetime
import hashlib
import json
import os
import re
import sqlite3

db_path_server = '/tmp/noob_server.db'
db_path_peer = '/tmp/noob_peer.db'
peer_config_path = '../../wpa_supplicant/eapnoob.conf'

def exec_query(query, db_path, args=[]):
    if not os.path.isfile(db_path_server):
        print(f'Server database file does not exist: {db_path_server}')
    if not os.path.isfile(db_path_peer):
        print(f'Peer database file does not exist: {db_path_peer}')

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

    query = 'SELECT Ssid, PeerId from EphemeralState WHERE PeerState=1'
    data = exec_query(query, db_path_peer)
    return data

def get_direction():
    dir_keyword = 'OobDirs'
    with open(peer_config_path, 'r') as f:
        for line in f:
            if '#' != line[0] and dir_keyword in line:
                parts = re.sub('[\s+]', '', line)
                direction = parts[len(dir_keyword) + 1]
    return direction

def gen_noob():
    """Generate a random 16 byte secret nonce"""

    noob = os.urandom(16)
    noob_b64 = base64.urlsafe_b64encode(noob)
    noob_b64 = str(noob_b64, 'utf-8').strip('=')
    return noob_b64

def compute_noob_id(noob_b64):
    """Compute identifier for the OOB message"""

    noob_id = 'NoobId' + noob_b64
    noob_id = noob_id.encode('utf-8')
    noob_id = hashlib.sha256(noob_id).digest()
    noob_id_b64 = base64.urlsafe_b64encode(noob_id[0:16])
    noob_id_b64 = str(noob_id_b64, 'utf-8').strip('=')
    return noob_id_b64

def compute_hoob(peer_id, noob, direction):
    """Compute 16-byte fingerprint from all exchanged parameters"""

    query = 'SELECT MacInput FROM EphemeralState WHERE PeerId=?'
    if direction == 1:
        db_path = db_path_peer
    else:
        db_path = db_path_server
    data = exec_query(query, db_path, [peer_id])
    if data is None:
        print('Query returned None in gen_noob')
        return None

    hoob_array = json.loads(data[0])
    hoob_array[len(hoob_array) - 1] = noob
    hoob_str = json.dumps(hoob_array, separators=(',', ':')).encode()
    hoob = hashlib.sha256(hoob_str).digest()
    hoob_b64 = base64.urlsafe_b64encode(hoob[0:16]).decode('ascii').strip('=')
    return hoob_b64

def transfer_oob(ssid, peer_id, direction):
    """Simulates the transferral of the OOB data"""

    noob = gen_noob()
    noob_id = compute_noob_id(noob)
    hoob = compute_hoob(peer_id, noob, direction)
    sent_time = int(datetime.utcnow().timestamp())

    # Insert the OOB data into the peer database
    query = 'INSERT INTO EphemeralNoob (Ssid, PeerId, NoobId, Noob, Hoob, sent_time) VALUES (?, ?, ?, ?, ?, ?)'
    args = [ssid, peer_id, noob_id, noob, hoob, sent_time]

    exec_query(query, db_path_peer, args)

    # Insert the OOB data into the server database
    query = 'INSERT INTO EphemeralNoob (PeerId, NoobId, Noob, Hoob, sent_time) VALUES (?, ?, ?, ?, ?)'
    args = [peer_id, noob_id, noob, hoob, sent_time]

    exec_query(query, db_path_server, args)

    if direction == '1':
        print(f'Successfully transferred the out-of-band data in peer-to-server direction')
    else:
        print(f'Successfully transferred the out-of-band data in server-to-peer direction')

if __name__ == '__main__':
    direction = get_direction()
    peer = get_peers()
    transfer_oob(peer[0], peer[1], direction)
