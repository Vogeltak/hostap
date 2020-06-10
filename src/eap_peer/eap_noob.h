#ifndef EAP_NOOB_PEER_H
#define EAP_NOOB_PEER_H


/* Configuration file */
#define CONF_FILE               "eapnoob.conf"

/* All the pre-processors of EAP-NOOB */
#define DB_NAME                     "/tmp/noob_peer.db"

/* Unique peer bitmasks to validate message structure.
 * Others are in the common header file */
#define PEER_MAKE_RCVD              0x0400
#define PEER_ID_NUM_RCVD            0x0800
#define DEF_MIN_SLEEP_RCVD          0x2000
#define MSG_ENC_FMT_RCVD            0x4000
#define PEER_TYPE_RCVD              0x8000

/* Bitmasks specifying expected parameters for each message */
#define TYPE_TWO_PARAMS            (PEERID_RCVD|VERSION_RCVD|CRYPTOSUITE_RCVD|DIR_RCVD|INFO_RCVD)
#define TYPE_THREE_PARAMS          (PEERID_RCVD|NONCE_RCVD|PKEY_RCVD)
#define TYPE_FOUR_PARAMS           (PEERID_RCVD)
#define TYPE_FIVE_PARAMS           (PEERID_RCVD)
#define TYPE_SIX_PARAMS            (PEERID_RCVD|MAC_RCVD|NOOBID_RCVD)
#define TYPE_SEVEN_PARAMS          (PEERID_RCVD|VERSION_RCVD|CRYPTOSUITE_RCVD|INFO_RCVD)
#define TYPE_EIGHT_PARAMS          (PEERID_RCVD|NONCE_RCVD)
#define TYPE_NINE_PARAMS           (PEERID_RCVD|MAC_RCVD)
#define CONF_PARAMS                (DIR_RCVD|CRYPTOSUITE_RCVD|VERSION_RCVD|PEER_TYPE_RCVD|PEER_ID_NUM_RCVD|PEER_TYPE_RCVD|MAX_OOB_RETRIES_RCVD)

/* Statements to create peer database tables */
#define CREATE_TABLES_EPHEMERALSTATE                \
    "CREATE TABLE IF NOT EXISTS EphemeralState(     \
    Ssid TEXT PRIMARY KEY,                          \
    PeerId TEXT,                                    \
    Vers TEXT NOT NULL,                             \
    Cryptosuites TEXT NOT NULL,                     \
    Realm TEXT,                                     \
    Dirs INTEGER,                                   \
    ServerInfo TEXT,                                \
    Ns BLOB,                                        \
    Np BLOB,                                        \
    Z BLOB,                                         \
    MacInput TEXT,                                  \
    creation_time  BIGINT,                          \
    ErrorCode INT,                                  \
    PeerState INTEGER,                              \
    JwkServer TEXT,                                 \
    JwkPeer TEXT,                                   \
    OobRetries);                                    \
                                                    \
    CREATE TABLE IF NOT EXISTS EphemeralNoob(       \
    Ssid TEXT NOT NULL REFERENCES EphemeralState(Ssid), \
    PeerId TEXT NOT NULL,                           \
    NoobId TEXT NOT NULL,                           \
    Noob TEXT NOT NULL,                             \
    Hoob TEXT NOT NULL,                             \
    sent_time BIGINT NOT NULL,                      \
    UNIQUE(Peerid,NoobId));"

#define CREATE_TABLES_PERSISTENTSTATE               \
    "CREATE TABLE IF NOT EXISTS PersistentState(    \
    Ssid TEXT NOT NULL,                             \
    PeerId TEXT NOT NULL,                           \
    Verp INT NOT NULL,                              \
    Cryptosuitep INT NOT NULL,                      \
    CryptosuitepPrev INT,                           \
    Realm TEXT,                                     \
    Kz BLOB NOT NULL,                               \
    KzPrev BLOB,                                    \
    PeerState INT,                                  \
    creation_time BIGINT,                           \
    last_used_time BIGINT)"

/* Statements for specific functions on the peer database */
#define DELETE_EPHEMERAL_FOR_ALL                    \
    "DELETE FROM EphemeralNoob;                     \
    DELETE FROM EphemeralState;"

#define QUERY_EPHEMERALSTATE                        \
    "SELECT * FROM EphemeralState WHERE Ssid=?;"

#define QUERY_EPHEMERALNOOB                         \
    "SELECT * FROM EphemeralNoob WHERE Ssid=?;"

#define QUERY_PERSISTENTSTATE                       \
    "SELECT * FROM PersistentState WHERE Ssid=?;"

enum {UPDATE_PERSISTENT_STATE, UPDATE_OOB_RETRIES, UPDATE_STATE_ERROR, DELETE_SSID};

struct eap_noob_global_conf {
    u32 default_minsleep;
    u32 oob_enc_fmt;
    char * peer_type;
    u32 read_conf;
};

struct eap_noob_peer_config_params {
    char * Peer_name;
    char * Peer_ID_Num;
};

#endif
