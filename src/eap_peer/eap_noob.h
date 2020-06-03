#ifndef EAPOOB_H
#define EAPOOB_H


/* Configuration file */
#define CONF_FILE               "eapnoob.conf"

/* All the pre-processors of EAP-NOOB */
#define DB_NAME                     "/tmp/noob_peer.db"

/* MAX values for the fields */
#define MAX_SUP_VER             1
#define MAX_SUP_CSUITES         1

/* Bitmasks to validate message structure*/
#define PEERID_RCVD                 0x0001
#define DIRS_RCVD                   0x0002
#define CRYPTOSUITES_RCVD           0x0004
#define VERSION_RCVD                0x0008
#define NONCE_RCVD                  0x0010
#define MAC_RCVD                    0x0020
#define PKEY_RCVD                   0x0040
#define INFO_RCVD                   0x0080
#define STATE_RCVD                  0x0100
#define MINSLP_RCVD                 0x0200
#define PEER_MAKE_RCVD              0x0400
#define PEER_ID_NUM_RCVD            0x0800
#define HINT_RCVD                   0x1000
#define DEF_MIN_SLEEP_RCVD          0x2000
#define MSG_ENC_FMT_RCVD            0x4000
#define PEER_TYPE_RCVD              0x8000
#define MAX_OOB_RETRIES_RCVD       0x10000

/* Bitmasks specifying expected parameters for each message */
#define TYPE_ONE_PARAMS             (PEERID_RCVD|VERSION_RCVD|CRYPTOSUITES_RCVD|DIRS_RCVD|INFO_RCVD)
#define TYPE_TWO_PARAMS             (PEERID_RCVD|NONCE_RCVD|PKEY_RCVD)
#define TYPE_THREE_PARAMS           (PEERID_RCVD)
#define TYPE_FOUR_PARAMS            (PEERID_RCVD|MAC_RCVD|HINT_RCVD)
#define TYPE_FIVE_PARAMS            (PEERID_RCVD|CRYPTOSUITES_RCVD|INFO_RCVD)
#define TYPE_SIX_PARAMS             (PEERID_RCVD|NONCE_RCVD)
#define TYPE_SEVEN_PARAMS           (PEERID_RCVD|MAC_RCVD)
#define TYPE_HINT_PARAMS            (PEERID_RCVD)
#define CONF_PARAMS                 (DIRS_RCVD|CRYPTOSUITES_RCVD|VERSION_RCVD|PEER_TYPE_RCVD|PEER_ID_NUM_RCVD|PEER_TYPE_RCVD|MAX_OOB_RETRIES_RCVD)

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
