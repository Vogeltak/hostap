#ifndef EAP_NOOB_SERVER_H
#define EAP_NOOB_SERVER_H

/* Configuration file */
#define CONF_FILE               "eapnoob.conf"

/* All the pre-processors of EAP-NOOB */

#define DB_NAME                 "/tmp/noob_server.db"
#define DEVICE_TABLE            "devices"

/* Unique server bitmasks to validate message structure.
 * Others are in the common header file */
#define SERVER_NAME_RCVD        0x0400
#define SERVER_URL_RCVD         0x0800
#define WE_COUNT_RCVD           0x2000
#define REALM_RCVD              0x4000
#define ENCODE_RCVD             0x8000

/* Bitmasks specifying expected parameters for each message */
#define TYPE_ONE_PARAMS         (PEERID_RCVD|VERSION_RCVD|CRYPTOSUITE_RCVD|DIR_RCVD|INFO_RCVD)
#define TYPE_TWO_PARAMS         (PEERID_RCVD|NONCE_RCVD|PKEY_RCVD)
#define TYPE_THREE_PARAMS       (PEERID_RCVD)
#define TYPE_FOUR_PARAMS        (PEERID_RCVD|MAC_RCVD)
#define TYPE_FIVE_PARAMS        (PEERID_RCVD|CRYPTOSUITE_RCVD|INFO_RCVD)
#define TYPE_SIX_PARAMS         (PEERID_RCVD|NONCE_RCVD)
#define TYPE_SEVEN_PARAMS       (PEERID_RCVD|MAC_RCVD)
#define TYPE_EIGHT_PARAMS       (PEERID_RCVD|NOOBID_RCVD)
#define CONF_PARAMS             (DIR_RCVD|CRYPTOSUITE_RCVD|VERSION_RCVD|SERVER_NAME_RCVD|SERVER_URL_RCVD|WE_COUNT_RCVD|REALM_RCVD|ENCODE_RCVD|MAX_OOB_RETRIES_RCVD)

/* Statements to create server database tables */
#define CREATE_TABLES_EPHEMERALSTATE                \
    "CREATE TABLE IF NOT EXISTS EphemeralState(     \
    PeerId TEXT PRIMARY KEY,                        \
    Verp INTEGER NOT NULL,                          \
    Cryptosuitep INTEGER NOT NULL,                  \
    Realm TEXT,                                     \
    Dirp INTEGER,                                   \
    PeerInfo TEXT,                                  \
    Ns BLOB,                                        \
    Np BLOB,                                        \
    Z BLOB,                                         \
    MacInput TEXT,                                  \
    CreationTime BIGINT,                            \
    ErrorCode INTEGER,                              \
    SleepCount INTEGER,                             \
    ServerState INTEGER,                            \
    JwkServer TEXT,                                 \
    JwkPeer TEXT,                                   \
    OobRetries INTEGER);                            \
                                                    \
    CREATE TABLE IF NOT EXISTS EphemeralNoob(       \
    PeerId TEXT NOT NULL REFERENCES EphemeralState(PeerId), \
    NoobId TEXT NOT NULL,                           \
    Noob TEXT NOT NULL,                             \
    Hoob TEXT NOT NULL,                             \
    sent_time BIGINT NOT NULL,                      \
    UNIQUE(Peerid,NoobId));"

#define CREATE_TABLES_PERSISTENTSTATE               \
    "CREATE TABLE IF NOT EXISTS PersistentState(    \
    PeerId TEXT NOT NULL PRIMARY KEY,               \
    Verp INTEGER NOT NULL CHECK (Verp=1),           \
    Cryptosuitep INTEGER NOT NULL,                  \
    Realm TEXT,                                     \
    Kz BLOB NOT NULL,                               \
    ServerState INT,                                \
    PeerInfo TEXT,                                  \
    CreationTime BIGINT,                            \
    last_used_time BIGINT);"

/* Statements for specific functions on the peer database */
#define DELETE_EPHEMERAL_FOR_PEERID                 \
    "DELETE FROM EphemeralNoob WHERE PeerId=?;      \
    DELETE FROM EphemeralState WHERE PeerId=?;"

#define DELETE_EPHEMERAL_FOR_ALL                    \
    "DELETE FROM EphemeralNoob;                     \
    DELETE FROM EphemeralState;"

#define QUERY_EPHEMERALSTATE                        \
    "SELECT * FROM EphemeralState WHERE PeerId=?;"

#define QUERY_EPHEMERALNOOB                         \
    "SELECT * FROM EphemeralNoob                    \
    WHERE PeerId=?;"//AND NoobId=?;"

#define QUERY_PERSISTENTSTATE                       \
    "SELECT * FROM PersistentState WHERE PeerId=?;"

enum {UPDATE_PERSISTENT_STATE, UPDATE_OOB_RETRIES, DELETE_EPHEMERAL, UPDATE_STATE_MINSLP, UPDATE_PERSISTENT_KEYS_SECRET, UPDATE_STATE_ERROR,
    UPDATE_INITIALEXCHANGE_INFO, GET_NOOBID};

struct eap_noob_global_conf {
    int read_conf;
    int max_we_count;
    char * realm;
    int len_realm;
    int oob_encode;
};

struct eap_noob_server_config_params {
    char * ServerName;
    char * ServerURL;
};

#endif
