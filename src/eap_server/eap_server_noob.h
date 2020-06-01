#ifndef EAPOOB_H
#define EAPOOB_H

/* Configuration file */
#define CONF_FILE               "eapnoob.conf"

/**
 * All the pre-processors of EAP-NOOB
 **/

#define RESERVED_DOMAIN         "eap-noob.net"
#define VERSION_ONE             1
#define SUITE_ONE               1
#define NOOBID_LEN              16
#define NOOB_LEN                16
#define NONCE_LEN               32
#define ECDH_SHARED_SECRET_LEN  32
#define ALGORITHM_ID            "EAP-NOOB"
#define ALGORITHM_ID_LEN        8
#define MACS_TYPE               2
#define MACP_TYPE               1

/* MAX values for fields */
#define MAX_SUP_VER             3
#define MAX_SUP_CSUITES         10
#define MAX_CONF_LEN            500
#define MAX_INFO_LEN            500
#define MAX_PEER_ID_LEN         22
#define MAX_LINE_SIZE           1000
#define MAX_MAC_INPUT_LEN       1500

#define KDF_LEN                 320
#define MSK_LEN                 64
#define EMSK_LEN                64
#define AMSK_LEN                64
#define KZ_LEN                  32
#define KMS_LEN                 32
#define KMP_LEN                 32
#define MAC_LEN                 32
#define MAX_X25519_LEN          48
#define HASH_LEN                16
#define METHOD_ID_LEN		    32

/* Valid or Invalid states */
#define INVALID                 0
#define VALID                   1
#define NUM_OF_STATES           5
#define MAX_MSG_TYPES           9

/* OOB DIRECTIONS */
#define PEER_TO_SERVER          1
#define SERVER_TO_PEER          2
#define BOTH_DIRECTIONS         3

#define SUCCESS                 1
#define FAILURE                 -1
#define EMPTY			0

#define DONE                    1
#define NOT_DONE                0

/* Default maximum value for OOB retries */
#define DEFAULT_MAX_OOB_RETRIES 5

/* Maximum allowed waiting exchages */
#define MAX_WAIT_EXCHNG_TRIES   5

/* Keying modes, as defined in Table 3 of draft 8 */
#define KEYING_COMPLETION_EXCHANGE 0
#define KEYING_RECONNECT_EXCHANGE_NO_ECDHE 1
#define KEYING_RECONNECT_EXCHANGE_ECDHE 2
#define KEYING_RECONNECT_EXCHANGE_NEW_CRYPTOSUITE 3

/* keywords for json encoding and decoding */
#define TYPE                    "Type"
#define ERRORINFO               "ErrorInfo"
#define ERRORCODE               "ErrorCode"
#define VERS                    "Vers"
#define CRYPTOSUITES            "Cryptosuites"
#define DIRS                    "Dirs"
#define NS                      "Ns"
#define NS2                     "Ns2"
#define SLEEPTIME               "SleepTime"
#define PEERID                  "PeerId"
#define PKS                     "PKs"
#define PKS2					"PKs2"
#define SERVERINFO              "ServerInfo"
#define MACS                    "MACs"
#define MACS2                   "MACs2"
#define PEERINFO_SERIAL         "Serial"
//#define PEERINFO_TYPE           "Type"
//#define PEERINFO_MAKE           "Make"
#define VERP                    "Verp"
#define CRYPTOSUITEP            "Cryptosuitep"
#define DIRP                    "Dirp"
#define NP                      "Np"
#define NP2                     "Np2"
#define PKP                     "PKp"
#define	PKP2                    "PKp2"
#define PEERINFO                "PeerInfo"
#define PEERSTATE               "PeerState"
#define NOOBID                  "NoobId"
#define MACP                    "MACp"
#define MACP2                   "MACp2"
#define X_COORDINATE            "x"
#define Y_COORDINATE            "y"
#define KEY_TYPE                "kty"
#define CURVE                   "crv"
#define REALM                   "Realm"
#define SERVERINFO_NAME         "Name"
#define SERVERINFO_URL          "Url"
#define KEYINGMODE              "KeyingMode"

#define ECDH_KDF_MAX            (1 << 30)

#define PEERID_RCVD             0x0001
#define DIRP_RCVD               0x0002
#define CRYPTOSUITEP_RCVD       0x0004
#define VERSION_RCVD            0x0008
#define NONCE_RCVD              0x0010
#define MAC_RCVD                0x0020
#define PKEY_RCVD               0x0040
#define INFO_RCVD               0x0080
#define STATE_RCVD              0x0100
#define MINSLP_RCVD             0x0200
#define SERVER_NAME_RCVD        0x0400
#define SERVER_URL_RCVD         0x0800
#define NOOBID_RCVD             0x1000
#define WE_COUNT_RCVD           0x2000
#define REALM_RCVD              0x4000
#define ENCODE_RCVD             0x8000
#define MAX_OOB_RETRIES_RCVD   0x10000

#define TYPE_ONE_PARAMS         (PEERID_RCVD|VERSION_RCVD|CRYPTOSUITEP_RCVD|DIRP_RCVD|INFO_RCVD)
#define TYPE_TWO_PARAMS         (PEERID_RCVD|NONCE_RCVD|PKEY_RCVD)
#define TYPE_THREE_PARAMS       (PEERID_RCVD)
#define TYPE_FOUR_PARAMS        (PEERID_RCVD|MAC_RCVD)
#define TYPE_FIVE_PARAMS        (PEERID_RCVD|CRYPTOSUITEP_RCVD|INFO_RCVD)
#define TYPE_SIX_PARAMS         (PEERID_RCVD|NONCE_RCVD)
#define TYPE_SEVEN_PARAMS       (PEERID_RCVD|MAC_RCVD)
#define TYPE_EIGHT_PARAMS       (PEERID_RCVD|NOOBID_RCVD)

#define CONF_PARAMS             (DIRP_RCVD|CRYPTOSUITEP_RCVD|VERSION_RCVD|SERVER_NAME_RCVD|SERVER_URL_RCVD|WE_COUNT_RCVD|REALM_RCVD|ENCODE_RCVD|MAX_OOB_RETRIES_RCVD)
#define DB_NAME                 "/tmp/noob_server.db"
#define DEVICE_TABLE            "devices"

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

#define EAP_NOOB_FREE(_D)                           \
    if (_D) {                                       \
        os_free(_D);                                \
        (_D) = NULL;                                \
    }

 /* Flag used during KDF and MAC generation */
enum {COMPLETION_EXCHANGE, RECONNECT_EXCHANGE, RECONNECT_EXCHANGE_NEW};

enum {UNREGISTERED_STATE, WAITING_FOR_OOB_STATE, OOB_RECEIVED_STATE, RECONNECTING_STATE, REGISTERED_STATE};

enum {NONE, EAP_NOOB_TYPE_1, EAP_NOOB_TYPE_2, EAP_NOOB_TYPE_3, EAP_NOOB_TYPE_4, EAP_NOOB_TYPE_5,
    EAP_NOOB_TYPE_6, EAP_NOOB_TYPE_7, EAP_NOOB_TYPE_8, EAP_NOOB_TYPE_9};

enum {UPDATE_PERSISTENT_STATE, UPDATE_OOB_RETRIES, DELETE_EPHEMERAL, UPDATE_STATE_MINSLP, UPDATE_PERSISTENT_KEYS_SECRET, UPDATE_STATE_ERROR,
    UPDATE_INITIALEXCHANGE_INFO, GET_NOOBID};

enum eap_noob_err_code {NO_ERROR, E1001, E1002, E1003, E1004, E1007, E2001, E2002,
                        E2003, E2004, E3001, E3002, E3003, E4001, E5001, E5002, E5003, E5004};

enum sql_datatypes {TEXT, INT, UNSIGNED_BIG_INT, BLOB,};

struct eap_noob_global_conf {
    int read_conf;
    int max_we_count;
    char * realm;
    int len_realm;
    int oob_encode;
};

struct eap_noob_ecdh_kdf_out {

    u8 * msk;
    u8 * emsk;
    u8 * amsk;
    u8 * MethodId;
    u8 * Kms;
    u8 * Kmp;
    u8 * Kz;
};

struct eap_noob_ecdh_kdf_nonce {
    u8 * Ns;
    u8 * Np;
    char * nonce_peer_b64; //Can be removed
};

struct eap_noob_oob_data {
    char * Hoob_b64;
    char * Noob_b64;
    char * NoobId_b64;
    time_t sent_time;
};

struct eap_noob_ecdh_key_exchange {
    EVP_PKEY * dh_key;

    char * x_peer_b64;
    char * y_peer_b64;

    char * x_b64;
    size_t x_len;
    char * y_b64;
    size_t y_len;

    char * jwk_serv;
    char * jwk_peer;

    u8 * shared_key;
    char * shared_key_b64;
    size_t shared_key_b64_len;
};

struct eap_noob_peer_data {

    u32 version;
    u32 cryptosuite;
    u32 dir;
    u32 sleeptime;
    u32 recv_msg;
    u32 rcvd_params;
    u32 sleep_count;
    u32 oob_retries;
    int oob_recv;

    u8 peer_state;
    u8 server_state;
    u8 next_req;
    u8 is_done;
    u8 is_success;

    char * peerid_rcvd;
    char * PeerId;
    char * peerinfo;
    char * peer_snum;  /* Only set, not used */
    char * mac;

    Boolean record_present;
    Boolean noobid_required;

    enum eap_noob_err_code err_code;

    time_t last_used_time;

    struct eap_noob_ecdh_key_exchange * ecdh_exchange_data;
    struct eap_noob_oob_data * oob_data;
    struct eap_noob_ecdh_kdf_nonce * kdf_nonce_data;
    struct eap_noob_ecdh_kdf_out * kdf_out;
    char * mac_input_str;

    char * Realm;
    u8 * Z;
    u8 * Ns;
    u8 * Np;
    u8 * Kz;
    time_t creation_time;
};

struct eap_noob_server_config_params {
    char * ServerName;
    char * ServerURL;
};

struct eap_noob_server_data {
    u32 version[MAX_SUP_VER];
    u32 cryptosuite[MAX_SUP_CSUITES];
    u32 dir;
    u32 keying_mode;
    char * server_info;
    u32 config_params;
    struct eap_noob_server_config_params * server_config_params;
    u32  max_oob_retries;
};

struct eap_noob_server_context {
    struct eap_noob_peer_data * peer_attr;
    struct eap_noob_server_data * server_attr;
    char * db_name;
    sqlite3 * server_db;
};

const int error_code[] =  {0,1001,1002,1003,1004,1007,2001,2002,2003,2004,3001,3002,3003,4001,5001,5002,5003,5004};

const char *error_info[] =  {
    "No error",
    "Invalid NAI",
    "Invalid message structure",
    "Invalid data",
    "Unexpected message type",
    "Invalid ECDHE key",
    "Unwanted peer",
    "State mismatch, user action required",
    "Unrecognized OOB message identifier",
    "Unexpected peer identifier",
    "No mutually supported protocol version",
    "No mutually supported cryptosuite",
    "No mutually supported OOB direction",
    "HMAC verification failure",
    "Application-specific error",
    "Invalid server info",
    "Invalid server URL",
    "Invalid peer info"};


/* This 2-D arry is used for state validation.
 * Cloumn number represents the state of Peer and the row number
 * represents the server state
 * The states are in squence as: {UNREGISTERED_STATE, WAITING_FOR_OOB_STATE,
 *  OOB_RECEIVED_STATE, RECONNECTING_STATE, REGISTERED_STATE}
 * for both peer and server */
const int state_machine[][5] = {
    {VALID, VALID,   VALID,   INVALID, INVALID},
    {VALID, VALID,   VALID,   INVALID, INVALID},
    {VALID, VALID,   VALID,   INVALID, INVALID},
    {VALID, INVALID, INVALID, VALID,   VALID},
    {VALID, INVALID, INVALID, VALID,   INVALID}
};

const int next_request_type[] = {
    EAP_NOOB_TYPE_1, EAP_NOOB_TYPE_1, EAP_NOOB_TYPE_1, NONE,            NONE,
    EAP_NOOB_TYPE_1, EAP_NOOB_TYPE_3, EAP_NOOB_TYPE_4, NONE,            NONE,
    EAP_NOOB_TYPE_1, EAP_NOOB_TYPE_4, EAP_NOOB_TYPE_4, NONE,            NONE,
    EAP_NOOB_TYPE_1, NONE,            NONE,            EAP_NOOB_TYPE_5, EAP_NOOB_TYPE_5,
    EAP_NOOB_TYPE_1, NONE,            NONE,            EAP_NOOB_TYPE_5, NONE
};


/*server state vs message type matrix*/
const int state_message_check[NUM_OF_STATES][MAX_MSG_TYPES] = {
    {VALID, VALID,   VALID,   INVALID,  INVALID,  INVALID,  INVALID,  INVALID, VALID}, //UNREGISTERED_STATE
    {VALID, VALID,   VALID,   VALID,    VALID,    INVALID,  INVALID,  INVALID, VALID}, //WAITING_FOR_OOB_STATE
    {VALID, VALID,   VALID,   INVALID,  VALID,    INVALID,  INVALID,  INVALID, VALID}, //OOB_RECEIVED_STATE
    {VALID, INVALID, INVALID, INVALID,  INVALID,  VALID,    VALID,    VALID,   VALID},   //RECONNECT
    {VALID, INVALID, INVALID, INVALID,  VALID,    INVALID,  INVALID,  INVALID, VALID}, //REGISTERED_STATE
};

#define EAP_NOOB_STATE_VALID                                                              \
    (state_machine[data->peer_attr->server_state][data->peer_attr->peer_state]  == VALID)   \

#endif
