#ifndef EAP_NOOB_H
#define EAP_NOOB_H

/* Configuration file */
#define CONF_FILE               "eapnoob.conf"

/*
 * Pre-processors for EAP-NOOB
 */

#define DEFAULT_REALM           "eap-noob.net"
#define VERSION_ONE             1
#define SUITE_ONE               1
#define ALGORITHM_ID            "EAP-NOOB"
#define ALGORITHM_ID_LEN        8
#define MACS_TYPE               2
#define MACP_TYPE               1
#define FORMAT_BASE64URL        1

/* Maximum values for fields */
#define MAX_SUP_VER             3
#define MAX_SUP_CSUITES         10
#define MAX_CONF_LEN            500
#define MAX_INFO_LEN            500
#define MAX_PEER_ID_LEN         22
#define MAX_LINE_SIZE           1000
#define MAX_MAC_INPUT_LEN       1500
#define MAX_X25519_LEN          48
#define MAX_URL_LEN             60
#define MAX_QUERY_LEN           2048

#define NOOBID_LEN              16
#define NOOB_LEN                16
#define NONCE_LEN               32
#define ECDH_SHARED_SECRET_LEN  32
#define KDF_LEN                 320
#define MSK_LEN                 64
#define EMSK_LEN                64
#define AMSK_LEN                64
#define KZ_LEN                  32
#define KMS_LEN                 32
#define KMP_LEN                 32
#define MAC_LEN                 32
#define HASH_LEN                16
#define METHOD_ID_LEN           32

/* Common bitmasks to validate message structure */
#define PEERID_RCVD                 0x0001
#define DIR_RCVD                    0x0002
#define CRYPTOSUITE_RCVD            0x0004
#define VERSION_RCVD                0x0008
#define NONCE_RCVD                  0x0010
#define MAC_RCVD                    0x0020
#define PKEY_RCVD                   0x0040
#define INFO_RCVD                   0x0080
#define STATE_RCVD                  0x0100
#define MINSLP_RCVD                 0x0200
#define NOOBID_RCVD                 0x1000
#define MAX_OOB_RETRIES_RCVD       0x10000

/* Valid or invalid states */
#define INVALID                 0
#define VALID                   1
#define NUM_OF_STATES           5
#define MAX_MSG_TYPES           9

/* OOB direction */
#define PEER_TO_SERVER          1
#define SERVER_TO_PEER          2
#define BOTH_DIRECTIONS         3

#define SUCCESS                 1
#define FAILURE                 -1
#define EMPTY                   0
#define DONE                    1
#define NOT_DONE                0

/* Default maximum value for OOB retries */
#define DEFAULT_MAX_OOB_RETRIES 5

/* Maximum allowed waiting exchages */
#define MAX_WAIT_EXCHNG_TRIES   5

/* keywords for JSON encoding and decoding */
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
#define PKS2                    "PKs2"
#define SERVERINFO              "ServerInfo"
#define MACS                    "MACs"
#define MACS2                   "MACs2"
#define PEERINFO_SERIAL         "Serial"
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
#define PEER_SERIAL_NUM         "Serial"
#define PEER_SSID               "SSID"
#define PEER_BSSID              "BSSID"
#define PEER_TYPE               "Type"
#define PEER_MAKE               "Make"
#define KEYINGMODE              "KeyingMode"

/* TODO: explanatory comment */
#define ECDH_KDF_MAX            (1 << 30)

#define EAP_NOOB_FREE(_D)                           \
    if (_D) {                                       \
        os_free(_D);                                \
        (_D) = NULL;                                \
    }

/* Flag used during KDF and MAC generation */
// TODO: can these be replaced by the KeyingModes defined below?
enum {COMPLETION_EXCHANGE, RECONNECT_EXCHANGE, RECONNECT_EXCHANGE_NEW};

/* Keying modes, as defined in Table 3 of draft 8 */
enum {KEYING_COMPLETION_EXCHANGE,
    KEYING_RECONNECT_EXCHANGE_NO_ECDHE,
    KEYING_RECONNECT_EXCHANGE_ECDHE,
    KEYING_RECONNECT_EXCHANGE_NEW_CRYPTOSUITE};


/* EAP-NOOB states in which peer and server can reside */
enum {UNREGISTERED_STATE, WAITING_FOR_OOB_STATE, OOB_RECEIVED_STATE, RECONNECTING_STATE, REGISTERED_STATE};

/* Message types, see https://tools.ietf.org/html/draft-ietf-emu-eap-noob-01#section-4.2 */
// TODO: Update to latest draft, where type 9 is now type 1
enum {NONE, EAP_NOOB_TYPE_1, EAP_NOOB_TYPE_2, EAP_NOOB_TYPE_3, EAP_NOOB_TYPE_4, EAP_NOOB_TYPE_5,
    EAP_NOOB_TYPE_6, EAP_NOOB_TYPE_7, EAP_NOOB_TYPE_8, EAP_NOOB_TYPE_9};

enum eap_noob_err_code {NO_ERROR, E1001, E1002, E1003, E1004, E1007, E2001, E2002,
                        E2003, E2004, E3001, E3002, E3003, E4001, E5001, E5002, E5003, E5004};

enum sql_datatypes {TEXT, INT, UNSIGNED_BIG_INT, BLOB,};

// TODO: Merge all ECDH related data
// Or possibly make use of the structs specified in crypto.h

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
};

struct eap_noob_oob_data {
    char * Hoob_b64;
    char * Noob_b64;
    char * NoobId_b64;
    time_t sent_time;
};

struct eap_noob_ecdh_key_exchange {
    EVP_PKEY * dh_key;

    size_t x_len;
    char * x_b64;
    char * x_b64_remote;

    size_t y_len;
    char * y_b64;
    char * y_b64_remote;

    char * jwk_serv;
    char * jwk_peer;

    u8 * shared_key;
    size_t shared_key_b64_len;
    char * shared_key_b64;
};

struct eap_noob_data {
    u32 versions[MAX_SUP_VER];
    u32 version;
    u32 cryptosuites[MAX_SUP_CSUITES];
    u32 cryptosuite;
    u32 cryptosuite_prev;
    u32 dirs;
    u32 dirp;
    u32 sleeptime;
    u32 minsleep;
    u32 sleep_count;
    u32 keying_mode;

    u32 recv_msg;
    u32 rcvd_params;

    u32 oob_retries;
    u32 max_oob_retries;
    u32 oob_recv;

    u8 peer_state;
    u8 server_state;

    u8 next_req;
    u8 is_done;
    u8 is_success;

    char *peerid_rcvd;
    char *peerid;
    char *peer_info;
    char *server_info;
    char *realm;
    char *ssid;

    char *mac_input_str;
    char *mac;

    enum eap_noob_err_code err_code;

    time_t creation_time;
    time_t last_used_time;

    bool record_present;

    u8 *Kz;
    u8 *KzPrev;

    struct eap_noob_ecdh_key_exchange *ecdh_exchange_data;
    struct eap_noob_oob_data *oob_data;
    struct eap_noob_ecdh_kdf_nonce *kdf_nonce_data;
    struct eap_noob_ecdh_kdf_out *kdf_out;

    u32 config_params;
    struct eap_noob_server_config_params *server_config_params;
    struct eap_noob_peer_config_params *peer_config_params;

    sqlite3 *db;

    int wired;
};

/* Common data arrays */
extern const int error_code[];
extern const char *error_info[];
extern const int state_machine[][5];
extern const int next_request_type[];
extern const int state_message_check[NUM_OF_STATES][MAX_MSG_TYPES];

#define EAP_NOOB_STATE_VALID                                                              \
    (state_machine[data->server_state][data->peer_state] == VALID)   \

/* Common routines */
void eap_noob_set_error(struct eap_noob_data *data, int val);
int eap_noob_Base64Decode(const char *b64message, unsigned char **buffer);
int eap_noob_Base64Encode(const unsigned char *buffer, size_t length, char **b64text);
void json_token_to_string(struct wpabuf *json, struct json_token *token);
char * json_dump(struct json_token * token);
void eap_noob_verify_param_len(struct eap_noob_data * data);
void eap_noob_decode_obj(struct eap_noob_data * data, struct json_token * root);
int eap_noob_ECDH_KDF_X9_63(unsigned char *out, size_t outlen,
        const unsigned char * Z, size_t Zlen,
        const unsigned char * algorithm_id, size_t algorithm_id_len,
        const unsigned char * partyUinfo, size_t partyUinfo_len,
        const unsigned char * partyVinfo, size_t partyVinfo_len,
        const unsigned char * suppPrivinfo, size_t suppPrivinfo_len,
        const EVP_MD * md);
int eap_noob_gen_KDF(struct eap_noob_data * data, int state);
char * eap_noob_build_mac_input(const struct eap_noob_data * data,
                                       int first_param, int state);
u8 * eap_noob_gen_MAC(const struct eap_noob_data * data, int type, u8 * key, int keylen, int state);
int eap_noob_derive_secret(struct eap_noob_data * data, size_t * secret_len);
int eap_noob_db_statements(sqlite3 * db, const char * query);
int eap_noob_exec_query(struct eap_noob_data * data, const char * query,
                               void (*callback)(struct eap_noob_data *, sqlite3_stmt *),
                               int num_args, ...);
int eap_noob_ctxt_alloc(struct eap_noob_data * data);

#endif /* EAP_NOOB_H */
