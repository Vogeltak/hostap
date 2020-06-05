/*
 * EAP-NOOB common routines
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <base64.h>
#include <sqlite3.h>
#include "common.h"
#include "json.h"
#include "eap_noob_common.h"

/* Common data arrays */
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
 * Column number represents the state of Peer and the row number
 * represents the server state
 * The states are in squence as: {UNREGISTERED_STATE, WAITING_FOR_OOB_STATE,
 * OOB_RECEIVED_STATE, RECONNECTING_STATE, REGISTERED_STATE}
 * for both peer and server */
const int state_machine[][5] = {
    {VALID, VALID,   VALID,   INVALID, INVALID},
    {VALID, VALID,   VALID,   INVALID, INVALID},
    {VALID, VALID,   VALID,   INVALID, INVALID},
    {VALID, INVALID, INVALID, VALID,   VALID},
    {VALID, INVALID, INVALID, VALID,   INVALID}
};

// TODO: Update to latest draft (type 9 -> type 1)
const int next_request_type[] = {
    EAP_NOOB_TYPE_1, EAP_NOOB_TYPE_1, EAP_NOOB_TYPE_1, NONE,            NONE,
    EAP_NOOB_TYPE_1, EAP_NOOB_TYPE_3, EAP_NOOB_TYPE_4, NONE,            NONE,
    EAP_NOOB_TYPE_1, EAP_NOOB_TYPE_4, EAP_NOOB_TYPE_4, NONE,            NONE,
    EAP_NOOB_TYPE_1, NONE,            NONE,            EAP_NOOB_TYPE_5, EAP_NOOB_TYPE_5,
    EAP_NOOB_TYPE_1, NONE,            NONE,            EAP_NOOB_TYPE_5, NONE
};

/*server state vs message type matrix*/
// TODO: Update to latest draft (type 9 -> type 1)
const int state_message_check[NUM_OF_STATES][MAX_MSG_TYPES] = {
    {VALID, VALID,   VALID,   INVALID,  INVALID,  INVALID,  INVALID,  INVALID, VALID}, //UNREGISTERED_STATE
    {VALID, VALID,   VALID,   VALID,    VALID,    INVALID,  INVALID,  INVALID, VALID}, //WAITING_FOR_OOB_STATE
    {VALID, VALID,   VALID,   INVALID,  VALID,    INVALID,  INVALID,  INVALID, VALID}, //OOB_RECEIVED_STATE
    {VALID, INVALID, INVALID, INVALID,  INVALID,  VALID,    VALID,    VALID,   VALID},   //RECONNECT
    {VALID, INVALID, INVALID, INVALID,  VALID,    INVALID,  INVALID,  INVALID, VALID}, //REGISTERED_STATE
};

void eap_noob_set_error(struct eap_noob_data *data, int val)
{
    data->next_req = NONE;
    data->err_code = val;
}

/*
 * eap_noob_Base64Decode : Decodes a base64url string.
 * @b64message : input base64url string
 * @buffer : output
 * Returns : Len of decoded string
**/
int eap_noob_Base64Decode(const char * b64message, unsigned char ** buffer)
{
    fprintf(stderr, "ENTER B64DECODE FUN\n");
    size_t len = os_strlen(b64message);
    size_t b64pad = 4*((len + 3)/4) - len;
    char *temp = os_zalloc(len + b64pad + 1);
    if (temp == NULL)
        return -1;
    os_memcpy(temp, b64message, len);
    for(int i = 0; i < len; i++) {
        if (temp[i] == '-')
            temp[i] = '+';
        else if (temp[i] == '_')
            temp[i] = '/';
    }
    for(int i = 0; i < b64pad; i++)
        temp[len + i] = '=';
    size_t decodeLen;
    unsigned char *tempX;
    tempX = base64_decode(temp, len + b64pad, &decodeLen);
    if (tempX == NULL)
        return -1;
    *buffer = os_zalloc(decodeLen + 1);
    memcpy(*buffer, tempX, decodeLen);
    return decodeLen;
}

/**
 * eap_noob_Base64Encode : Encode an ascii string to base64url. Dealloc b64text
 * as needed from the caller.
 * @buffer : input buffer
 * @length : input buffer length
 * @b64text : converted base64url text
 * Returns : SUCCESS/FAILURE
 **/
int eap_noob_Base64Encode(const unsigned char * buffer, size_t length, char ** b64text)
{
    size_t len = 0;
    char *tmp;
    tmp = base64_encode(buffer, length, &len);
    if (tmp == NULL)
        return -1;
    for(int i = 0; i < len; i++) {
        if (tmp[i] == '+')
            tmp[i] = '-';
        else if (tmp[i] == '/')
            tmp[i] = '_';
        else if (tmp[i] == '=') {
            tmp[i] = '\0';
            len = i;
            break;
        }
    }

    *b64text = os_zalloc(len);
    if (*b64text == NULL)
        return -1;
    os_memcpy(*b64text, tmp, len);

    return SUCCESS;
}

/**
 * Dump a json token to a string.
 * @json: output buffer to write the json string to
 * @token: the json_token to dump
 */
void json_token_to_string(struct wpabuf * json, struct json_token * token)
{
    struct json_token * sibling = token;
    int element_nr = 0;

    while (sibling) {
        // Insert a value separator when this is not the first element
        if (element_nr) {
            json_value_sep(json);
        }

        switch (sibling->type) {
            case JSON_OBJECT:
                json_start_object(json, sibling->name);
                json_token_to_string(json, sibling->child);
                json_end_object(json);
                break;
            case JSON_ARRAY:
                json_start_array(json, sibling->name);
                struct json_token * child = sibling->child;
                int i = 0;
                while (child) {
                    // Assume we are only dealing with arrays containing numbers or strings

                    /*if (child->type == JSON_OBJECT || child->type == JSON_ARRAY) {
                        struct wpabuf * child_json = wpabuf_alloc(wpabuf_size(json));
                        if (!child_json) continue;

                        json_token_to_string(child_json, child);
                        char * child_str = strndup(wpabuf_head(child_json), wpabuf_len(child_json));
                        printf("Generated child string: %s\n", child_str);

                        wpabuf_printf(json, "%s%s", i ? "," : "", child_str);

                        wpabuf_free(child_json);
                        os_free(child_str);
                    }*/
                    if (child->type == JSON_STRING) {
                        wpabuf_printf(json, "%s\"%s\"", i ? "," : "", child->string);
                    } else if (child->type == JSON_NUMBER) {
                        wpabuf_printf(json, "%s%u", i ? "," : "", child->number);
                    }

                    child = child->sibling;
                    i++;
                }
                json_end_array(json);
                break;
            case JSON_STRING:
                json_add_string(json, sibling->name, sibling->string);
                break;
            case JSON_NUMBER:
                json_add_int(json, sibling->name, sibling->number);
                break;
            default:
                ;
        }

        // When converting to string, do not include siblings of the root token.
        // This function assumes that the root token is either an object or an
        // array, and that the caller wishes to only dump _this_ token to a string.
        // Thus, if the type is something else, it means that we are *inside*
        // the root, and therefore we want to loop over all children.
        if (sibling->type != JSON_OBJECT && sibling->type != JSON_ARRAY) {
            sibling = sibling->sibling;
        } else {
            sibling = NULL;
        }
        element_nr++;
    }
}

/**
 * Wrapper function that dumps a json_token to a string.
 * @token: the token to be dumped
 * Returns: a string representation of the token
 */
char * json_dump(struct json_token * token)
{
    struct wpabuf * dump = wpabuf_alloc(10000);
    if (!dump) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory in %s", __func__);
        return NULL;
    }

    json_token_to_string(dump, token);

    char * str = strndup(wpabuf_head(dump), wpabuf_len(dump));

    wpabuf_free(dump);

    return str;
}

/**
 * eap_noob_verify_param_len : verify lengths of string type parameters
 * @data : noob data
 **/
void eap_noob_verify_param_len(struct eap_noob_data * data)
{
    u32 count  = 0;
    u32 pos = 0x01;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    for (count  = 0; count < 32; count++) {
        if (data->rcvd_params & pos) {
            switch(pos) {
                case PEERID_RCVD:
                    if (strlen(data->peerid_rcvd) > MAX_PEER_ID_LEN) {
                        eap_noob_set_error(data, E1003);
                    }
                    break;
                case NONCE_RCVD:
                    if (data->kdf_nonce_data->Np && strlen((char *)data->kdf_nonce_data->Np) > NONCE_LEN) {
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Np is too long");
                        eap_noob_set_error(data, E1003);
                    }
                    if (data->kdf_nonce_data->Ns && strlen((char *)data->kdf_nonce_data->Ns) > NONCE_LEN) {
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Ns is too long");
                        eap_noob_set_error(data, E1003);
                    }
                    break;
                case MAC_RCVD:
                    if (strlen(data->mac) > MAC_LEN) {
                        eap_noob_set_error(data, E1003);
                    }
                    break;
                case INFO_RCVD:
                    if (strlen(data->peer_info) > MAX_INFO_LEN) {
                        eap_noob_set_error(data, E5004);
                    }
                    if (strlen(data->server_info) > MAX_INFO_LEN) {
                        eap_noob_set_error(data, E5002);
                    }
                    break;
                default:
                    ;
            }
        }
        pos = pos<<1;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s", __func__);
}

/**
 * eap_noob_decode_obj : Decode parameters from incoming messages
 * @data : noob data
 * @root : incoming json object with message parameters
**/
void eap_noob_decode_obj(struct eap_noob_data * data, struct json_token * root)
{
    struct json_token * child = NULL;
    char * key = NULL;
    struct json_token * el = NULL;
    char * val_str = NULL;
    int val_int;

    if (!data || !root) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        goto EXIT;
    }

    if (root->type != JSON_OBJECT) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Request data does not have a JSON object as root");
        goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    // Loop over all children of the JSON root object
    child = root->child;
    while (child) {
        key = child->name;

        switch (child->type) {
            case JSON_OBJECT:
                // PKp or PKp2
                if (!os_strcmp(key, PKP) || !os_strcmp(key, PKP2) ||
                    !os_strcmp(key, PKS) || !os_strcmp(key, PKS2)) {
                    struct json_token * child_copy;
                    memcpy(&child_copy, &child, sizeof(child));
                    if (!child_copy) {
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error while copying json_token");
                        goto EXIT;
                    }

                    // Exclude name of the new root object from the JSON dump
                    child_copy->name = NULL;

                    // Public keys of the server and peer are stored in different
                    // fields of eap_noob_data.
                    if (!os_strcmp(key, PKP) || !os_strcmp(key, PKP2)) {
                        data->ecdh_exchange_data->jwk_peer = json_dump(child_copy);
                        if (!data->ecdh_exchange_data->jwk_peer) {
                            data->err_code = E1003;
                            goto EXIT;
                        }
                    } else {
                        data->ecdh_exchange_data->jwk_serv = json_dump(child_copy);
                        if (!data->ecdh_exchange_data->jwk_serv) {
                            data->err_code = E1003;
                            goto EXIT;
                        }
                    }

                    // Also decode the contents of the public key object
                    // for later use.
                    eap_noob_decode_obj(data, child);

                    data->rcvd_params |= PKEY_RCVD;
                }
                // PeerInfo
                else if (!os_strcmp(key, PEERINFO) || !os_strcmp(key, SERVERINFO)) {
                    struct json_token * child_copy;
                    memcpy(&child_copy, &child, sizeof(child));
                    if (!child_copy) {
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error while copying json_token");
                        goto EXIT;
                    }

                    // Exclude name of the new root object from the JSON dump
                    child_copy->name = NULL;

                    // Retrieve string and store it in the appropriate field
                    if (!os_strcmp(key, PEERINFO)) {
                        data->peer_info = json_dump(child_copy);
                    } else {
                        data->server_info = json_dump(child_copy);
                    }

                    // Free intermediate variable
                    json_free(child_copy);

                    data->rcvd_params |= INFO_RCVD;
                }
                break;
            case JSON_ARRAY:
                // Vers
                if (!os_strcmp(key, VERS)) {
                    el = child->child;
                    int i = 0;

                    while (el) {
                        data->versions[i] = el->number;
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Version array value = %d",
                                data->versions[i]);
                        el = el->sibling;
                        i++;
                    }

                    data->rcvd_params |= VERSION_RCVD;
                }
                // Cryptosuites
                else if (!os_strcmp(key, CRYPTOSUITES)) {
                    el = child->child;
                    int i = 0;

                    while (el) {
                        data->cryptosuites[i] = el->number;
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Cryptosuites array value = %d",
                                data->cryptosuites[i]);
                        el = el->sibling;
                        i++;
                    }
                     data->rcvd_params |= CRYPTOSUITE_RCVD;
                }
                break;
            case JSON_STRING:
                val_str = child->string;
                if (!val_str) {
                    data->err_code = E1003;
                    goto EXIT;
                }

                // PeerId
                if (!os_strcmp(key, PEERID)) {
                    data->peerid_rcvd = os_strdup(val_str);
                    data->rcvd_params |= PEERID_RCVD;
                }
                // Realm
                else if (!os_strcmp(key, REALM)) {
                    EAP_NOOB_FREE(data->realm);
                    data->realm = os_strdup(val_str);
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Realm %s", data->realm);
                }
                // Ns or Ns2
                else if (!os_strcmp(key, NS) || !os_strcmp(key, NS2)) {
                    size_t decode_len = eap_noob_Base64Decode(val_str, &data->kdf_nonce_data->Ns);
                    if (decode_len) {
                        data->rcvd_params |= NONCE_RCVD;
                    }
                }
                // Np or Np2
                else if (!os_strcmp(key, NP) || !os_strcmp(key, NP2)) {
                    size_t decode_len = eap_noob_Base64Decode(val_str, &data->kdf_nonce_data->Np);
                    if (decode_len) {
                        data->rcvd_params |= NONCE_RCVD;
                    }
                }
                // NoobId
                else if (!os_strcmp(key, NOOBID)) {
                    data->oob_data->NoobId_b64 = os_strdup(val_str);
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Received NoobId = %s", data->oob_data->NoobId_b64);
                    data->rcvd_params |= NOOBID_RCVD;
                }
                // MACs or MACs2
                else if (!os_strcmp(key, MACS) || !os_strcmp(key, MACS2)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Received MAC %s", val_str);
                    size_t decode_len = eap_noob_Base64Decode((char *) val_str, (u8 **) &data->mac);
                    if (decode_len) {
                        data->rcvd_params |= MAC_RCVD;
                    }
                }
                // MACp or MACp2
                else if (!os_strcmp(key, MACP) || !os_strcmp(key, MACP2)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Received MAC %s", val_str);
                    size_t decode_len = eap_noob_Base64Decode((char *) val_str, (u8 **) &data->mac);
                    if (decode_len) {
                        data->rcvd_params |= MAC_RCVD;
                    }
                }
                // x
                else if (!os_strcmp(key, X_COORDINATE)) {
                    data->ecdh_exchange_data->x_b64_remote = os_strdup(val_str);
                    wpa_printf(MSG_DEBUG, "X coordinate %s", data->ecdh_exchange_data->x_b64_remote);
                }
                // y
                else if (!os_strcmp(key, Y_COORDINATE)) {
                    data->ecdh_exchange_data->y_b64_remote = os_strdup(val_str);
                    wpa_printf(MSG_DEBUG, "Y coordinate %s", data->ecdh_exchange_data->y_b64_remote);
                }
                break;
            case JSON_NUMBER:
                val_int = child->number;
                if (!val_int && os_strcmp(key, TYPE) && os_strcmp(key, SLEEPTIME)
                    && os_strcmp(key, PEERSTATE)) {
                    data->err_code = E1003;
                    goto EXIT;
                }
                // PeerState
                if (!os_strcmp(key, PEERSTATE)) {
                    data->peer_state = val_int;
                    data->rcvd_params |= STATE_RCVD;
                }
                // Dirp
                else if (!os_strcmp(key, DIRP)) {
                    data->dirp = val_int;
                    data->rcvd_params |= DIR_RCVD;
                }
                // Dirs
                else if (!os_strcmp(key, DIRS)) {
                    data->dirs = val_int;
                    data->rcvd_params |= DIR_RCVD;
                }
                // Verp
                else if (!os_strcmp(key, VERP)) {
                    data->version = val_int;
                    data->rcvd_params |= VERSION_RCVD;
                }
                // Cryptosuitep
                else if (!os_strcmp(key, CRYPTOSUITEP)) {
                    data->cryptosuite = val_int;
                    data->rcvd_params |= CRYPTOSUITE_RCVD;
                }
                // SleepTime
                else if (!os_strcmp(key, SLEEPTIME)) {
                    data->minsleep = val_int;
                    //data->rcvd_params |= MINSLP_RCVD;
                }
                // KeyingMode
                else if (!os_strcmp(key, KEYINGMODE)) {
                    data->keying_mode = val_int;
                }
                // ErrorCode
                else if (!os_strcmp(key, ERRORCODE)) {
                    data->err_code = val_int;
                }
                break;
            default:
                ;
        }

        // Done handling this child,
        // now update the reference to the next child of the JSON root object
        child = child->sibling;
    }

    eap_noob_verify_param_len(data);
EXIT:
    os_free(val_str);
    json_free(child);
    json_free(el);
    EAP_NOOB_FREE(key);
    return;
}

/**
 *eap_noob_ECDH_KDF_X9_63: generates KDF
 *@out:
 *@outlen:
 * Z:
 * Zlen:
 * alorithm_id:
 * alorithm_id_len:
 * partyUinfo:
 * partyUinfo_len:
 * partyVinfo:
 * partyVinfo_len
 * suppPrivinfo:
 * suppPrivinfo_len:
 * EVP_MD:
 * Returns:
**/
int eap_noob_ECDH_KDF_X9_63(unsigned char *out, size_t outlen,
        const unsigned char * Z, size_t Zlen,
        const unsigned char * algorithm_id, size_t algorithm_id_len,
        const unsigned char * partyUinfo, size_t partyUinfo_len,
        const unsigned char * partyVinfo, size_t partyVinfo_len,
        const unsigned char * suppPrivinfo, size_t suppPrivinfo_len,
        const EVP_MD * md)
{
    EVP_MD_CTX * mctx = NULL;
    unsigned char ctr[4] = {0};
    unsigned int i = 0;
    size_t mdlen = 0;
    int rv = 0;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: KDF start");
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Value:", Z, Zlen);

    if (algorithm_id_len > ECDH_KDF_MAX || outlen > ECDH_KDF_MAX ||
        Zlen > ECDH_KDF_MAX || partyUinfo_len > ECDH_KDF_MAX ||
        partyVinfo_len > ECDH_KDF_MAX || suppPrivinfo_len > ECDH_KDF_MAX)
        return 0;

    mctx = EVP_MD_CTX_create();
    if (mctx == NULL)
        return 0;

    mdlen = EVP_MD_size(md);
    wpa_printf(MSG_DEBUG,"EAP-NOOB: KDF begin %d", (int)mdlen);
    for (i = 1;; i++) {
        unsigned char mtmp[EVP_MAX_MD_SIZE];
        EVP_DigestInit_ex(mctx, md, NULL);
        ctr[3] = (i & 0xFF);
        ctr[2] = ((i >> 8) & 0xFF);
        ctr[1] = ((i >> 16) & 0xFF);
        ctr[0] = (i >> 24);
        if (!EVP_DigestUpdate(mctx, ctr, sizeof(ctr)))
            goto err;
        if (!EVP_DigestUpdate(mctx, Z, Zlen))
            goto err;
        if (!EVP_DigestUpdate(mctx, algorithm_id, algorithm_id_len))
            goto err;
        if (!EVP_DigestUpdate(mctx, partyUinfo, partyUinfo_len))
            goto err;
        if (!EVP_DigestUpdate(mctx, partyVinfo, partyVinfo_len))
            goto err;

        if (suppPrivinfo != NULL)
            if (!EVP_DigestUpdate(mctx, suppPrivinfo, suppPrivinfo_len))
                goto err;

        if (outlen >= mdlen) {
            if (!EVP_DigestFinal(mctx, out, NULL))
                goto err;
            outlen -= mdlen;
            if (outlen == 0)
                break;
            out += mdlen;
        } else {
            if (!EVP_DigestFinal(mctx, mtmp, NULL))
                goto err;
            memcpy(out, mtmp, outlen);
            OPENSSL_cleanse(mtmp, mdlen);
            break;
        }
    }
    rv = 1;
err:
    wpa_printf(MSG_DEBUG,"EAP-NOOB:KDF finished %d",rv);
    EVP_MD_CTX_destroy(mctx);
    return rv;
}

/**
 * eap_noob_gen_KDF : generates and updates the KDF inside the peer data.
 * @data  : peer data.
 * @state : EAP_NOOB state
 * Returns:
**/
int eap_noob_gen_KDF(struct eap_noob_data * data, int state)
{
    const EVP_MD * md = EVP_sha256();
    unsigned char * out = os_zalloc(KDF_LEN);
    int counter = 0, len = 0;
    u8 * Noob;

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Algorith ID:", ALGORITHM_ID,ALGORITHM_ID_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce_Peer", data->kdf_nonce_data->Np,
                      NONCE_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce_Serv", data->kdf_nonce_data->Ns,
                      NONCE_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Shared Key", data->ecdh_exchange_data->shared_key,
                      ECDH_SHARED_SECRET_LEN);
    if (state == COMPLETION_EXCHANGE) {
        len = eap_noob_Base64Decode(data->oob_data->Noob_b64, &Noob);
        if (len != NOOB_LEN) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode Noob");
            return FAILURE;
        }
        wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Noob", Noob, NOOB_LEN);
        eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
                data->ecdh_exchange_data->shared_key, ECDH_SHARED_SECRET_LEN,
                (unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
                data->kdf_nonce_data->Np, NONCE_LEN,
                data->kdf_nonce_data->Ns, NONCE_LEN,
                Noob, NOOB_LEN, md);
    } else {

        wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: kz", data->Kz,KZ_LEN);
        eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
                data->Kz, KZ_LEN,
                (unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
                data->kdf_nonce_data->Np, NONCE_LEN,
                data->kdf_nonce_data->Ns, NONCE_LEN,
                NULL, 0, md);
    }
    wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: KDF",out,KDF_LEN);

    if (out != NULL) {
        data->kdf_out->msk = os_zalloc(MSK_LEN);
        data->kdf_out->emsk = os_zalloc(EMSK_LEN);
        data->kdf_out->amsk = os_zalloc(AMSK_LEN);
        data->kdf_out->MethodId = os_zalloc(METHOD_ID_LEN);
        data->kdf_out->Kms = os_zalloc(KMS_LEN);
        data->kdf_out->Kmp = os_zalloc(KMP_LEN);
        data->kdf_out->Kz = os_zalloc(KZ_LEN);

        memcpy(data->kdf_out->msk,out,MSK_LEN);
        counter += MSK_LEN;
        memcpy(data->kdf_out->emsk, out + counter, EMSK_LEN);
        counter += EMSK_LEN;
        memcpy(data->kdf_out->amsk, out + counter, AMSK_LEN);
        counter += AMSK_LEN;
        memcpy(data->kdf_out->MethodId, out + counter, METHOD_ID_LEN);
        counter += METHOD_ID_LEN;
        memcpy(data->kdf_out->Kms, out + counter, KMS_LEN);
        counter += KMS_LEN;
        memcpy(data->kdf_out->Kmp, out + counter, KMP_LEN);
        counter += KMP_LEN;
        memcpy(data->kdf_out->Kz, out + counter, KZ_LEN);

        // Save for later use in the reconnect exchange.
        if(state == COMPLETION_EXCHANGE) {
            data->Kz = os_zalloc(KZ_LEN);
            memcpy(data->Kz, out + counter, KZ_LEN);
        }
        counter += KZ_LEN;
    } else {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in allocating memory, %s", __func__);
        return FAILURE;
    }
    return SUCCESS;
}

/**
 * Construct a JSON array string of all input data for a MAC.
 * @data: peer data that contains all required data
 * @first_param: either the type of MAC or the Direction, necessary for MAC or Hoob respectively
 * @state: the current state
 */
char * eap_noob_build_mac_input(const struct eap_noob_data * data,
                                       int first_param, int state)
{
    struct wpabuf * mac_json;
    char * nonce;

    // Allocate memory to the JSON string to be built
    mac_json = wpabuf_alloc(MAX_MAC_INPUT_LEN);
    if (!mac_json) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for MAC JSON");
        return NULL;
    }

    // Build the MAC input string from all components as specified in draft 8
    // https://tools.ietf.org/html/draft-ietf-emu-eap-noob-00
    json_start_array(mac_json, NULL);

    // Integer that either indicates the MAC type (MACs = 2, MACp = 1)
    // or the direction of OOB data (peer-to-server = 1, server-to-peer = 2)
    // See section 3.3.2. Message data fields of the latest draft:
    // https://tools.ietf.org/html/draft-ietf-emu-eap-noob-00
    if (first_param == 1 || first_param == 2) {
        wpabuf_printf(mac_json, "%u", first_param);
    } else {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: MAC type or Direction was not 1 or 2 in %s", __func__);
        return NULL;
    }

    // Versions supported by server
    json_value_sep(mac_json);
    json_start_array(mac_json, NULL);
    for (int i = 0; i < MAX_SUP_VER; i++) {
        if (data->versions[i] > 0)
            wpabuf_printf(mac_json, "%s%u", i ? "," : "", data->versions[i]);
    }
    json_end_array(mac_json);

    // Version chosen by peer
    wpabuf_printf(mac_json, ",%u", data->version);

    // PeerId assigned by the server to the peer
    wpabuf_printf(mac_json, ",\"%s\"", data->peerid);

    // Cryptosuites supported by the server
    json_value_sep(mac_json);
    json_start_array(mac_json, NULL);
    for (int i = 0; i < MAX_SUP_CSUITES; i++) {
        if (data->cryptosuites[i] > 0)
            wpabuf_printf(mac_json, "%s%u", i ? "," : "", data->cryptosuites[i]);
    }
    json_end_array(mac_json);

    // Direction supported by the server
    if (state == RECONNECTING_STATE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%u", data->dirs);
    }

    // Server info object
    if (state == RECONNECTING_STATE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%s", data->server_info);
    }

    // Cryptosuite chosen by peer
    wpabuf_printf(mac_json, ",%u", data->cryptosuite);

    // Direction supported by the peer
    if (state == RECONNECTING_STATE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%u", data->dirp);
    }

    // If the Realm is specified, include it
    // Otherwise, insert an empty string
    if (data->realm) {
        wpabuf_printf(mac_json, ",\"%s\"", data->realm);
    } else {
        wpabuf_printf(mac_json, ",\"\"");
    }

    // Peer info object
    if (state == RECONNECTING_STATE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%s", data->peer_info);
    }

    // KeyingMode
    if (state == RECONNECTING_STATE) {
        wpabuf_printf(mac_json, ",%u", data->keying_mode);
    } else {
        wpabuf_printf(mac_json, ",0");
    }

    // Public key server
    if (state == RECONNECTING_STATE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%s", data->ecdh_exchange_data->jwk_serv);
    }

    // Server nonce
    eap_noob_Base64Encode(data->kdf_nonce_data->Ns, NONCE_LEN, &nonce);
    wpabuf_printf(mac_json, ",\"%s\"", nonce);

    // Public key peer
    if (state == RECONNECTING_STATE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%s", data->ecdh_exchange_data->jwk_peer);
    }

    // Peer nonce
    eap_noob_Base64Encode(data->kdf_nonce_data->Np, NONCE_LEN, &nonce);
    wpabuf_printf(mac_json, ",\"%s\"", nonce);

    // Nonce out of band
    if (state == RECONNECTING_STATE || !data->oob_data->Noob_b64) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",\"%s\"", data->oob_data->Noob_b64);
    }

    json_end_array(mac_json);

    // Dump to string
    char * res = strndup(wpabuf_head(mac_json), wpabuf_len(mac_json));
    if (!res) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to copy MAC input string");
        return NULL;
    }

    wpabuf_free(mac_json);
    os_free(nonce);

    return res;
}

/**
 * eap_noob_gen_MAC : generate an HMAC for user authentication.
 * @data : peer data
 * type  : MAC type
 * @key  : key to generate MAC
 * @keylen: key length
 * Returns : MAC on success or NULL on error.
 **/
u8 * eap_noob_gen_MAC(const struct eap_noob_data * data, int type, u8 * key, int keylen, int state)
{
    u8 * mac = NULL;
    char * mac_input;

    // TODO: Verify that all required information exists

    // Build the MAC input string and store it
    mac_input = eap_noob_build_mac_input(data, type, state);

    // Calculate MAC
    mac = HMAC(EVP_sha256(), key, keylen,
            (u8 *) mac_input,
            os_strlen(mac_input), NULL, NULL);

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Generated MAC", mac, MAC_LEN);

    return mac;
}

int eap_noob_derive_secret(struct eap_noob_data * data, size_t * secret_len)
{
    EVP_PKEY_CTX * ctx = NULL;
    EVP_PKEY * serverkey = NULL;
    unsigned char * server_pub_key  = NULL;
    size_t skeylen = 0, len = 0;
    int ret = SUCCESS;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering function %s", __func__);
    if (NULL == data || NULL == secret_len) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context is NULL");
        return FAILURE;
    }
    EAP_NOOB_FREE(data->ecdh_exchange_data->shared_key);
    len = eap_noob_Base64Decode(data->ecdh_exchange_data->x_b64_remote, &server_pub_key);
    if (len == 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode");
        ret = FAILURE; goto EXIT;
    }

    serverkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_pub_key, len);

    ctx = EVP_PKEY_CTX_new(data->ecdh_exchange_data->dh_key, NULL);
    if (!ctx) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to create context");
        ret = FAILURE; goto EXIT;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to init key derivation");
        ret = FAILURE; goto EXIT;
    }

    if (EVP_PKEY_derive_set_peer(ctx, serverkey) <= 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to set peer key");
        ret = FAILURE; goto EXIT;
    }

    if (EVP_PKEY_derive(ctx, NULL, &skeylen) <= 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to get secret key len");
        ret = FAILURE; goto EXIT;
    }

    data->ecdh_exchange_data->shared_key  = OPENSSL_malloc(skeylen);

    if (!data->ecdh_exchange_data->shared_key) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for secret");
        ret = FAILURE; goto EXIT;
    }

    if (EVP_PKEY_derive(ctx, data->ecdh_exchange_data->shared_key, &skeylen) <= 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to derive secret key");
        ret = FAILURE; goto EXIT;
    }

    (*secret_len) = skeylen;

    wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Secret Derived",
            data->ecdh_exchange_data->shared_key, *secret_len);

EXIT:
    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    EAP_NOOB_FREE(server_pub_key);

    if (ret != SUCCESS)
        EAP_NOOB_FREE(data->ecdh_exchange_data->shared_key);

    return ret;
}

/**
 * eap_noob_db_statements : execute one or more sql statements that do not return rows
 * @db : open sqlite3 database handle
 * @query : query to be executed
 * Returns  :  SUCCESS/FAILURE
 **/
int eap_noob_db_statements(sqlite3 * db, const char * query)
{
    int nByte = os_strlen(query);
    sqlite3_stmt * stmt;
    const char * tail = query;
    const char * sql_error;
    int ret = SUCCESS;

    if (NULL == db || NULL == query) return FAILURE;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);

    /* Loop through multiple SQL statements in sqlite3 */
    while (tail < query + nByte) {
        if (SQLITE_OK != sqlite3_prepare_v2(db, tail, -1, &stmt, &tail)
            || NULL == stmt) {
            ret = FAILURE; goto EXIT; }
        if (SQLITE_DONE != sqlite3_step(stmt)) {
            ret = FAILURE; goto EXIT; }
    }
EXIT:
    if (ret == FAILURE) {
        sql_error = sqlite3_errmsg(db);
        if (sql_error != NULL)
            wpa_printf(MSG_DEBUG,"EAP-NOOB: SQL error : %s", sql_error);
    }
    if (stmt) sqlite3_finalize(stmt);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, ret %d",__func__, ret);
    return ret;
}

/**
 * eap_noob_exec_query : Function to execute a sql query. Prepapres, binds and steps.
 * Takes variable number of arguments (TYPE, VAL). For Blob, (TYPE, LEN, VAL)
 * @data : Noob data
 * @query : query to be executed
 * @callback : pointer to callback function
 * @num_args : number of variable inputs to function
 * Returns  :  SUCCESS/FAILURE
 **/
int eap_noob_exec_query(struct eap_noob_data * data, const char * query,
                               void (*callback)(struct eap_noob_data *, sqlite3_stmt *),
                               int num_args, ...)
{
    sqlite3_stmt * stmt = NULL;
    va_list args;
    int ret, i, indx = 0, ival, bval_len;
    char * sval = NULL;
    u8 * bval = NULL;
    u64 bival;
    int query_type=0;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s, query - (%s), Number of arguments (%d)", __func__, query, num_args);

    if(os_strstr(query,"SELECT"))
        query_type=1;

    if (SQLITE_OK != (ret = sqlite3_prepare_v2(data->db, query, strlen(query)+1, &stmt, NULL))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error preparing statement, ret (%d)", ret);
        ret = FAILURE; goto EXIT;
    }

    va_start(args, num_args);

    for (i = 0; i < num_args; i+=2, ++indx) {
        enum sql_datatypes type = va_arg(args, enum sql_datatypes);
        switch(type) {
            case INT:
                ival = va_arg(args, int);
                printf("exec_query int %d, indx %d\n", ival, indx+1);
                if (SQLITE_OK != sqlite3_bind_int(stmt, (indx+1), ival)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Error binding %d at index %d", ival, i+1);
                    ret = FAILURE; goto EXIT;
                }
                break;
            case UNSIGNED_BIG_INT:
                bival = va_arg(args, u64);
                if (SQLITE_OK != sqlite3_bind_int64(stmt, (indx+1), bival)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Error binding %lu at index %d", bival, i+1);
                    ret = FAILURE; goto EXIT;
                }
                break;
            case TEXT:
                sval = va_arg(args, char *);
                printf("exec_query string %s, indx %d\n", sval, indx+1);
                if (SQLITE_OK != sqlite3_bind_text(stmt, (indx+1), sval, strlen(sval), NULL)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB:Error binding %s at index %d", sval, i+1);
                    ret = FAILURE; goto EXIT;
                }
                break;
            case BLOB:
                bval_len = va_arg(args, int);
                bval = va_arg(args, u8 *);
                if (SQLITE_OK != sqlite3_bind_blob(stmt, (indx+1), (void *)bval, bval_len, NULL)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Error binding %.*s at index %d", bval_len, bval, indx+1);
                    ret = FAILURE; goto EXIT;
                } i++;
                break;
            default:
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Wrong data type");
                ret = FAILURE; goto EXIT;
        }
    }
    i=0;
    while(1) {
        ret = sqlite3_step(stmt);
        if (ret == SQLITE_DONE) {
            if(i==0 && query_type==1){
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Done executing SELECT query that returned 0 rows, ret (%d)\n", ret);
                ret = EMPTY; break;
            }
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Done executing the query, ret (%d)\n", ret);
            ret = SUCCESS; break;
        } else if (ret != SQLITE_ROW) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Unexpected error in step, ret (%d)", ret);
            ret = FAILURE; goto EXIT;
        }
        i++;
        if (NULL != callback) {
            callback(data, stmt);
        }
    }

EXIT:
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, ret %d", __func__, ret);
    if (ret == FAILURE) {
        char * sql_error = (char *)sqlite3_errmsg(data->db);
        if (sql_error != NULL)
            wpa_printf(MSG_DEBUG,"EAP-NOOB: SQL error : %s\n", sql_error);
    }
    va_end(args);
    sqlite3_finalize(stmt);
    return ret;
}

/**
 * eap_noob_ctxt_alloc : Allocates the data structs for EAP-NOOB
 * @peer : noob data
 * Returns : SUCCESS/FAILURE
 **/
int eap_noob_ctxt_alloc(struct eap_noob_data * data)
{
    if (!data) return FAILURE;

    if ((NULL == (data->oob_data = \
           os_zalloc(sizeof (struct eap_noob_oob_data))))) {
        return FAILURE;
    }

    if ((NULL == (data->ecdh_exchange_data = \
           os_zalloc(sizeof (struct eap_noob_ecdh_key_exchange))))) {
        return FAILURE;
    }

    if ((NULL == (data->kdf_nonce_data = \
           os_zalloc(sizeof (struct eap_noob_ecdh_kdf_nonce))))) {
        return FAILURE;
    }

    if ((NULL == (data->kdf_out = \
           os_zalloc(sizeof (struct eap_noob_ecdh_kdf_out))))) {
        return FAILURE;
    }

    return SUCCESS;
}
