/*
 * EAP server method: EAP-NOOB
 *  Copyright (c) 2016, Aalto University
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of the Aalto University nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL AALTO UNIVERSITY BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  See CONTRIBUTORS for more information.
 */

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

//#include "utils/base64.c"
#include <stdint.h>
#include <unistd.h>
#include <sqlite3.h>
#include <time.h>
#include "utils/base64.c"
#include "includes.h"
#include "common.h"
#include "json.h"
#include "crypto/crypto.h"
#include "eap_i.h"
#include "eap_server_noob.h"

static struct eap_noob_global_conf server_conf;

static inline void eap_noob_set_done(struct eap_noob_server_context * data, int val)
{
    data->peer_attr->is_done = val;
}

static inline void eap_noob_set_success(struct eap_noob_server_context * data, int val)
{
    data->peer_attr->is_success = val;
}

static inline void eap_noob_set_error(struct eap_noob_peer_data * peer_attr, int val)
{
    peer_attr->next_req = NONE;
    peer_attr->err_code = val;
}

static inline void eap_noob_change_state(struct eap_noob_server_context * data, int val)
{
    data->peer_attr->server_state = val;
}

/**
 * eap_noob_verify_peerId : Compares recived PeerId with the assigned one
 * @data : server context
 * @return : SUCCESS or FAILURE
 **/
static int eap_noob_verify_peerId(struct eap_noob_server_context * data)
{
    if (NULL == data || NULL == data->peer_attr) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context null in %s", __func__);
        return FAILURE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
    if (0 != strcmp(data->peer_attr->PeerId, data->peer_attr->peerid_rcvd)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Verification of PeerId failed, setting error E2004");
        eap_noob_set_error(data->peer_attr, E2004); return FAILURE;
    }
    return SUCCESS;
}

/**
 * eap_noob_Base64Decode : Decodes a base64url string.
 * @b64message : input base64url string
 * @buffer : output
 * Returns : Len of decoded string
**/
static int eap_noob_Base64Decode(const char * b64message, unsigned char ** buffer)
{
    fprintf(stderr, "ENTER B64DECODE FUN\n");
    size_t len = os_strlen(b64message);
    size_t b64pad = 4*((len + 3)/4) - len;
    unsigned char *temp = os_zalloc(len + b64pad + 1);
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
    unsigned char *tmp;
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
 * eap_noob_db_statements : execute one or more sql statements that do not return rows
 * @db : open sqlite3 database handle
 * @query : query to be executed
 * Returns  :  SUCCESS/FAILURE
 **/
static int eap_noob_db_statements(sqlite3 * db, const char * query)
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
    /* if (stmt) */ sqlite3_finalize(stmt);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, ret %d",__func__, ret);
    return ret;
}


static void columns_persistentstate(struct eap_noob_server_context * data, sqlite3_stmt * stmt)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB: In %s", __func__);
    data->peer_attr->version = sqlite3_column_int(stmt, 1);
    data->peer_attr->cryptosuite = sqlite3_column_int(stmt, 2);
    data->peer_attr->Realm = os_strdup((char *) sqlite3_column_text(stmt, 3));
    data->peer_attr->Kz = os_memdup(sqlite3_column_blob(stmt, 4), KZ_LEN);
    data->peer_attr->server_state = sqlite3_column_int(stmt, 5);
    data->peer_attr->creation_time = (uint64_t) sqlite3_column_int64(stmt, 6);
    data->peer_attr->last_used_time = (uint64_t) sqlite3_column_int64(stmt, 7);
}

static void columns_ephemeralstate(struct eap_noob_server_context * data, sqlite3_stmt * stmt)
{
    data->peer_attr->version = sqlite3_column_int(stmt, 1);
    data->peer_attr->cryptosuite = sqlite3_column_int(stmt, 2);
    data->peer_attr->Realm = os_strdup((char *) sqlite3_column_text(stmt, 3));
    data->peer_attr->dir = sqlite3_column_int(stmt, 4);
    data->peer_attr->peerinfo = os_strdup((char *) sqlite3_column_text(stmt, 5));
    data->peer_attr->kdf_nonce_data->Ns = os_memdup(sqlite3_column_blob(stmt, 6), NONCE_LEN);
    data->peer_attr->kdf_nonce_data->Np = os_memdup(sqlite3_column_blob(stmt, 7), NONCE_LEN);
    data->peer_attr->ecdh_exchange_data->shared_key = os_memdup(sqlite3_column_blob(stmt, 8), ECDH_SHARED_SECRET_LEN);
    data->peer_attr->mac_input_str = os_strdup((char *) sqlite3_column_text(stmt, 9));
    data->peer_attr->creation_time = (uint64_t) sqlite3_column_int64(stmt, 10);
    data->peer_attr->err_code = sqlite3_column_int(stmt, 11);
    data->peer_attr->sleep_count = sqlite3_column_int(stmt, 12);
    data->peer_attr->server_state = sqlite3_column_int(stmt, 13);
    data->peer_attr->ecdh_exchange_data->jwk_serv = os_strdup((char *) sqlite3_column_text(stmt, 14));
    data->peer_attr->ecdh_exchange_data->jwk_peer = os_strdup((char *) sqlite3_column_text(stmt, 15));
    data->peer_attr->oob_retries = sqlite3_column_int(stmt, 16);
}

static void columns_ephemeralnoob(struct eap_noob_server_context * data, sqlite3_stmt * stmt)
{
    data->peer_attr->oob_data->NoobId_b64 = os_strdup((char *)sqlite3_column_text(stmt, 1));
    data->peer_attr->oob_data->Noob_b64 = os_strdup((char *)sqlite3_column_text(stmt, 2));
    data->peer_attr->oob_data->Hoob_b64 = os_strdup((char *) sqlite3_column_text(stmt, 3));
    data->peer_attr->oob_data->sent_time = (uint64_t) sqlite3_column_int64(stmt, 4);
}

/**
 * eap_noob_exec_query : Function to execute a sql query. Prepapres, binds and steps.
 * Takes variable number of arguments (TYPE, VAL). For Blob, (TYPE, LEN, VAL)
 * @data : Server context
 * @query : query to be executed
 * @callback : pointer to callback function
 * @num_args : number of variable inputs to function
 * Returns  :  SUCCESS/FAILURE
 **/
static int eap_noob_exec_query(struct eap_noob_server_context * data, const char * query,
                               void (*callback)(struct eap_noob_server_context *, sqlite3_stmt *),
                               int num_args, ...)
{
    sqlite3_stmt * stmt = NULL;
    va_list args;
    int ret, i, indx = 0, ival, bval_len;
    char * sval = NULL;
    u8 * bval = NULL;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s, query - (%s), Number of arguments (%d)", __func__, query, num_args);
    if (SQLITE_OK != (ret = sqlite3_prepare_v2(data->server_db, query, strlen(query)+1, &stmt, NULL))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error preparing statement, ret (%d)", ret);
        ret = FAILURE; goto EXIT;
    }

    va_start(args, num_args);

    for (i = 0; i < num_args; i+=2, ++indx) {
        enum sql_datatypes type = va_arg(args, enum sql_datatypes);
        switch(type) {
            case INT:
                ival = va_arg(args, int);
                if (SQLITE_OK != sqlite3_bind_int(stmt, (indx+1), ival)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Error binding %d at index %d", ival, i+1);
                    ret = FAILURE; goto EXIT;
                }
                break;
            case UNSIGNED_BIG_INT: /* TODO */
                break;
            case TEXT:
                sval = va_arg(args, char *);
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

    while(1) {
        ret = sqlite3_step(stmt);
        if (ret == SQLITE_DONE) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Done executing the query, ret (%d)\n", ret);
            ret = SUCCESS; break;
        } else if (ret != SQLITE_ROW) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Unexpected error in step, ret (%d)", ret);
            ret = FAILURE; goto EXIT;
        }
        if (NULL != callback) callback(data, stmt);
    }

EXIT:
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, ret %d", __func__, ret);
    if (ret == FAILURE) {
        char * sql_error = (char *)sqlite3_errmsg(data->server_db);
        if (sql_error != NULL)
            wpa_printf(MSG_DEBUG,"EAP-NOOB: SQL error : %s\n", sql_error);
    }
    va_end(args);
    sqlite3_finalize(stmt);
    return ret;
}

/**
 * eap_noob_db_functions : Execute various DB queries
 * @data : server context
 * @type : type of update
 * Returns : SUCCESS/FAILURE
 **/
static int eap_noob_db_functions(struct eap_noob_server_context * data, u8 type)
{
    char query[MAX_LINE_SIZE] = {0};
    char * dump_str = NULL;
    int ret = FAILURE;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context is NULL"); return FAILURE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);
    switch(type) {
        case UPDATE_PERSISTENT_STATE:
            os_snprintf(query, MAX_LINE_SIZE, "UPDATE PersistentState SET ServerState=? where PeerId=?");
            ret = eap_noob_exec_query(data, query, NULL, 4, INT, data->peer_attr->server_state,
                  TEXT, data->peer_attr->PeerId);
            break;
        case UPDATE_STATE_ERROR:
            os_snprintf(query, MAX_LINE_SIZE, "UPDATE EphemeralState SET ServerState=?, ErrorCode=? where PeerId=?");
            ret = eap_noob_exec_query(data, query, NULL, 6, INT, data->peer_attr->server_state, INT,
                  data->peer_attr->err_code, TEXT, data->peer_attr->PeerId);
            break;
        case UPDATE_OOB_RETRIES:
            os_snprintf(query, MAX_LINE_SIZE, "UPDATE EphemeralState SET OobRetries=? WHERE PeerId=?");
            ret = eap_noob_exec_query(data, query, NULL, 4, INT, data->peer_attr->oob_retries,
                                      TEXT, data->peer_attr->PeerId);
            break;
        case DELETE_EPHEMERAL:
            os_snprintf(query, MAX_LINE_SIZE, "DELETE FROM EphemeralState WHERE PeerId=?");
            ret = eap_noob_exec_query(data, query, NULL, 2, TEXT, data->peer_attr->PeerId);

            os_snprintf(query, MAX_LINE_SIZE, "DELETE FROM EphemeralNoob WHERE PeerId=?");
            ret &= eap_noob_exec_query(data, query, NULL, 2, TEXT, data->peer_attr->PeerId);
            break;
        case UPDATE_STATE_MINSLP:
            os_snprintf(query, MAX_LINE_SIZE, "UPDATE EphemeralState SET ServerState=?, SleepCount =? where PeerId=?");
            ret = eap_noob_exec_query(data, query, NULL, 6, INT, data->peer_attr->server_state, INT,
                  data->peer_attr->sleep_count, TEXT, data->peer_attr->PeerId);
            break;
        case UPDATE_PERSISTENT_KEYS_SECRET:
            os_snprintf(query, MAX_LINE_SIZE, "DELETE FROM EphemeralState WHERE PeerId=?");
            if (FAILURE == eap_noob_exec_query(data, query, NULL, 2, TEXT, data->peer_attr->PeerId))
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Unexpected error in deleting entry in EphemeralState");
            os_snprintf(query, MAX_LINE_SIZE, "DELETE FROM EphemeralNoob WHERE PeerId=?");
            if (FAILURE == eap_noob_exec_query(data, query, NULL, 2, TEXT, data->peer_attr->PeerId))
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Unexpected error in deleting entry in EphemeralNoob");
            os_snprintf(query, MAX_LINE_SIZE, "INSERT INTO PersistentState (PeerId, Verp, Cryptosuitep, Realm, Kz, "
                    "ServerState, PeerInfo) VALUES(?, ?, ?, ?, ?, ?, ?)");
            ret = eap_noob_exec_query(data, query, NULL, 14, TEXT, data->peer_attr->PeerId, INT, data->peer_attr->version,
                  INT, data->peer_attr->cryptosuite, TEXT, server_conf.realm, BLOB, KZ_LEN, data->peer_attr->kdf_out->Kz, INT,
                  data->peer_attr->server_state, TEXT, data->peer_attr->peerinfo);
            break;
        case UPDATE_INITIALEXCHANGE_INFO:
            os_snprintf(query, MAX_LINE_SIZE, "INSERT INTO EphemeralState ( PeerId, Verp, Cryptosuitep, Realm, Dirp, PeerInfo, "
                  "Ns, Np, Z, MacInput, SleepCount, ServerState, JwkServer, JwkPeer, OobRetries) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            ret = eap_noob_exec_query(data, query, NULL, 33, TEXT, data->peer_attr->PeerId, INT, data->peer_attr->version,
                  INT, data->peer_attr->cryptosuite, TEXT, server_conf.realm, INT, data->peer_attr->dir, TEXT,
                  data->peer_attr->peerinfo, BLOB, NONCE_LEN, data->peer_attr->kdf_nonce_data->Ns, BLOB, NONCE_LEN,
                  data->peer_attr->kdf_nonce_data->Np, BLOB, ECDH_SHARED_SECRET_LEN, data->peer_attr->ecdh_exchange_data->shared_key,
                  TEXT, data->peer_attr->mac_input_str, INT, data->peer_attr->sleep_count, INT, data->peer_attr->server_state,
                  TEXT, data->peer_attr->ecdh_exchange_data->jwk_serv, TEXT, data->peer_attr->ecdh_exchange_data->jwk_peer, INT, 0);
            os_free(dump_str);
            break;
        case GET_NOOBID:
            os_snprintf(query, MAX_LINE_SIZE, "SELECT * FROM EphemeralNoob WHERE PeerId=? AND NoobId=?;");
            ret = eap_noob_exec_query(data, query, columns_ephemeralnoob, 4, TEXT, data->peer_attr->PeerId, TEXT,
                  data->peer_attr->oob_data->NoobId_b64);
            break;
        default:
            wpa_printf(MSG_ERROR, "EAP-NOOB: Wrong DB update type");
            return FAILURE;
    }

    if (FAILURE == ret) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: DB value update failed");
        return FAILURE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, ret = SUCCESS", __func__);
    return SUCCESS;
}

/**
 * eap_noob_get_next_req :
 * @data :
 * Returns : NONE or next req type
 **/
static int eap_noob_get_next_req(struct eap_noob_server_context * data)
{
    int retval = NONE;
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context is NULL");
        return retval;
    }
    if (EAP_NOOB_STATE_VALID) {
        retval = next_request_type[(data->peer_attr->server_state * NUM_OF_STATES) \
                 + data->peer_attr->peer_state];
    }
    wpa_printf (MSG_DEBUG,"EAP-NOOB:Serv state = %d, Peer state = %d, Next req =%d",
                data->peer_attr->server_state, data->peer_attr->peer_state, retval);
    if (retval == EAP_NOOB_TYPE_5) {
        data->peer_attr->server_state = RECONNECTING_STATE;
        if (FAILURE == eap_noob_db_functions(data, UPDATE_PERSISTENT_STATE))
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Error updating state to Reconnecting");
    }

    if ((data->peer_attr->dir == SERVER_TO_PEER)  && (retval == EAP_NOOB_TYPE_4)) {
        retval = EAP_NOOB_TYPE_8;
        wpa_printf(MSG_DEBUG,"EAP-NOOB: NoobId Required: True");
    }

    if (retval == EAP_NOOB_TYPE_3) { //checking for max WE count if type is 3
        if (server_conf.max_we_count <= data->peer_attr->sleep_count) {
            eap_noob_set_error(data->peer_attr, E2001); return NONE;
        } else {
            data->peer_attr->sleep_count++;
            if (FAILURE == eap_noob_db_functions(data, UPDATE_STATE_MINSLP)) {
                wpa_printf(MSG_DEBUG,"EAP-NOOB: Min Sleep DB update Error");
                eap_noob_set_error(data->peer_attr,E2001); return NONE;
            }
        }
    }
    return retval;
}

/**
 * eap_noob_parse_NAI: Parse NAI
 * @data : server context
 * @NAI  : Network Access Identifier
 * Returns : FAILURE/SUCCESS
 **/
static int eap_noob_parse_NAI(struct eap_noob_server_context * data, const char * NAI)
{
    char * user_name_peer = NULL;
    char * realm = NULL;
    char * _NAI = NULL;

    if (NULL == NAI || NULL == data) {
        eap_noob_set_error(data->peer_attr, E1001); return FAILURE;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s, parsing NAI (%s)",__func__, NAI);

    _NAI = (char *)NAI;

    if (os_strstr(_NAI, RESERVED_DOMAIN) || os_strstr(_NAI, server_conf.realm)) {
        user_name_peer = strsep(&_NAI, "@");
        realm = strsep(&_NAI, "@");

        if (strlen(user_name_peer) > MAX_PEER_ID_LEN) {
            eap_noob_set_error(data->peer_attr,E1001);
            return FAILURE;
        }

        // If user part of the NAI is not equal to "noob", the NAI is invalid
        if (strcmp("noob", user_name_peer)) {
			eap_noob_set_error(data->peer_attr, E1001);
			return FAILURE;
		}

        // TODO: This if-else block is unnecessary, taking into account all
        // previously conducted tests.
        if (0 == strcmp(realm, server_conf.realm)) {
            return SUCCESS;
        } else if (0 == strcmp("noob", user_name_peer) && 0 == strcmp(realm, RESERVED_DOMAIN)) {
            data->peer_attr->peer_state = UNREGISTERED_STATE;
            return SUCCESS;
        }
    }

    // NAI realm is neither the RESERVED_DOMAIN nor the configured realm
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, setting error E1001",__func__);
    eap_noob_set_error(data->peer_attr, E1001);
    return FAILURE;
}

static int eap_noob_query_ephemeralstate(struct eap_noob_server_context * data)
{
    if (FAILURE == eap_noob_exec_query(data, QUERY_EPHEMERALSTATE, columns_ephemeralstate, 2,
                   TEXT, data->peer_attr->peerid_rcvd)) {
        wpa_printf(MSG_DEBUG, "Peer not found in ephemeral table");
        if (FAILURE == eap_noob_exec_query(data, QUERY_PERSISTENTSTATE, columns_persistentstate, 2,
                   TEXT, data->peer_attr->peerid_rcvd)) {
            eap_noob_set_error(data->peer_attr, E2004); /* Unexpected peerId */
            return FAILURE;
        } else {
            eap_noob_set_error(data->peer_attr, E1001); /* Invalid NAI or peer state */
            return FAILURE;
        }
    }

    if (data->peer_attr->server_state == OOB_RECEIVED_STATE) {
        if (FAILURE == eap_noob_exec_query(data, QUERY_EPHEMERALNOOB, columns_ephemeralnoob, 2,
                TEXT, data->peer_attr->peerid_rcvd)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in retreiving NoobId");
            return FAILURE;
        }
        wpa_printf(MSG_DEBUG, "EAP-NOOB: PeerId %s", data->peer_attr->peerid_rcvd);
    }
    return SUCCESS;
}

static int eap_noob_query_persistentstate(struct eap_noob_server_context * data)
{
    if (FAILURE == eap_noob_exec_query(data, QUERY_PERSISTENTSTATE, columns_persistentstate, 2,
                   TEXT, data->peer_attr->peerid_rcvd)) {
        if (FAILURE == eap_noob_exec_query(data, QUERY_EPHEMERALSTATE, columns_ephemeralstate, 2,
                    TEXT, data->peer_attr->peerid_rcvd)) {
            eap_noob_set_error(data->peer_attr, E2004);
            return FAILURE;
        } else {
            eap_noob_set_error(data->peer_attr, E1001);
            return FAILURE;
        }
    }
    return SUCCESS;
}

/**
 * eap_noob_create_db : Creates a new DB or opens the existing DB and
 *                      populates the context
 * @data : server context
 * returns : SUCCESS/FAILURE
 **/
static int eap_noob_create_db(struct eap_noob_server_context * data)
{
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return FAILURE;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
    if (SQLITE_OK != sqlite3_open_v2(data->db_name, &data->server_db,
                SQLITE_OPEN_READWRITE| SQLITE_OPEN_CREATE, NULL)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to open and Create Table");
        return FAILURE;
    }

    if (FAILURE == eap_noob_db_statements(data->server_db, CREATE_TABLES_EPHEMERALSTATE) ||
        FAILURE == eap_noob_db_statements(data->server_db, CREATE_TABLES_PERSISTENTSTATE)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Unexpected error in table creation");
        return FAILURE;
    }
    /* Based on peer_state, decide which table to query */
    if (data->peer_attr->peerid_rcvd) {
        data->peer_attr->PeerId = os_strdup(data->peer_attr->peerid_rcvd);
        if (data->peer_attr->peer_state <= OOB_RECEIVED_STATE)
            return eap_noob_query_ephemeralstate(data);
        else
            return eap_noob_query_persistentstate(data);
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s",__func__);
    return SUCCESS;
}

/**
 * eap_noob_assign_config:
 * @conf_name :
 * @conf_value :
 * @data : server context
 **/
static void eap_noob_assign_config(char * conf_name, char * conf_value, struct eap_noob_server_data * data)
{
    if (NULL == conf_name || NULL == conf_value || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return;
    }

    /*TODO : version and csuite are directly converted to integer.
     * This needs to be changed if more than one csuite or version is supported. */
    wpa_printf(MSG_DEBUG, "EAP-NOOB: CONF Name = %s %d", conf_name, (int)strlen(conf_name));
    if (0 == strcmp("Version", conf_name)) {
        data->version[0] = (int) strtol(conf_value, NULL, 10); data->config_params |= VERSION_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d", data->version[0]);
    }
    else if (0 == strcmp("Csuite",conf_name)) {
        data->cryptosuite[0] = (int) strtol(conf_value, NULL, 10); data->config_params |= CRYPTOSUITEP_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d", data->cryptosuite[0]);
    }
    else if (0 == strcmp("OobDirs",conf_name)) {
        data->dir = (int) strtol(conf_value, NULL, 10); data->config_params |= DIRP_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d", data->dir);
    }
    else if (0 == strcmp("ServerName", conf_name)) {
        data->server_config_params->ServerName = os_strdup(conf_value); data->config_params |= SERVER_NAME_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s\n", data->server_config_params->ServerName);
    }
    else if (0 == strcmp("ServerUrl", conf_name)) {
        data->server_config_params->ServerURL = os_strdup(conf_value); data->config_params |= SERVER_URL_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s", data->server_config_params->ServerURL);
    }
    else if (0 == strcmp("OobRetries", conf_name)) {
        data->max_oob_retries = (int) strtol(conf_value, NULL, 10);
        data->config_params |= MAX_OOB_RETRIES_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE READ= %d", data->max_oob_retries);
    }
    else if (0 == strcmp("Max_WE", conf_name)) {
        server_conf.max_we_count = (int) strtol(conf_value, NULL, 10);
        data->config_params |= WE_COUNT_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d", server_conf.max_we_count);
        /* assign some default value if user has given wrong value */
        if (server_conf.max_we_count == 0) server_conf.max_we_count = MAX_WAIT_EXCHNG_TRIES;
    }
    else if (0 == strcmp("Realm", conf_name)) {
        EAP_NOOB_FREE(server_conf.realm);
        server_conf.len_realm = strlen(conf_value);
        server_conf.realm = (char *) os_strdup(conf_value);
        data->config_params |= REALM_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s", server_conf.realm);
    }
    else if (0 == strcmp("OobMessageEncoding", conf_name)) {
        server_conf.oob_encode = (int) strtol(conf_value, NULL, 10);
        data->config_params |= ENCODE_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d", server_conf.oob_encode);
    }
}

/**
 * eap_noob_parse_config : parse each line from the config file
 * @buff : read line
 * @data :
 * data : server_context
**/
static void eap_noob_parse_config(char * buff, struct eap_noob_server_data * data)
{
    char * pos = NULL, * conf_name = NULL, * conf_value = NULL, * token = NULL;
    if (NULL == buff || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__); return;
    }

    pos = buff; server_conf.read_conf = 1;
    for (; *pos == ' ' || *pos == '\t' ; pos++);
    if (*pos == '#') return;

    if (os_strstr(pos, "=")) {
        conf_name = strsep(&pos, "=");
        /* handle if there are any space after the conf item name*/
        token = conf_name;
        for (; (*token != ' ' && *token != 0 && *token != '\t'); token++);
        *token = '\0';

        token = strsep(&pos,"=");
        /* handle if there are any space before the conf item value*/
        for (; (*token == ' ' || *token == '\t' ); token++);

        /* handle if there are any comments after the conf item value*/
        conf_value = token;

        for (; (*token != '\n' && *token != '\t'); token++);
        *token = '\0';
        eap_noob_assign_config(conf_name,conf_value, data);
    }
}

/**
 * eap_noob_handle_incomplete_conf :  assigns defult value if the configuration is incomplete
 * @data : server config
 * Returs : FAILURE/SUCCESS
 **/
static int eap_noob_handle_incomplete_conf(struct eap_noob_server_context * data)
{
    if (NULL == data || NULL == data->server_attr) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return FAILURE;
    }

    if (0 == (data->server_attr->config_params & SERVER_URL_RCVD) ||
        0 == (data->server_attr->config_params & SERVER_NAME_RCVD)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: ServerName or ServerURL missing"); return FAILURE;
    }

    if (0 == (data->server_attr->config_params & ENCODE_RCVD)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Encoding Scheme not specified"); return FAILURE;
    }

    /* set default values if not provided via config */
    if (0 == (data->server_attr->config_params & VERSION_RCVD))
        data->server_attr->version[0] = VERSION_ONE;

    if (0 == (data->server_attr->config_params & CRYPTOSUITEP_RCVD))
        data->server_attr->cryptosuite[0] = SUITE_ONE;

    if (0 == (data->server_attr->config_params & DIRP_RCVD))
        data->server_attr->dir = BOTH_DIRECTIONS;

    if (0 == (data->server_attr->config_params & MAX_OOB_RETRIES_RCVD)) {
        data->server_attr->max_oob_retries = DEFAULT_MAX_OOB_RETRIES;
    }

    if (0 == (data->server_attr->config_params & WE_COUNT_RCVD))
        server_conf.max_we_count = MAX_WAIT_EXCHNG_TRIES;

    if (0 == (data->server_attr->config_params & REALM_RCVD))
        server_conf.realm = os_strdup(RESERVED_DOMAIN);

    return SUCCESS;
}

/**
 * eap_noob_serverinfo: Append a JSON object for server information.
 * @data : server config
 * @json : wpabuf json object to which the server info object should be appended.
 * @name : name for the server info json object, or NULL.
**/
static void eap_noob_prepare_server_info_json(struct eap_noob_server_config_params * data, struct wpabuf * json, char * name)
{
    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return;
    }

    json_start_object(json, name);
    json_add_string(json, SERVERINFO_NAME, data->ServerName);
    json_value_sep(json);
    json_add_string(json, SERVERINFO_URL, data->ServerURL);
    json_end_object(json);
}

/**
 * Generate a string representation of a JSON server information object.
 * @data: server config
 * Returns: A string representation of the server info object
 */
static char * eap_noob_prepare_server_info_string(struct eap_noob_server_config_params * data)
{
    struct wpabuf * json = NULL;
    char * resp = NULL;

    json = wpabuf_alloc(MAX_INFO_LEN);
    if (!json) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for JSON wpabuf");
        return NULL;
    }

    // Append JSON server info object without a name
    eap_noob_prepare_server_info_json( data, json, NULL);

    // Get a string representation of the JSON object
    resp = strndup(wpabuf_head(json), wpabuf_len(json));

    if (strlen(resp) > MAX_INFO_LEN) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Server info object is too long");
        os_free(resp);
        return NULL;
    }

    wpabuf_free(json);

    return resp;
}

/**
 * eap_noob_read_config : read configuraions from config file
 * @data : server context
 * Returns : SUCCESS/FAILURE
**/
static int eap_noob_read_config(struct eap_noob_server_context * data)
{
    FILE * conf_file = NULL;
    char * buff = NULL;
    int ret = SUCCESS;

    if (NULL == data || NULL == data->server_attr) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        ret = FAILURE; goto ERROR_EXIT;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering function %s", __func__);

    if (NULL == (conf_file = fopen(CONF_FILE, "r"))) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Configuration file not found");
        ret = FAILURE; goto ERROR_EXIT;
    }

    if (NULL == (buff = os_malloc(MAX_CONF_LEN))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in allocating memory.");
        ret = FAILURE; goto ERROR_EXIT;
    }
    if (NULL == (data->server_attr->server_config_params =
            os_malloc(sizeof(struct eap_noob_server_config_params)))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in allocating memory.");
        ret = FAILURE; goto ERROR_EXIT;
    }

    data->server_attr->config_params = 0;
    while(!feof(conf_file)) {
        if (fgets(buff, MAX_CONF_LEN, conf_file)) {
            eap_noob_parse_config(buff, data->server_attr);
            memset(buff, 0, MAX_CONF_LEN);
        }
    }

    if ((data->server_attr->version[0] > MAX_SUP_VER) || (data->server_attr->cryptosuite[0] > MAX_SUP_CSUITES) ||
        (data->server_attr->dir > BOTH_DIRECTIONS)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect confing value");
        ret = FAILURE; goto ERROR_EXIT;
    }

    if (data->server_attr->config_params != CONF_PARAMS && FAILURE == eap_noob_handle_incomplete_conf(data)) {
        ret = FAILURE; goto ERROR_EXIT;
    }

    data->server_attr->server_info =  eap_noob_prepare_server_info_string(data->server_attr->server_config_params);
    if(!data->server_attr->server_info){
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to prepare ServerInfo string!");
        ret = FAILURE; goto ERROR_EXIT;
    }

ERROR_EXIT:
    if (ret != SUCCESS)
        EAP_NOOB_FREE(data->server_attr->server_config_params);
    EAP_NOOB_FREE(buff);
    fclose(conf_file);
    return ret;
}

/**
 * eap_noob_get_id_peer - generate PEER ID
 * @str: pointer to PEER ID
 * @size: PEER ID Length
 **/
int eap_noob_get_id_peer(char * str, size_t size)
{
    const u8 charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    time_t t = 0;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Generating PeerId");
    srand((unsigned)time(&t));

    int charset_size = (int)(sizeof(charset) - 1);

    /* To-Do: Check whether the generated Peer ID is already in db */
    if (size) {
        size_t n;
        for (n = 0; n < size; n++) {
            int key = rand() % charset_size;
            str[n] = charset[key];
        }
        str[n] = '\0';
    }

    if (str != NULL)
        return 0;

    return 1;
}


/**
 * eap_noob_ECDH_KDF_X9_63: generates KDF
 * @out:
 * @outlen:
 * @Z:
 * @Zlen:
 * @alorithm_id:
 * @alorithm_id_len:
 * @partyUinfo:
 * @partyUinfo_len:
 * @partyVinfo:
 * @partyVinfo_len
 * @suppPrivinfo:
 * @suppPrivinfo_len:
 * @EVP_MD:
 * @Returns:
 **/

int eap_noob_ECDH_KDF_X9_63(unsigned char *out, size_t outlen,
        const unsigned char * Z, size_t Zlen,
        const unsigned char * algorithm_id, size_t algorithm_id_len,
        const unsigned char * partyUinfo, size_t partyUinfo_len,
        const unsigned char * partyVinfo, size_t partyVinfo_len,
        const unsigned char * suppPrivinfo, size_t suppPrivinfo_len,
        const EVP_MD *md)
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
        ctr[3] = i & 0xFF;
        ctr[2] = (i >> 8) & 0xFF;
        ctr[1] = (i >> 16) & 0xFF;
        ctr[0] = (i >> 24) & 0xFF;
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
 * eap_noob_gen_KDF : generates and updates the KDF inside the peer context.
 * @data  : peer context.
 * @state : EAP_NOOB state
 * Returns:
 **/
static int eap_noob_gen_KDF(struct eap_noob_server_context * data, int state)
{
    const EVP_MD * md = EVP_sha256();
    unsigned char * out = os_zalloc(KDF_LEN);
    int counter = 0, len = 0;
    u8 * Noob;
//TODO: Check that these are not null before proceeding to kdf
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: ALGORITH ID:", ALGORITHM_ID, ALGORITHM_ID_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Peer_NONCE:", data->peer_attr->kdf_nonce_data->Np, NONCE_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Serv_NONCE:", data->peer_attr->kdf_nonce_data->Ns, NONCE_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Shared Key:", data->peer_attr->ecdh_exchange_data->shared_key,
                      ECDH_SHARED_SECRET_LEN);

    if (state == COMPLETION_EXCHANGE) {
        len = eap_noob_Base64Decode(data->peer_attr->oob_data->Noob_b64, &Noob);
	if (len != NOOB_LEN) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode Noob");
		return FAILURE;
	}
        wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: NOOB:", Noob, NOOB_LEN);
        eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
                data->peer_attr->ecdh_exchange_data->shared_key, ECDH_SHARED_SECRET_LEN,
                (unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
                data->peer_attr->kdf_nonce_data->Np, NONCE_LEN,
                data->peer_attr->kdf_nonce_data->Ns, NONCE_LEN,
                Noob, NOOB_LEN, md);
    } else {
        wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Kz:", data->peer_attr->Kz, KZ_LEN);
        eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
                data->peer_attr->Kz, KZ_LEN,
                (unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
                data->peer_attr->kdf_nonce_data->Np, NONCE_LEN,
                data->peer_attr->kdf_nonce_data->Ns, NONCE_LEN,
                NULL,0, md);
    }
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: KDF", out, KDF_LEN);

    if (out != NULL) {
        data->peer_attr->kdf_out->msk = os_zalloc(MSK_LEN);
        data->peer_attr->kdf_out->emsk = os_zalloc(EMSK_LEN);
        data->peer_attr->kdf_out->amsk = os_zalloc(AMSK_LEN);
        data->peer_attr->kdf_out->MethodId = os_zalloc(METHOD_ID_LEN);
        data->peer_attr->kdf_out->Kms = os_zalloc(KMS_LEN);
        data->peer_attr->kdf_out->Kmp = os_zalloc(KMP_LEN);
        data->peer_attr->kdf_out->Kz = os_zalloc(KZ_LEN);

        memcpy(data->peer_attr->kdf_out->msk, out, MSK_LEN);
        counter += MSK_LEN;
        memcpy(data->peer_attr->kdf_out->emsk, out + counter, EMSK_LEN);
        counter += EMSK_LEN;
        memcpy(data->peer_attr->kdf_out->amsk, out + counter, AMSK_LEN);
        counter += AMSK_LEN;
        memcpy(data->peer_attr->kdf_out->MethodId, out + counter, METHOD_ID_LEN);
        counter += METHOD_ID_LEN;
        memcpy(data->peer_attr->kdf_out->Kms, out + counter, KMS_LEN);
        counter += KMS_LEN;
        memcpy(data->peer_attr->kdf_out->Kmp, out + counter, KMP_LEN);
        counter += KMP_LEN;
        memcpy(data->peer_attr->kdf_out->Kz, out + counter, KZ_LEN);
        if(state == COMPLETION_EXCHANGE) {
	   data->peer_attr->Kz = os_zalloc(KZ_LEN);
	   memcpy(data->peer_attr->Kz, out + counter, KZ_LEN);
	}
        counter += KZ_LEN;
        os_free(out);
    } else {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in allocating memory, %s", __func__);
	return FAILURE;
    }
    return SUCCESS;
}

static void eap_noob_get_sid(struct eap_sm * sm, struct eap_noob_server_context * data)
{
    char *query = NULL;
    if ((NULL == sm->rad_attr) || (NULL == sm->rad_attr->calledSID) ||
        (NULL == sm->rad_attr->callingSID) || (NULL == sm->rad_attr->nasId)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return;
    }

    if(NULL == (query = (char *)malloc(500))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error allocating memory in %s", __func__);
        return;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s, Values Received: %s,%s", __func__,
               sm->rad_attr->calledSID, sm->rad_attr->callingSID);

    os_snprintf(query, 500, "INSERT INTO radius (user_name, called_st_id, calling_st_id, NAS_id) VALUES (?, ?, ?, ?)");
    if (FAILURE == eap_noob_exec_query(data, query, NULL, 8, TEXT, data->peer_attr->PeerId, TEXT, sm->rad_attr->calledSID,
            TEXT, sm->rad_attr->callingSID, TEXT, sm->rad_attr->nasId)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: DB value insertion failed");
    }

    EAP_NOOB_FREE(sm->rad_attr->callingSID);
    EAP_NOOB_FREE(sm->rad_attr->calledSID);
    EAP_NOOB_FREE(sm->rad_attr->nasId);
    EAP_NOOB_FREE(sm->rad_attr);
    EAP_NOOB_FREE(query);
}

static int eap_noob_derive_session_secret(struct eap_noob_server_context * data, size_t * secret_len)
{
    EVP_PKEY_CTX * ctx = NULL;
    EVP_PKEY * peerkey = NULL;
    unsigned char * peer_pub_key = NULL;
    size_t skeylen = 0, len = 0;
    int ret = SUCCESS;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering function %s", __func__);
    if (NULL == data || NULL == secret_len) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context is NULL");
        return FAILURE;
    }

    EAP_NOOB_FREE(data->peer_attr->ecdh_exchange_data->shared_key);
    len = eap_noob_Base64Decode(data->peer_attr->ecdh_exchange_data->x_peer_b64, &peer_pub_key);
    if (len == 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode public key of peer");
        ret = FAILURE; goto EXIT;
    }

    peerkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub_key, len);
    if(peerkey == NULL) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to initialize public key of peer");
        ret = FAILURE; goto EXIT;
    }

    ctx = EVP_PKEY_CTX_new(data->peer_attr->ecdh_exchange_data->dh_key, NULL);
    if (!ctx) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to create context");
        ret = FAILURE; goto EXIT;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to init key derivation");
        ret = FAILURE; goto EXIT;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to set peer key");
        ret = FAILURE; goto EXIT;
    }

    if (EVP_PKEY_derive(ctx, NULL, &skeylen) <= 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to get secret key len");
        ret = FAILURE; goto EXIT;
    }

    data->peer_attr->ecdh_exchange_data->shared_key  = OPENSSL_malloc(skeylen);

    if (!data->peer_attr->ecdh_exchange_data->shared_key) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for secret");
        ret = FAILURE; goto EXIT;
    }

    if (EVP_PKEY_derive(ctx, data->peer_attr->ecdh_exchange_data->shared_key, &skeylen) <= 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to derive secret key");
        ret = FAILURE; goto EXIT;
    }

    (*secret_len) = skeylen;

    wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Secret Derived",
            data->peer_attr->ecdh_exchange_data->shared_key, *secret_len);

EXIT:
    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    EAP_NOOB_FREE(peer_pub_key);

    if (ret != SUCCESS)
        EAP_NOOB_FREE(data->peer_attr->ecdh_exchange_data->shared_key);

    return ret;
}
static int eap_noob_get_key(struct eap_noob_server_context * data)
{
    EVP_PKEY_CTX * pctx = NULL;
    BIO * mem_pub = BIO_new(BIO_s_mem());
    unsigned char * pub_key_char = NULL;
    size_t pub_key_len = 0;
    int ret = SUCCESS;

/*
    Uncomment the next 6 lines of code for using the test vectors of Curve25519 in RFC 7748.
    Peer = Bob
    Server = Alice
*/


    char * priv_key_test_vector = "MC4CAQAwBQYDK2VuBCIEIHcHbQpzGKV9PBbBclGyZkXfTC+H68CZKrF3+6UduSwq";
    BIO* b641 = BIO_new(BIO_f_base64());
    BIO* mem1 = BIO_new(BIO_s_mem());
    BIO_set_flags(b641,BIO_FLAGS_BASE64_NO_NL);
    BIO_puts(mem1,priv_key_test_vector);
    mem1 = BIO_push(b641,mem1);

    wpa_printf(MSG_DEBUG, "EAP-NOOB: entering %s", __func__);

    /* Initialize context to generate keys - Curve25519 */
    if (NULL == (pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to create context for parameter generation.");
        ret = FAILURE; goto EXIT;
    }

    EVP_PKEY_keygen_init(pctx);

    /* Generate X25519 key pair */
   //EVP_PKEY_keygen(pctx, &data->peer_attr->ecdh_exchange_data->dh_key);

/*
    If you are using the RFC 7748 test vector, you do not need to generate a key pair. Instead you use the
    private key from the RFC. For using the test vector, comment out the line above and
    uncomment the following line code
*/
    d2i_PrivateKey_bio(mem1,&data->peer_attr->ecdh_exchange_data->dh_key);

    PEM_write_PrivateKey(stdout, data->peer_attr->ecdh_exchange_data->dh_key,
                         NULL, NULL, 0, NULL, NULL);
    PEM_write_PUBKEY(stdout, data->peer_attr->ecdh_exchange_data->dh_key);

    /* Get public key */
    if (1 != i2d_PUBKEY_bio(mem_pub, data->peer_attr->ecdh_exchange_data->dh_key)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to copy public key to bio.");
        ret = FAILURE; goto EXIT;
    }

    pub_key_char = os_zalloc(MAX_X25519_LEN);
    pub_key_len = BIO_read(mem_pub, pub_key_char, MAX_X25519_LEN);

/*
 * This code removes the openssl internal ASN encoding and only keeps the 32 bytes of curve25519
 * public key which is then encoded in the JWK format and sent to the other party. This code may
 * need to be updated when openssl changes its internal format for public-key encoded in PEM.
*/
    unsigned char * pub_key_char_asn_removed = pub_key_char + (pub_key_len-32);
    pub_key_len = 32;

    EAP_NOOB_FREE(data->peer_attr->ecdh_exchange_data->x_b64);
    eap_noob_Base64Encode(pub_key_char_asn_removed, pub_key_len, &data->peer_attr->ecdh_exchange_data->x_b64);

EXIT:
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    EAP_NOOB_FREE(pub_key_char);
    BIO_free_all(mem_pub);
    return ret;
}

static int eap_noob_get_sleeptime(struct eap_noob_server_context * data)
{
    /* TODO:  Include actual implementation for calculating the waiting time.
     * return  \
     * (int)((eap_noob_cal_pow(2,data->peer_attr->sleep_count))* (rand()%8) + 1) % 3600 ; */
    return 60;
}

/**
 * eap_noob_err_msg : prepares error message
 * @data : server context
 * @id   : response message id
 * Returns : pointer to message buffer or null
 **/
static struct wpabuf * eap_noob_err_msg(struct eap_noob_server_context * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * req = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(ERRORCODE) + strlen(ERRORINFO);
    size_t code = 0;

    if (!data || !data->peer_attr || !(code = data->peer_attr->err_code)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is NULL", __func__);
        goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Build error request");

    len += strlen(error_info[code]);

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, NONE);
    json_value_sep(json);
    if (data->peer_attr->PeerId && code != E1001) {
        json_add_string(json, PEERID, data->peer_attr->PeerId);
    } else {
        json_add_string(json, PEERID, data->peer_attr->peerid_rcvd);
    }
    json_add_int(json, ERRORCODE, error_code[code]);
    json_value_sep(json);
    json_add_string(json, ERRORINFO, error_info[code]);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str);

    if (code != E1001 && FAILURE == eap_noob_db_functions(data, UPDATE_STATE_ERROR)) {
        wpa_printf(MSG_DEBUG,"EAP-NOOB: Failed to write error to the database");
    }

    req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (!req) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for error message response");
        goto EXIT;
    }

    wpabuf_put_data(req, json_str, len);
    eap_noob_set_done(data, DONE);
    eap_noob_set_success(data, FAILURE);
    data->peer_attr->err_code = NO_ERROR;
EXIT:
    wpabuf_free(json);
    EAP_NOOB_FREE(json_str);
    return req;
}

/**
 * Construct a JSON array string of all input data for a MAC.
 * @data: server context that contains all required data
 * @first_param: either the type of MAC or the Direction, necessary for MAC or Hoob respectively
 * @state: the current state
 */
static char * eap_noob_build_mac_input(const struct eap_noob_server_context * data,
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
        if (data->server_attr->version[i] > 0)
            wpabuf_printf(mac_json, "%s%u", i ? "," : "", data->server_attr->version[i]);
    }
    json_end_array(mac_json);

    // Version chosen by peer
    wpabuf_printf(mac_json, ",%u", data->peer_attr->version);

    // PeerId assigned by the server to the peer
    wpabuf_printf(mac_json, ",\"%s\"", data->peer_attr->PeerId);

    // Cryptosuites supported by the server
    json_value_sep(mac_json);
    json_start_array(mac_json, NULL);
    for (int i = 0; i < MAX_SUP_CSUITES; i++) {
        if (data->server_attr->cryptosuite[i] > 0)
            wpabuf_printf(mac_json, "%s%u", i ? "," : "", data->server_attr->cryptosuite[i]);
    }
    json_end_array(mac_json);

    // Direction supported by the server
    if (state == RECONNECTING_STATE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%u", data->server_attr->dir);
    }

    // Server info object
    if (state == RECONNECTING_STATE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%s", data->server_attr->server_info);
    }

    // Cryptosuite chosen by peer
    wpabuf_printf(mac_json, ",%u", data->peer_attr->cryptosuite);

    // Direction supported by the peer
    if (state == RECONNECTING_STATE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%u", data->peer_attr->dir);
    }

    // If the Realm is specified, include it
    // Otherwise, insert an empty string
    if (data->peer_attr->Realm) {
        wpabuf_printf(mac_json, ",\"%s\"", data->peer_attr->Realm);
    } else if (server_conf.realm) {
        wpabuf_printf(mac_json, ",\"%s\"", server_conf.realm);
    } else {
        wpabuf_printf(mac_json, ",\"\"");
    }

    // Peer info object
    if (state == RECONNECTING_STATE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%s", data->peer_attr->peerinfo);
    }

    // KeyingMode
    if (state == RECONNECTING_STATE) {
        wpabuf_printf(mac_json, ",%u", data->server_attr->keying_mode);
    } else {
        wpabuf_printf(mac_json, ",0");
    }

    // Public key server
    if (state == RECONNECTING_STATE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%s", data->peer_attr->ecdh_exchange_data->jwk_serv);
    }

    // Server nonce
    eap_noob_Base64Encode(data->peer_attr->kdf_nonce_data->Ns, NONCE_LEN, &nonce);
    wpabuf_printf(mac_json, ",\"%s\"", nonce);

    // Public key peer
    if (state == RECONNECTING_STATE) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",%s", data->peer_attr->ecdh_exchange_data->jwk_peer);
    }

    // Peer nonce
    eap_noob_Base64Encode(data->peer_attr->kdf_nonce_data->Np, NONCE_LEN, &nonce);
    wpabuf_printf(mac_json, ",\"%s\"", nonce);

    // Nonce out of band
    if (state == RECONNECTING_STATE || !data->peer_attr->oob_data->Noob_b64) {
        wpabuf_printf(mac_json, ",\"\"");
    } else {
        wpabuf_printf(mac_json, ",\"%s\"", data->peer_attr->oob_data->Noob_b64);
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
 * @data : server context
 * type  : MAC type
 * @key  : key to generate MAC
 * @keylen: key length
 * Returns : MAC on success or NULL on error.
 **/
static u8 * eap_noob_gen_MAC(const struct eap_noob_server_context * data, int type, u8 * key, int keylen, int state)
{
    u8 * mac = NULL;

    // TODO: Verify that all required information exists


    // Build the MAC input and store it
    data->peer_attr->mac_input_str = eap_noob_build_mac_input(data, type, state);

    // Calculate MAC
    mac = HMAC(EVP_sha256(), key, keylen,
            (u8 *) data->peer_attr->mac_input_str,
            os_strlen(data->peer_attr->mac_input_str), NULL, NULL);

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Generated MAC", mac, MAC_LEN);

    return mac;
}


/**
 * eap_noob_req_type_seven :
 * @data : server context
 * @id  :
 * Returns :
**/
static struct wpabuf * eap_noob_req_type_seven(struct eap_noob_server_context * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN + strlen(MACP2) + MAC_LEN;
    u8 * mac = NULL;
    char * mac_b64 = NULL;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Request 3/Fast Reconnect");

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    if (SUCCESS != eap_noob_gen_KDF(data, RECONNECT_EXCHANGE)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Error in KDF during Request/NOOB-FR");
        goto EXIT;
    }

    // Generate the MAC
    mac = eap_noob_gen_MAC(data, MACS_TYPE, data->peer_attr->kdf_out->Kms, KMS_LEN, RECONNECTING_STATE);
    if (!mac) {
        goto EXIT;
    }

    // Convert MAC to base 64
    if (FAILURE == eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64)) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_7);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peer_attr->PeerId);
    json_value_sep(json);
    json_add_string(json, MACS2, mac_b64);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_REQUEST, id);
    if (!resp) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for Response/NOOB-FR");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    EAP_NOOB_FREE(json_str);
    return resp;
}

/**
 * eap_oob_req_type_six - Build the EAP-Request/Fast Reconnect 2.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_type_six(struct eap_noob_server_context * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN
        + strlen(NS) + NONCE_LEN * 1.5;
    char * Ns_b64;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    // Generate server nonce
    data->peer_attr->kdf_nonce_data->Ns = os_zalloc(NONCE_LEN);
    int rc = RAND_bytes(data->peer_attr->kdf_nonce_data->Ns, NONCE_LEN);
    unsigned long error = ERR_get_error();
    if (rc != SUCCESS) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce. Error=%lu", error);
        os_free(data->peer_attr->kdf_nonce_data->Ns);
        goto EXIT;
    }

    // Encode nonce in base 64
    eap_noob_Base64Encode(data->peer_attr->kdf_nonce_data->Ns, NONCE_LEN, &Ns_b64);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Nonce %s", Ns_b64);

    /* TODO: Based on the previous and the current versions of cryptosuites of peers,
     * decide whether new public key has to be generated
     * TODO: change get key params and finally store only base 64 encoded public key */

    // Create JSON EAP message

    json = wpabuf_alloc(len);
    if (!json) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for json request");
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_6);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peer_attr->PeerId);
    json_value_sep(json);
    // TODO: Determine keying mode
    json_add_int(json, KEYINGMODE, 1);
    json_value_sep(json);
    json_add_string(json, NS2, Ns_b64);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id);
    if (!resp) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for Request/RE");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    EAP_NOOB_FREE(json_str);
    EAP_NOOB_FREE(Ns_b64);
    return resp;
}

/**
 * TODO send Cryptosuites only if it has changed;
 * eap_oob_req_type_five - Build the EAP-Request/Fast Reconnect 1.
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_type_five(struct eap_noob_server_context * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(VERS) + MAX_SUP_VER + strlen(PEERID) + MAX_PEER_ID_LEN +
        strlen(CRYPTOSUITES) + MAX_SUP_CSUITES + strlen(PEERINFO) + MAX_INFO_LEN;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        goto EXIT;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_5);
    json_value_sep(json);
    json_start_array(json, VERS);
    for (int i = 0; i < MAX_SUP_VER; i++) {
        if (data->server_attr->version[i] > 0) {
            wpabuf_printf(json, "%s%u", i ? "," : "", data->server_attr->version[i]);
        }
    }
    json_end_array(json);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peer_attr->PeerId);
    json_value_sep(json);
    json_start_array(json, CRYPTOSUITES);
    for (int i = 0; i < MAX_SUP_CSUITES; i++) {
        if (data->server_attr->cryptosuite[i] > 0) {
            wpabuf_printf(json, "%s%u", i ? "," : "", data->server_attr->cryptosuite[i]);
        }
    }
    json_end_array(json);
    if (strcmp(server_conf.realm, RESERVED_DOMAIN)) {
        json_add_string(json, REALM, server_conf.realm);
    } else {
        json_add_string(json, REALM, "");
    }
    // Helper method to add the server information object to the wpabuf
    eap_noob_prepare_server_info_json(data->server_attr->server_config_params, json, SERVERINFO);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id);
    if (!resp) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for Reconnect Exchange Response");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    EAP_NOOB_FREE(json_str);
    return resp;
}

/**
 * eap_oob_req_type_four - Build the EAP-Request
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_type_four(struct eap_noob_server_context * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN +
        + strlen(NOOBID) + NOOBID_LEN + strlen(MACS) + MAC_LEN;
    char * mac_b64 = NULL;
    u8 * mac = NULL;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        return NULL;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    if (SUCCESS != eap_noob_gen_KDF(data, COMPLETION_EXCHANGE)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Error in KDF during Request/NOOB-CE");
        goto EXIT;
    }

    mac = eap_noob_gen_MAC(data, MACS_TYPE, data->peer_attr->kdf_out->Kms,
            KMS_LEN, data->peer_attr->server_state);
    if (!mac) {
        goto EXIT;
    }

    if (FAILURE == eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64)) {
        goto EXIT;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_4);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peer_attr->PeerId);
    json_value_sep(json);
    json_add_string(json, NOOBID, data->peer_attr->oob_data->NoobId_b64);
    json_value_sep(json);
    json_add_string(json, MACS, mac_b64);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str) + 1;

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id);
    if (!resp) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for Completion Response");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    EAP_NOOB_FREE(json_str);
    EAP_NOOB_FREE(mac_b64);
    return resp;
}

/**
 * eap_oob_req_type_three - Build the EAP-Request
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_type_three(struct eap_noob_server_context * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN + strlen(SLEEPTIME);
    struct timespec time;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 3");
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        goto EXIT;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    data->peer_attr->sleeptime = eap_noob_get_sleeptime(data);

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_3);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peer_attr->PeerId);
    json_value_sep(json);
    json_add_int(json, SLEEPTIME, data->peer_attr->sleeptime);
    json_end_object(json);

    clock_gettime(CLOCK_REALTIME, &time);
    data->peer_attr->last_used_time = time.tv_sec;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Current time is %ld", data->peer_attr->last_used_time);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id);
    if (resp == NULL) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for Response/NOOB-WE");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    EAP_NOOB_FREE(json_str);
    return resp;
}

/**
 *  eap_noob_build_JWK : Builds a JWK object to send in the inband message
 *  @jwk : output json string
 *  @x_64 : x co-ordinate in base64url format
 *  Returns : FAILURE/SUCCESS
**/
static int eap_noob_build_JWK(char ** jwk, const char * x_b64)
{
    struct wpabuf * json;
    size_t len = 500;

    if (!x_b64) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: X-coordinate is NULL when building JWK");
        return FAILURE;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory while building JWK");
        return FAILURE;
    }

    json_start_object(json, NULL);
    json_add_string(json, KEY_TYPE, "EC");
    json_value_sep(json);
    json_add_string(json, CURVE, "P-256");
    json_value_sep(json);
    json_add_string(json, X_COORDINATE, x_b64);
    json_end_object(json);

    *jwk = strndup(wpabuf_head(json), wpabuf_len(json));
    if (!*jwk) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to copy JWK");
        wpabuf_free(json);
        return FAILURE;
    }

    wpabuf_free(json);

    wpa_printf(MSG_DEBUG, "EAP-NOOB: JWK key is %s", *jwk);

    return SUCCESS;
}

/**
 * eap_oob_req_type_two - Build the EAP-Request/Initial Exchange 2.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_type_two(struct eap_noob_server_context *data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN
        + strlen(PKS) + 500 + strlen(NS) + NONCE_LEN * 1.5 + strlen(SLEEPTIME);
    //size_t secret_len = ECDH_SHARED_SECRET_LEN;
    char * Ns_b64;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Request 2/Initial Exchange");

    // Generate server nonce
    data->peer_attr->kdf_nonce_data->Ns = os_malloc(NONCE_LEN);
    int rc = RAND_bytes(data->peer_attr->kdf_nonce_data->Ns, NONCE_LEN);
    unsigned long error = ERR_get_error();
    if (rc != 1) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce. Error= %lu", error);
        os_free(data->peer_attr->kdf_nonce_data->Ns);
        goto EXIT;
    }

    // Encode the nonce in base 64
    eap_noob_Base64Encode(data->peer_attr->kdf_nonce_data->Ns, NONCE_LEN, &Ns_b64);
    wpa_printf(MSG_DEBUG,"EAP-NOOB: Nonce %s", Ns_b64);

    // Generate key material
    if (eap_noob_get_key(data) == FAILURE) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate keys");
        eap_noob_set_done(data, DONE);
        eap_noob_set_success(data, FAILURE);
        goto EXIT;
    }

    // Build JWK to represent server
    if (FAILURE == eap_noob_build_JWK(&data->peer_attr->ecdh_exchange_data->jwk_serv,
                data->peer_attr->ecdh_exchange_data->x_b64)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate JWK");
        goto EXIT;
    }

    // Get time the peer is expected to sleep
    data->peer_attr->sleeptime = eap_noob_get_sleeptime(data);

    // Create JSON EAP message

    json = wpabuf_alloc(len);
    if (!json) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for json response");
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_2);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peer_attr->PeerId);
    json_value_sep(json);
    wpabuf_printf(json, "\"%s\":%s", PKS, data->peer_attr->ecdh_exchange_data->jwk_serv);
    json_value_sep(json);
    json_add_string(json, NS, Ns_b64);
    json_value_sep(json);
    json_add_int(json, SLEEPTIME, data->peer_attr->sleeptime);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id);
    if (!resp) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for Response/NOOB-IE");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    EAP_NOOB_FREE(json_str);
    EAP_NOOB_FREE(Ns_b64);
    return resp;
}

/**
 * eap_oob_req_type_one - Build the EAP-Request/Initial Exchange 1.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_type_one(struct eap_noob_server_context * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(VERS) + MAX_SUP_VER + strlen(PEERID) + MAX_PEER_ID_LEN +
        strlen(CRYPTOSUITES) + MAX_SUP_CSUITES + strlen(PEERINFO) + MAX_INFO_LEN;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        goto EXIT;
    }

    EAP_NOOB_FREE(data->peer_attr->PeerId);
    data->peer_attr->PeerId = os_malloc(MAX_PEER_ID_LEN);
    if (eap_noob_get_id_peer(data->peer_attr->PeerId, MAX_PEER_ID_LEN)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to generate PeerId");
        return NULL;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_1);
    json_value_sep(json);
    json_start_array(json, VERS);
    for (int i = 0; i < MAX_SUP_VER; i++) {
        if (data->server_attr->version[i] > 0) {
            wpabuf_printf(json, "%s%u", i ? "," : "", data->server_attr->version[i]);
        }
    }
    json_end_array(json);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peer_attr->PeerId);
    json_value_sep(json);
    if (strcmp(server_conf.realm, RESERVED_DOMAIN)) {
        json_add_string(json, REALM, server_conf.realm);
    } else {
        json_add_string(json, REALM, "");
    }
    json_value_sep(json);
    json_start_array(json, CRYPTOSUITES);
    for (int i = 0; i < MAX_SUP_CSUITES; i++) {
        if (data->server_attr->cryptosuite[i] > 0) {
            wpabuf_printf(json, "%s%u", i ? "," : "", data->server_attr->cryptosuite[i]);
        }
    }
    json_end_array(json);
    json_value_sep(json);
    json_add_int(json, DIRS, data->server_attr->dir);
    json_value_sep(json);
    // Helper method to add the server information object to the wpabuf
    eap_noob_prepare_server_info_json(data->server_attr->server_config_params, json, SERVERINFO);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id);
    if (!resp) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for Reconnect Exchange Response");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    EAP_NOOB_FREE(json_str);
    return resp;
}

/**
 * eap_noob_req_noobid -
 * @data: Pointer to private EAP-NOOB data
 * @id: EAP response to be processed (eapRespData)
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_noobid(struct eap_noob_server_context * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Building message request type 8");

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_8);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peer_attr->PeerId);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id);
    if (!resp) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for NoobId hint response");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    EAP_NOOB_FREE(json_str);
    return resp;
}

/**
 * Prepare message type 9 request (for PeerId and PeerState); Common Handshake
 * @data: Pointer to private EAP-NOOB data
 * @id: EAP response to be processed (eapRespData)
 * Return: Pointer to allocated EAP-Request packet, or NULL if an error occurred
 */
static struct wpabuf * eap_noob_req_type_nine(struct eap_noob_server_context * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE);

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        goto EXIT;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_9);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str);

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id);
    if (!resp) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for handshake request");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    EAP_NOOB_FREE(json_str);
    return resp;
}

/**
 * eap_noob_buildReq - Build the EAP-Request packets.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @priv: Pointer to private EAP-NOOB data
 * @id: EAP response to be processed (eapRespData)
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_buildReq(struct eap_sm * sm, void * priv, u8 id)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB: BUILDREQ SERVER");
    struct eap_noob_server_context *data = NULL;

    if (NULL == sm || NULL == priv) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    data = priv;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: next request = %d", data->peer_attr->next_req);
    //TODO : replce switch case with function pointers.
    switch (data->peer_attr->next_req) {
        case NONE:
            return eap_noob_err_msg(data,id);

        case EAP_NOOB_TYPE_1:
            return eap_noob_req_type_one(data, id);

        case EAP_NOOB_TYPE_2:
            return eap_noob_req_type_two(data, id);

        case EAP_NOOB_TYPE_3:
            return eap_noob_req_type_three(data, id);

        case EAP_NOOB_TYPE_4:
            return eap_noob_req_type_four(data, id);

        case EAP_NOOB_TYPE_5:
            return eap_noob_req_type_five(data, id);

        case EAP_NOOB_TYPE_6:
            return eap_noob_req_type_six(data, id);

        case EAP_NOOB_TYPE_7:
            return eap_noob_req_type_seven(data, id);

        case EAP_NOOB_TYPE_8:
            return eap_noob_req_noobid(data, id);
        case EAP_NOOB_TYPE_9:
            return eap_noob_req_type_nine(data, id);
        default:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Unknown type in buildReq");
            break;
    }
    return NULL;
}


/**
 * eap_oob_check - Check the EAP-Response is valid.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @priv: Pointer to private EAP-NOOB data
 * @respData: EAP response to be processed (eapRespData)
 * Returns: False if response is valid, True otherwise.
 **/
static _Bool eap_noob_check(struct eap_sm * sm, void * priv,
                              struct wpabuf * respData)
{
    struct eap_noob_server_context * data = NULL;
    struct json_token * resp_obj = NULL;
    struct json_token * resp_type = NULL;
    const u8 * pos = NULL;
    u32 state = 0;
    size_t len = 0;
    Boolean ret = FALSE;

    if (!priv || !sm || !respData) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        ret = TRUE;
        goto EXIT;
    }

    wpa_printf(MSG_INFO, "EAP-NOOB: Checking EAP-Response packet.");

    // Retrieve information from the response

    data = priv;
    state = data->peer_attr->server_state;
    pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_NOOB, respData, &len);

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Received response = %s", pos);

    // Check for possible errors

    resp_obj = json_parse((char *) pos, len);
    if (resp_obj && resp_obj->type == JSON_OBJECT) {
        resp_type = json_get_member(resp_obj, TYPE);

        if (resp_type && resp_type->type == JSON_NUMBER) {
            data->peer_attr->recv_msg = resp_type->number;
        } else {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown message type");
            eap_noob_set_error(data->peer_attr, E1002);
            ret = TRUE;
            goto EXIT;
        }
    } else {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown format received");
        eap_noob_set_error(data->peer_attr, E1002);
        ret = TRUE;
        goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Received frame: opcode = %d", data->peer_attr->recv_msg);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: STATE = %d",data->peer_attr->server_state);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: VERIFY STATE SERV = %d PEER = %d",
            data->peer_attr->server_state, data->peer_attr->peer_state);

    if ((data->peer_attr->recv_msg != NONE) &&
            (state >= NUM_OF_STATES ||
            data->peer_attr->recv_msg > MAX_MSG_TYPES ||
            state_message_check[state][data->peer_attr->recv_msg] != VALID)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Setting error in received message."
            "state (%d), message type (%d), state received (%d)",
            state, data->peer_attr->recv_msg,
            state_message_check[state][data->peer_attr->recv_msg]);
        eap_noob_set_error(data->peer_attr,E1004);
        ret = TRUE;
        goto EXIT;
    }

EXIT:
    /*
    if (resp_obj)
        json_free(resp_obj);
    if (resp_type)
        json_free(resp_type);
     */
    return ret;
}

/**
 * eap_noob_del_temp_tuples :
 * @data : peer context
 * retures: FAILURE/SUCCESS
 **/
static int eap_noob_del_temp_tuples(struct eap_noob_server_context * data)
{
    char * query = os_malloc(MAX_LINE_SIZE);
    int ret = SUCCESS;

    if (NULL == data || NULL == query) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null or malloc failed.", __func__);
        ret = FAILURE; goto EXIT;
    }

    os_snprintf(query, MAX_LINE_SIZE, "Delete from %s WHERE PeerId=?", DEVICE_TABLE);
    if (FAILURE == eap_noob_exec_query(data, query, NULL, 2, data->peer_attr->peerid_rcvd)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: DB tuple deletion failed");
        ret = FAILURE; goto EXIT;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: TEMP Tuples removed");
EXIT:
    EAP_NOOB_FREE(query);
    return ret;
}

/**
 * eap_noob_verify_param_len : verify lengths of string type parameters
 * @data : peer context
 **/
static void eap_noob_verify_param_len(struct eap_noob_peer_data * data)
{
    u32 count  = 0;
    u32 pos = 0x01;

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
                    if (strlen((char *)data->kdf_nonce_data->Np) > NONCE_LEN) {
                        eap_noob_set_error(data, E1003);
                    }
                    break;
                case MAC_RCVD:
                    if (strlen(data->mac) > MAC_LEN) {
                        eap_noob_set_error(data, E1003);
                    }
                    break;
                case INFO_RCVD:
                    if (strlen(data->peerinfo) > MAX_INFO_LEN) {
                        eap_noob_set_error(data, E1003);
                    }
                    break;
            }
        }
        pos = pos<<1;
    }
}

/**
 * eap_noob_FindIndex :
 * @val :
 * returns:
 **/
int eap_noob_FindIndex(int value)
{
    int index = 0;
    while (index < 13 && error_code[index] != value) ++index;
    return index;
}

/**
 * Dump a json token to a string.
 * @json: output buffer to write the json string to
 * @token: the json_token to dump
 */
static void json_token_to_string(struct wpabuf * json, struct json_token * token) {
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
        // array, and that the caller wishes to only dump *this* token to a string.
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
static char * json_dump(struct json_token * token) {
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
 * eap_noob_decode_obj : Decode parameters from incoming messages
 * @data : peer context
 * @req_obj : incoming json object with message parameters
 **/
static void  eap_noob_decode_obj(struct eap_noob_peer_data * data, struct json_token * root)
{
    struct json_token * child = NULL;
    char * key = NULL;
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
                if (!os_strcmp(key, PKP) || !os_strcmp(key, PKP2)) {
                    struct json_token * child_copy;
                    memcpy(&child_copy, &child, sizeof(child));
                    if (!child_copy) {
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error while copying json_token");
                        goto EXIT;
                    }

                    // Exclude name of the new root object from the JSON dump
                    child_copy->name = NULL;

                    data->ecdh_exchange_data->jwk_peer = json_dump(child_copy);
                    if (!data->ecdh_exchange_data->jwk_peer) {
                        data->err_code = E1003;
                        goto EXIT;
                    }

                    // Also decode the contents of the public key object
                    // for later use.
                    eap_noob_decode_obj(data, child);

                    data->rcvd_params |= PKEY_RCVD;
                }
                // PeerInfo
                else if (!os_strcmp(key, PEERINFO)) {
                    struct json_token * child_copy;
                    memcpy(&child_copy, &child, sizeof(child));
                    if (!child_copy) {
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error while copying json_token");
                        goto EXIT;
                    }

                    // Exclude name of the new root object from the JSON dump
                    child_copy->name = NULL;

                    // Retrieve string
                    data->peerinfo = json_dump(child_copy);

                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Peer info: %s", data->peerinfo);

                    // Free intermediate variable
                    json_free(child_copy);

                    data->rcvd_params |= INFO_RCVD;
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
                // NoobId
                else if (!os_strcmp(key, NOOBID)) {
                    data->oob_data->NoobId_b64 = os_strdup(val_str);
                    data->rcvd_params |= NOOBID_RCVD;
                }
                // Serial
                else if (!os_strcmp(key, PEERINFO_SERIAL)) {
                    data->peer_snum = os_strdup(val_str);
                }
                // Np or Np2
                else if (!os_strcmp(key, NP) || !os_strcmp(key, NP2)) {
                    size_t decode_len = eap_noob_Base64Decode(val_str, &data->kdf_nonce_data->Np);
                    if (decode_len) {
                        data->rcvd_params |= NONCE_RCVD;
                    } else {
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode peer nonce");
                    }
                }
                // MACp or MACp2
                else if (!os_strcmp(key, MACP) || !os_strcmp(key, MACP2)) {
                    size_t decode_len = eap_noob_Base64Decode((char *) val_str, (u8 **) &data->mac);
                    if (decode_len) {
                        data->rcvd_params |= MAC_RCVD;
                    } else {
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode peer MAC");
                    }
                }
                // x
                else if (!os_strcmp(key, X_COORDINATE)) {
                    data->ecdh_exchange_data->x_peer_b64 = os_strdup(val_str);
                    wpa_printf(MSG_DEBUG, "X coordinate %s", data->ecdh_exchange_data->x_peer_b64);
                }
                // y
                else if (!os_strcmp(key, Y_COORDINATE)) {
                    data->ecdh_exchange_data->y_peer_b64 = os_strdup(val_str);
                    wpa_printf(MSG_DEBUG, "X coordinate %s", data->ecdh_exchange_data->y_peer_b64);
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
                // Verp
                else if (!os_strcmp(key, VERP)) {
                    data->version = val_int;
                    data->rcvd_params |= VERSION_RCVD;
                }
                // Cryptosuitep
                else if (!os_strcmp(key, CRYPTOSUITEP)) {
                    data->cryptosuite = val_int;
                    data->rcvd_params |= CRYPTOSUITEP_RCVD;
                }
                // Dirp
                else if (!os_strcmp(key, DIRP)) {
                    data->dir = val_int;
                    data->rcvd_params |= DIRP_RCVD;
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
    if (val_str)
        os_free(val_str);
    if (child)
        json_free(child);
    EAP_NOOB_FREE(key);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s", __func__);
}

/**
 * eap_oob_rsp_type_seven - Process EAP-Response
 * @data: Pointer to private EAP-NOOB data
 **/
static void eap_noob_rsp_type_seven(struct eap_noob_server_context * data)
{
    u8 * mac = NULL; char * mac_b64 = NULL;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        return;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-FR-3");

    /* TODO :  validate MAC address along with peerID */
    if (data->peer_attr->rcvd_params != TYPE_SEVEN_PARAMS) {
        eap_noob_set_error(data->peer_attr, E1002);
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if ((data->peer_attr->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if (eap_noob_verify_peerId(data)) {
        mac = eap_noob_gen_MAC(data, MACP_TYPE, data->peer_attr->kdf_out->Kmp, KMP_LEN, RECONNECTING_STATE);
        eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64);
        if (0 != strcmp(data->peer_attr->mac, (char *)mac)) {
            eap_noob_set_error(data->peer_attr,E4001);
            eap_noob_set_done(data, NOT_DONE); goto EXIT;
        }
        eap_noob_change_state(data, REGISTERED_STATE);
        if (FAILURE == eap_noob_db_functions(data, UPDATE_PERSISTENT_STATE)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Updating server state failed ");
            goto EXIT;
        }
        data->peer_attr->next_req = NONE;
        eap_noob_set_done(data, DONE); eap_noob_set_success(data, SUCCESS);
    }
EXIT:
    EAP_NOOB_FREE(mac_b64);
    return;
}


/**
 * eap_oob_rsp_type_six - Process EAP-Response/Fast Reconnect 2
 * @data: Pointer to private EAP-NOOB data
 **/
static void eap_noob_rsp_type_six(struct eap_noob_server_context * data)
{
    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-FR-2");
    if (data->peer_attr->rcvd_params != TYPE_SIX_PARAMS) {
        eap_noob_set_error(data->peer_attr, E1002);
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if ((data->peer_attr->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce Peer", data->peer_attr->kdf_nonce_data->Np, NONCE_LEN);
    if (eap_noob_verify_peerId(data)) {
        data->peer_attr->next_req = EAP_NOOB_TYPE_7;
        eap_noob_set_done(data, NOT_DONE); data->peer_attr->rcvd_params = 0;
    }
}

/**
 * eap_oob_rsp_type_five - Process EAP-Response Type 5
 * @data: Pointer to private EAP-NOOB data
 **/
static void eap_noob_rsp_type_five(struct eap_noob_server_context * data)
{
    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-FR-1");
    /* TODO: Check for the current cryptosuite and the previous to
     * decide whether new key exchange has to be done. */
    if ((data->peer_attr->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if (data->peer_attr->rcvd_params != TYPE_FIVE_PARAMS) {
        eap_noob_set_error(data->peer_attr, E1002);
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if (eap_noob_verify_peerId(data))
        data->peer_attr->next_req = EAP_NOOB_TYPE_6;

    eap_noob_set_done(data, NOT_DONE);
    data->peer_attr->rcvd_params = 0;
}

/**
 * eap_oob_rsp_type_four - Process EAP-Response Type 4
 * @data: Pointer to private EAP-NOOB data
 **/
static void eap_noob_rsp_type_four(struct eap_noob_server_context * data)
{
    u8 * mac = NULL; char * mac_b64 = NULL; int dir = 0;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
    dir = (data->server_attr->dir & data->peer_attr->dir);
    /* TODO :  validate MAC address along with peerID */
    if (data->peer_attr->rcvd_params != TYPE_FOUR_PARAMS) {
        eap_noob_set_error(data->peer_attr,E1002);
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if ((data->peer_attr->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }

    if (eap_noob_verify_peerId(data)) {
        mac = eap_noob_gen_MAC(data, MACP_TYPE, data->peer_attr->kdf_out->Kmp, KMP_LEN, data->peer_attr->peer_state);
        eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64);
        if (0 != strcmp(data->peer_attr->mac, (char *)mac)) {
            eap_noob_set_error(data->peer_attr,E4001); eap_noob_set_done(data, NOT_DONE); goto EXIT;
        }
        eap_noob_change_state(data, REGISTERED_STATE);
        if (FAILURE == eap_noob_db_functions(data,UPDATE_PERSISTENT_KEYS_SECRET)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Updating server state failed "); goto EXIT;
        }
        if (dir == SERVER_TO_PEER) eap_noob_del_temp_tuples(data);

        data->peer_attr->next_req = NONE;
        eap_noob_set_done(data, DONE); eap_noob_set_success(data, SUCCESS);
    }
EXIT:
    EAP_NOOB_FREE(mac_b64);
}

/**
 * eap_oob_rsp_type_three - Process EAP-Response Type 3
 * @data: Pointer to private EAP-NOOB data
 **/
static void eap_noob_rsp_type_three(struct eap_noob_server_context * data)
{
    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-WE-3");

    if (data->peer_attr->rcvd_params != TYPE_THREE_PARAMS) {
        eap_noob_set_error(data->peer_attr,E1002);
        eap_noob_set_done(data, NOT_DONE);
        return;
    }
    if ((data->peer_attr->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE);
        return;
    }

    if (eap_noob_verify_peerId(data)) {
        eap_noob_change_state(data, WAITING_FOR_OOB_STATE);
        data->peer_attr->next_req = NONE;
        eap_noob_set_done(data, DONE);
        eap_noob_set_success(data, FAILURE);
    }
}

/**
 * eap_oob_rsp_type_two - Process EAP-Response/Initial Exchange 2
 * @data: Pointer to private EAP-NOOB data
 **/
static void eap_noob_rsp_type_two(struct eap_noob_server_context * data)
{
    size_t secret_len = ECDH_SHARED_SECRET_LEN;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-IE-2");

    if (data->peer_attr->rcvd_params != TYPE_TWO_PARAMS) {
        eap_noob_set_error(data->peer_attr,E1002);
        eap_noob_set_done(data, NOT_DONE); return;
    }
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce Peer", data->peer_attr->kdf_nonce_data->Np, NONCE_LEN);
    if ((data->peer_attr->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }

    if (eap_noob_verify_peerId(data)) {
        wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce Peer", data->peer_attr->kdf_nonce_data->Np, NONCE_LEN);
        if (eap_noob_derive_session_secret(data,&secret_len) != SUCCESS) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in deriving shared key"); return;
        }
        eap_noob_Base64Encode(data->peer_attr->ecdh_exchange_data->shared_key,
          ECDH_SHARED_SECRET_LEN, &data->peer_attr->ecdh_exchange_data->shared_key_b64);
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Shared secret %s", data->peer_attr->ecdh_exchange_data->shared_key_b64);
        eap_noob_change_state(data, WAITING_FOR_OOB_STATE);

        // Generate the MAC input string such that it can be used for
        // calculating the Hoob.
        data->peer_attr->mac_input_str = eap_noob_build_mac_input(data, data->peer_attr->dir, data->peer_attr->server_state);

        if (FAILURE == eap_noob_db_functions(data, UPDATE_INITIALEXCHANGE_INFO)) {
            eap_noob_set_done(data, DONE);
            eap_noob_set_success(data,FAILURE);
            return;
        }

        data->peer_attr->next_req = NONE;
        eap_noob_set_done(data, DONE);
        eap_noob_set_success(data, FAILURE);
    }
}

/**
 * eap_oob_rsp_type_one - Process EAP-Response/Initial Exchange 1
 * @data: Pointer to private EAP-NOOB data
 * @payload: EAP data received from the peer
 * @payloadlen: Length of the payload
 **/
static void eap_noob_rsp_type_one(struct eap_sm *sm,
                                  struct eap_noob_server_context *data)
{
    /* Check for the supporting cryptosuites, PeerId, version, direction*/
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-IE-1");

    if (!data || !sm) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    if ((data->peer_attr->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if (data->peer_attr->rcvd_params != TYPE_ONE_PARAMS) {
        eap_noob_set_error(data->peer_attr,E1002);
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if (eap_noob_verify_peerId(data)) {
        data->peer_attr->next_req = EAP_NOOB_TYPE_2;
    }
    eap_noob_get_sid(sm, data); eap_noob_set_done(data, NOT_DONE);
    data->peer_attr->rcvd_params = 0;
}

static void eap_noob_rsp_noobid(struct eap_noob_server_context * data)
{
    if ((data->peer_attr->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE);
        return;
    }

    if (data->peer_attr->rcvd_params != TYPE_EIGHT_PARAMS) {
        eap_noob_set_error(data->peer_attr,E1002);
        eap_noob_set_done(data, NOT_DONE);
        return;
    }

    if (!eap_noob_verify_peerId(data)) {
        eap_noob_set_error(data->peer_attr,E2004);
        eap_noob_set_done(data, NOT_DONE);
        return;
    }

    if (!eap_noob_db_functions(data, GET_NOOBID) || NULL == data->peer_attr->oob_data->NoobId_b64) {
        eap_noob_set_error(data->peer_attr,E2003);
        eap_noob_set_done(data,NOT_DONE);
    } else {
        eap_noob_set_done(data, NOT_DONE);
        data->peer_attr->next_req = EAP_NOOB_TYPE_4;
    }

    data->peer_attr->rcvd_params = 0;
}

static void eap_noob_rsp_type_nine(struct eap_noob_server_context * data)
{
    int result = SUCCESS;
    char * input = NULL;
    const u8 * addr[1];
    size_t len[1];
    u8 hash[32];
    char * hoob_b64;
    int error = 0;

    // Initialize or reopen databases
    if (!(result = eap_noob_create_db(data))) {
        goto EXIT;
    }

    // TODO: Are these checks really necessary? Aren't these the only states in
    // which a message of type 9 is exchanged anyhow?
    if (data->peer_attr->server_state == UNREGISTERED_STATE ||
        data->peer_attr->server_state == WAITING_FOR_OOB_STATE ||
        data->peer_attr->server_state == RECONNECTING_STATE) {
        if (FAILURE == (result = eap_noob_read_config(data))) {
            goto EXIT;
        }
    }

    // Check whether new OOB data has arrived, if so, verify the Hoob
    if (data->peer_attr->server_state == WAITING_FOR_OOB_STATE &&
        data->peer_attr->dir == PEER_TO_SERVER) {
        // Retrieve OOB data from the database
        if (FAILURE == eap_noob_exec_query(data, QUERY_EPHEMERALNOOB, columns_ephemeralnoob, 2, TEXT, data->peer_attr->peerid_rcvd)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Error while retrieving OOB data from the database");
            result = FAILURE;
            goto EXIT;
        }

        // There must be OOB data available before continuing
        if (data->peer_attr->oob_data->Hoob_b64 &&
            data->peer_attr->oob_data->Noob_b64) {
            // Build the Hoob input for the local calculation
            input = eap_noob_build_mac_input(data, data->peer_attr->dir, data->peer_attr->server_state);
            if (!input) {
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to build Hoob input");
                result = FAILURE;
                goto EXIT;
            }

            addr[0] = (u8 *) input;
            len[0] = os_strlen(input);

            // Perform the SHA-256 hash operation on the Hoob input
            error = sha256_vector(1, addr, len, hash);
            if (error) {
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Error while creating SHA-256 hash");
                result = FAILURE;
                goto EXIT;
            }

            // Encode the Hoob in base64
            // As per the specification in the EAP-NOOB standard, the length of the
            // Hoob should be 16 bytes, which is 22 bytes after base64 encoding.
            eap_noob_Base64Encode(hash, HASH_LEN, &hoob_b64);
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Local Hoob base64 %s", hoob_b64);

            // Verify the locally generated Hoob against the one received out-of-band
            if (!os_strcmp(hoob_b64, data->peer_attr->oob_data->Hoob_b64)) {
                // Both Hoobs are equal, thus the received OOB data is valid and
                // the server moves on to the next state.
                eap_noob_change_state(data, OOB_RECEIVED_STATE);
            } else {
                wpa_printf(MSG_INFO, "EAP-NOOB: Received Hoob does not match local Hoob");

                // Increase number of invalid Hoobs received
                data->peer_attr->oob_retries++;
                wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB retries = %d", data->peer_attr->oob_retries);
                eap_noob_db_functions(data, UPDATE_OOB_RETRIES);

                // Reset the server to Unregistered state if the maximum
                // number of OOB retries (i.e. invalid Hoobs) has been reached.
                if (data->peer_attr->oob_retries >= data->server_attr->max_oob_retries) {
                    eap_noob_change_state(data, UNREGISTERED_STATE);
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Max OOB retries exceeded. Reset server to Unregistered state");
                    // Remove the current Ephemeral entries
                    eap_noob_db_functions(data, DELETE_EPHEMERAL);
                }
            }
        }
    }

    // Determine the next request message that the server should send to the peer
    // after concluding the common handshake.
    if (data->peer_attr->err_code == NO_ERROR) {
        data->peer_attr->next_req = eap_noob_get_next_req(data);
    } else {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Could not get next request type, error in peer attr: %d", data->peer_attr->err_code);
        result = FAILURE;
        goto EXIT;
    }
EXIT:
    if (result == FAILURE) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Error while handling response message type 9");
    }
    data->peer_attr->rcvd_params = 0;
}

/**
 * eap_oob_process - Control Process EAP-Response.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @priv: Pointer to private EAP-NOOB data
 * @respData: EAP response to be processed (eapRespData)
 **/
static void eap_noob_process(struct eap_sm * sm, void * priv, struct wpabuf * respData)
{
    struct eap_noob_server_context * data = NULL;
    struct json_token * resp_obj = NULL;
    const u8 * pos = NULL;
    size_t len = 0;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: PROCESS SERVER");

    if (NULL == sm || NULL == priv || NULL == respData) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return;
    }

    data = priv;
    pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_NOOB, respData, &len);

    if (NULL == pos || len < 1) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in eap header validation, %s",__func__);
        goto EXIT;
    }

    if (data->peer_attr->err_code != NO_ERROR) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error not none, exiting, %s", __func__);
        goto EXIT;
    }

    resp_obj = json_parse((char *) pos, os_strlen((char *) pos));
    if (!resp_obj) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error allocating json obj, %s", __func__);
        goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: RECEIVED RESPONSE = %s", pos);

    // Decode the JSON object and store it locally
    // This way, all methods will be able to access it.
    eap_noob_decode_obj(data->peer_attr, resp_obj);
    if (data->peer_attr->err_code != NO_ERROR) {
        goto EXIT;
    }

    /* TODO : replce switch case with function pointers. */
    switch (data->peer_attr->recv_msg) {
        case EAP_NOOB_TYPE_1:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 1");
            eap_noob_rsp_type_one(sm, data);
            break;

        case EAP_NOOB_TYPE_2:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 2");
            eap_noob_rsp_type_two(data);
            break;

        case EAP_NOOB_TYPE_3:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 3");
            eap_noob_rsp_type_three(data);
            break;

        case EAP_NOOB_TYPE_4:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 4");
            eap_noob_rsp_type_four(data);
            break;

        case EAP_NOOB_TYPE_5:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 5");
            eap_noob_rsp_type_five(data);
            break;

        case EAP_NOOB_TYPE_6:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 6");
            eap_noob_rsp_type_six(data);
            break;

        case EAP_NOOB_TYPE_7:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 7");
            eap_noob_rsp_type_seven(data);
            break;
        case EAP_NOOB_TYPE_8:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE NoobId");
            eap_noob_rsp_noobid(data);
            break;
        case EAP_NOOB_TYPE_9:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 9");
            eap_noob_rsp_type_nine(data);
            break;

        case NONE:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ERROR received");
            if (FAILURE == eap_noob_db_functions(data, UPDATE_STATE_ERROR)) {
                wpa_printf(MSG_DEBUG,"Fail to Write Error to DB");
            }

            eap_noob_set_done(data, DONE);
            eap_noob_set_success(data, FAILURE);
            break;
    }
    data->peer_attr->recv_msg = 0;
EXIT:
    ;
    //json_free(resp_obj);
}


static _Bool eap_noob_isDone(struct eap_sm *sm, void *priv)
{

    struct eap_noob_server_context *data = priv;
    printf("DONE   = %d\n",data->peer_attr->is_done);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: IS Done? %d",(data->peer_attr->is_done == DONE));
    return (data->peer_attr->is_done == DONE);
}

/**
 * eap_oob_isSuccess - Check EAP-NOOB was successful.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @priv: Pointer to private EAP-NOOB data
 * Returns: True if EAP-NOOB is successful, False otherwise.
 **/
static _Bool eap_noob_isSuccess(struct eap_sm *sm, void *priv)
{
    struct eap_noob_server_context *data = priv;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: IS SUCCESS? %d",(data->peer_attr->is_success == SUCCESS));
    return (data->peer_attr->is_success == SUCCESS);
}

/**
 * eap_noob_getKey : gets the msk if available
 * @sm : eap statemachine context
 * @priv : eap noob data
 * @len : msk len
 * Returns MSK or NULL
**/
static u8 * eap_noob_getKey(struct eap_sm * sm, void * priv, size_t * len)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB: GET KEY");
    struct eap_noob_server_context *data = NULL;
    u8 *key = NULL;

    if (!priv || !sm || !len) return NULL;
    data = priv;

    if ((data->peer_attr->server_state != REGISTERED_STATE) || (!data->peer_attr->kdf_out->msk))
        return NULL;

    //Base64Decode((char *)data->peer_attr->kdf_out->msk_b64, &data->peer_attr->kdf_out->msk, len);
    if (NULL == (key = os_malloc(MSK_LEN)))
        return NULL;

    *len = MSK_LEN;
    os_memcpy(key, data->peer_attr->kdf_out->msk, MSK_LEN);
    //memset(key,1,64);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: MSK Derived", key, MSK_LEN);
    return key;
}


/**
 * eap_noob_get_session_id : gets the session id if available
 * @sm : eap statemachine context
 * @priv : eap noob data
 * @len : session id len
 * Returns Session Id or NULL
**/
static u8 * eap_noob_get_session_id(struct eap_sm *sm, void *priv, size_t *len)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB:Get Session ID called");
    struct eap_noob_server_context *data = NULL;
    u8 *session_id = NULL;

    if (!priv || !sm || !len) return NULL;
  	data = priv;

    if ((data->peer_attr->server_state != REGISTERED_STATE) || (!data->peer_attr->kdf_out->MethodId))
        return NULL;

    if (NULL == (session_id = os_malloc(1 + METHOD_ID_LEN)))
        return NULL;


    *len = 1 + METHOD_ID_LEN;

    session_id[0] = EAP_TYPE_NOOB;
    os_memcpy(session_id + 1, data->peer_attr->kdf_out->MethodId, METHOD_ID_LEN);
    wpa_hexdump(MSG_DEBUG, "EAP-NOOB: Derived Session-Id", session_id, *len);

    return session_id;
}

/**
 * eap_noob_get_emsk : gets the msk if available
 * @sm : eap statemachine context
 * @priv : eap noob data
 * @len : msk len
 * Returns EMSK or NULL
**/
static u8 * eap_noob_get_emsk(struct eap_sm * sm, void * priv, size_t * len)
{
    struct eap_noob_server_context * data = NULL;
    u8 * emsk = NULL;
    wpa_printf(MSG_DEBUG, "EAP-NOOB:Get EMSK called");

    if (!priv || !sm || !len) return NULL;
    data = priv;

    if ((data->peer_attr->server_state != REGISTERED_STATE) || (!data->peer_attr->kdf_out->emsk))
        return NULL;
    if (NULL == (emsk = os_malloc(EAP_EMSK_LEN)))
        return NULL;
    os_memcpy(emsk, data->peer_attr->kdf_out->emsk, EAP_EMSK_LEN);
    if (emsk) {
        *len = EAP_EMSK_LEN; wpa_hexdump(MSG_DEBUG, "EAP-NOOB: Copied EMSK", emsk, EAP_EMSK_LEN);
    } else
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to fetch EMSK");

    return emsk;
}


static int eap_noob_getTimeout(struct eap_sm *sm, void *priv)
{
    //struct eap_oob_server_context *data = priv;

    printf("In function %s\n",__func__);
    /* Recommended retransmit times: retransmit timeout 5 seconds,
     * per-message timeout 15 seconds, i.e., 3 tries. */
    sm->MaxRetrans = 0; /* total 3 attempts */
    return 1;
}

/**
 * eap_noob_server_ctxt_alloc : Allocates the subcontexts inside the peer context
 * @sm : eap method context
 * @peer : server context
 * Returns : SUCCESS/FAILURE
 **/
static int eap_noob_server_ctxt_alloc(struct eap_sm * sm, struct eap_noob_server_context * data)
{
    if (!data || !sm) return FAILURE;

    if (NULL == (data->peer_attr = \
          os_zalloc(sizeof (struct eap_noob_peer_data)))) {
        return FAILURE;
    }

    if ((NULL == (data->server_attr = \
           os_zalloc(sizeof (struct eap_noob_server_data))))) {
        return FAILURE;
    }

    if ((NULL == (data->peer_attr->ecdh_exchange_data = \
           os_zalloc(sizeof (struct eap_noob_ecdh_key_exchange))))) {
        return FAILURE;
    }

    if ((NULL == (data->peer_attr->oob_data = \
           os_zalloc(sizeof (struct eap_noob_oob_data))))) {
        return FAILURE;
    }

    if ((NULL == (data->peer_attr->kdf_out = \
           os_zalloc(sizeof (struct eap_noob_ecdh_kdf_out))))) {
        return FAILURE;
    }

    if ((NULL == (data->peer_attr->kdf_nonce_data = \
           os_zalloc(sizeof (struct eap_noob_ecdh_kdf_nonce))))) {
        return FAILURE;
    }

    return SUCCESS;
}

/**
 * eap_noob_server_ctxt_init -Supporting Initializer for EAP-NOOB Peer Method
 * Allocates memory for the EAP-NOOB data
 * @data: Pointer to EAP-NOOB data
 * @sm : eap method context
 **/
static int eap_noob_server_ctxt_init(struct eap_noob_server_context * data, struct eap_sm * sm)
{
    char * NAI = NULL;
    int retval = FAILURE;

    if (FAILURE == eap_noob_server_ctxt_alloc(sm, data))
        return FAILURE;

    data->peer_attr->server_state = UNREGISTERED_STATE;
    data->peer_attr->peer_state = UNREGISTERED_STATE;
    data->peer_attr->err_code = NO_ERROR;
    data->peer_attr->rcvd_params = 0;
    data->peer_attr->sleep_count = 0;

    /* Setup DB. DB file name for the server */
    data->db_name = (char *) os_strdup(DB_NAME);

    if (server_conf.read_conf == 0 && FAILURE == eap_noob_read_config(data)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to initialize context");
        return FAILURE;
    }

    if (sm->identity) {
        NAI = os_zalloc(sm->identity_len+1);
        if (NULL == NAI) {
            eap_noob_set_error(data->peer_attr, E1001);
            return FAILURE;
        }
        os_memcpy(NAI, sm->identity, sm->identity_len);
        strcat(NAI, "\0");
    }

    if (SUCCESS == (retval = eap_noob_parse_NAI(data, NAI))) {
        if (data->peer_attr->err_code == NO_ERROR) {
            // Always set the next request to type 9, because every Exchange
            // must start with the Common Handshake,
            // as per version 8 of the draft.
            data->peer_attr->next_req = EAP_NOOB_TYPE_9;
        }
    }

    EAP_NOOB_FREE(NAI);
    if (retval == FAILURE)
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to initialize context");
    return retval;
}

/**
 * eap_noob_free_ctx : Free up all memory in server context
 * @data: Pointer to EAP-NOOB data
 **/
static void eap_noob_free_ctx(struct eap_noob_server_context * data)
{
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return;
    }

    struct eap_noob_peer_data * peer = data->peer_attr;
    struct eap_noob_server_data * serv = data->server_attr;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    if (serv) {
        EAP_NOOB_FREE(serv->server_info);
        if (serv->server_config_params) {
            EAP_NOOB_FREE(serv->server_config_params->ServerName);
            EAP_NOOB_FREE(serv->server_config_params->ServerURL);
            os_free(serv->server_config_params);
            serv->server_config_params = NULL;
        }
        os_free(serv); serv = NULL;
    }
    if (peer) {
        EAP_NOOB_FREE(peer->PeerId);
        EAP_NOOB_FREE(peer->peerid_rcvd);
        EAP_NOOB_FREE(peer->peerinfo);
        EAP_NOOB_FREE(peer->peer_snum);
        EAP_NOOB_FREE(peer->mac);
        if (peer->kdf_nonce_data) {
            EAP_NOOB_FREE(peer->kdf_nonce_data->Np);
            EAP_NOOB_FREE(peer->kdf_nonce_data->nonce_peer_b64);
            EAP_NOOB_FREE(peer->kdf_nonce_data->Ns);
            //EAP_NOOB_FREE(peer->kdf_nonce_data->nonce_server_b64);
            os_free(peer->kdf_nonce_data);
            peer->kdf_nonce_data = NULL;
        }
        if (peer->ecdh_exchange_data) {
            EVP_PKEY_free(peer->ecdh_exchange_data->dh_key);
            EAP_NOOB_FREE(peer->ecdh_exchange_data->shared_key);
            EAP_NOOB_FREE(peer->ecdh_exchange_data->shared_key_b64);
            EAP_NOOB_FREE(peer->ecdh_exchange_data->x_peer_b64);
            EAP_NOOB_FREE(peer->ecdh_exchange_data->y_peer_b64);
            EAP_NOOB_FREE(peer->ecdh_exchange_data->x_b64);
            //EAP_NOOB_FREE(peer->ecdh_exchange_data->y_b64);
            EAP_NOOB_FREE(peer->ecdh_exchange_data->jwk_serv);
            EAP_NOOB_FREE(peer->ecdh_exchange_data->jwk_peer);
            os_free(peer->ecdh_exchange_data);
            peer->ecdh_exchange_data = NULL;
        }
        if (peer->oob_data) {
            EAP_NOOB_FREE(peer->oob_data->Noob_b64);
            EAP_NOOB_FREE(peer->oob_data->NoobId_b64);
            EAP_NOOB_FREE(peer->oob_data->Hoob_b64);
            os_free(peer->oob_data); peer->oob_data = NULL;
        }
        if (peer->kdf_out) {
            EAP_NOOB_FREE(peer->kdf_out->msk);
            EAP_NOOB_FREE(peer->kdf_out->emsk);
            EAP_NOOB_FREE(peer->kdf_out->amsk);
            EAP_NOOB_FREE(peer->kdf_out->MethodId);
            EAP_NOOB_FREE(peer->kdf_out->Kms);
            EAP_NOOB_FREE(peer->kdf_out->Kmp);
            EAP_NOOB_FREE(peer->kdf_out->Kz);
            os_free(peer->kdf_out); peer->kdf_out = NULL;
        }
        os_free(peer); peer = NULL;
    }

    if (SQLITE_OK != sqlite3_close_v2(data->server_db)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error closing DB");
        char * sql_error = (char *)sqlite3_errmsg(data->server_db);
        if (sql_error != NULL)
            wpa_printf(MSG_DEBUG,"EAP-NOOB: SQL error : %s\n", sql_error);
    }

    EAP_NOOB_FREE(data->db_name);
    os_free(data); data = NULL;
}

/**
 * eap_oob_reset - Release/Reset EAP-NOOB data that is not needed.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @priv: Pointer to private EAP-NOOB data
 **/
static void eap_noob_reset(struct eap_sm * sm, void * priv)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB: RESET SERVER");
    struct eap_noob_server_context *data = priv;

    eap_noob_free_ctx(data);
}

/**
 * eap_noob_init - Initialize the EAP-NOOB Peer Method
 * Allocates memory for the EAP-NOOB data
 * @sm: Pointer to EAP State Machine data
 **/
static void * eap_noob_init(struct eap_sm *sm)
{
    struct eap_noob_server_context * data = NULL;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: INIT SERVER");

    if (NULL == (data = os_zalloc( sizeof (struct eap_noob_server_context)))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: INIT SERVER Fail to Allocate Memory");
        return NULL;
    }

    //TODO: check if hard coded initialization can be avoided
    if (FAILURE == eap_noob_server_ctxt_init(data,sm) && data->peer_attr->err_code == NO_ERROR) {
        wpa_printf(MSG_DEBUG,"EAP-NOOB: INIT SERVER Fail to initialize context");
        eap_noob_free_ctx(data);
        return NULL;
    }

    return data;
}

/**
 * eap_server_noob_register - Register EAP-NOOB as a supported EAP peer method.
 * Returns: 0 on success, -1 on invalid method, or -2 if a matching EAP
 * method has already been registered
 **/
int eap_server_noob_register(void)
{
    struct eap_method *eap = NULL;

    eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
            EAP_VENDOR_IETF, EAP_TYPE_NOOB, "NOOB");
    if (eap == NULL)
        return -1;

    eap->init = eap_noob_init;
    eap->reset = eap_noob_reset;
    eap->buildReq = eap_noob_buildReq;
    eap->check = eap_noob_check;
    eap->process = eap_noob_process;
    eap->isDone = eap_noob_isDone;
    eap->getKey = eap_noob_getKey;
    eap->get_emsk = eap_noob_get_emsk;
    eap->isSuccess = eap_noob_isSuccess;
    eap->getSessionId = eap_noob_get_session_id;
    eap->getTimeout = eap_noob_getTimeout;

    return eap_server_method_register(eap);
}
