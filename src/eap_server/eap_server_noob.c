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
#include "eap_common/eap_noob_common.h"
#include "eap_i.h"
#include "eap_server_noob.h"

static struct eap_noob_global_conf server_conf;

static inline void eap_noob_set_done(struct eap_noob_data * data, int val)
{
    data->is_done = val;
}

static inline void eap_noob_set_success(struct eap_noob_data * data, int val)
{
    data->is_success = val;
}

static inline void eap_noob_change_state(struct eap_noob_data * data, int val)
{
    data->server_state = val;
}

/**
 * eap_noob_verify_peerId : Compares recived PeerId with the assigned one
 * @data : server data
 * @return : SUCCESS or FAILURE
 **/
static int eap_noob_verify_peerId(struct eap_noob_data * data)
{
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: server data null in %s", __func__);
        return FAILURE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
    if (0 != strcmp(data->peerid, data->peerid_rcvd)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Verification of PeerId failed, setting error E2004");
        eap_noob_set_error(data, E2004); return FAILURE;
    }
    return SUCCESS;
}

static void columns_persistentstate(struct eap_noob_data * data, sqlite3_stmt * stmt)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB: In %s", __func__);
    data->version = sqlite3_column_int(stmt, 1);
    data->cryptosuite = sqlite3_column_int(stmt, 2);
    data->realm = os_strdup((char *) sqlite3_column_text(stmt, 3));
    data->Kz = os_memdup(sqlite3_column_blob(stmt, 4), KZ_LEN);
    data->server_state = sqlite3_column_int(stmt, 5);
    data->creation_time = (uint64_t) sqlite3_column_int64(stmt, 6);
    data->last_used_time = (uint64_t) sqlite3_column_int64(stmt, 7);
}

static void columns_ephemeralstate(struct eap_noob_data * data, sqlite3_stmt * stmt)
{
    data->version = sqlite3_column_int(stmt, 1);
    data->cryptosuite = sqlite3_column_int(stmt, 2);
    data->realm = os_strdup((char *) sqlite3_column_text(stmt, 3));
    data->dirp = sqlite3_column_int(stmt, 4);
    data->peer_info = os_strdup((char *) sqlite3_column_text(stmt, 5));
    data->kdf_nonce_data->Ns = os_memdup(sqlite3_column_blob(stmt, 6), NONCE_LEN);
    data->kdf_nonce_data->Np = os_memdup(sqlite3_column_blob(stmt, 7), NONCE_LEN);
    data->ecdh_exchange_data->shared_key = os_memdup(sqlite3_column_blob(stmt, 8), ECDH_SHARED_SECRET_LEN);
    data->mac_input_str = os_strdup((char *) sqlite3_column_text(stmt, 9));
    data->creation_time = (uint64_t) sqlite3_column_int64(stmt, 10);
    data->err_code = sqlite3_column_int(stmt, 11);
    data->sleep_count = sqlite3_column_int(stmt, 12);
    data->server_state = sqlite3_column_int(stmt, 13);
    data->ecdh_exchange_data->jwk_serv = os_strdup((char *) sqlite3_column_text(stmt, 14));
    data->ecdh_exchange_data->jwk_peer = os_strdup((char *) sqlite3_column_text(stmt, 15));
    data->oob_retries = sqlite3_column_int(stmt, 16);
}

static void columns_ephemeralnoob(struct eap_noob_data * data, sqlite3_stmt * stmt)
{
    data->oob_data->NoobId_b64 = os_strdup((char *)sqlite3_column_text(stmt, 1));
    data->oob_data->Noob_b64 = os_strdup((char *)sqlite3_column_text(stmt, 2));
    data->oob_data->Hoob_b64 = os_strdup((char *) sqlite3_column_text(stmt, 3));
    data->oob_data->sent_time = (uint64_t) sqlite3_column_int64(stmt, 4);
}

/**
 * eap_noob_db_functions : Execute various DB queries
 * @data : server data
 * @type : type of update
 * Returns : SUCCESS/FAILURE
 **/
static int eap_noob_db_functions(struct eap_noob_data * data, u8 type)
{
    char query[MAX_LINE_SIZE] = {0};
    char * dump_str = NULL;
    int ret = FAILURE;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: server data is NULL"); return FAILURE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);
    switch(type) {
        case UPDATE_PERSISTENT_STATE:
            os_snprintf(query, MAX_LINE_SIZE, "UPDATE PersistentState SET ServerState=? where PeerId=?");
            ret = eap_noob_exec_query(data, query, NULL, 4, INT, data->server_state,
                  TEXT, data->peerid);
            break;
        case UPDATE_STATE_ERROR:
            os_snprintf(query, MAX_LINE_SIZE, "UPDATE EphemeralState SET ServerState=?, ErrorCode=? where PeerId=?");
            ret = eap_noob_exec_query(data, query, NULL, 6, INT, data->server_state, INT,
                  data->err_code, TEXT, data->peerid);
            break;
        case UPDATE_OOB_RETRIES:
            os_snprintf(query, MAX_LINE_SIZE, "UPDATE EphemeralState SET OobRetries=? WHERE PeerId=?");
            ret = eap_noob_exec_query(data, query, NULL, 4, INT, data->oob_retries,
                                      TEXT, data->peerid);
            break;
        case DELETE_EPHEMERAL:
            os_snprintf(query, MAX_LINE_SIZE, "DELETE FROM EphemeralState WHERE PeerId=?");
            ret = eap_noob_exec_query(data, query, NULL, 2, TEXT, data->peerid);

            os_snprintf(query, MAX_LINE_SIZE, "DELETE FROM EphemeralNoob WHERE PeerId=?");
            ret &= eap_noob_exec_query(data, query, NULL, 2, TEXT, data->peerid);
            break;
        case UPDATE_STATE_MINSLP:
            os_snprintf(query, MAX_LINE_SIZE, "UPDATE EphemeralState SET ServerState=?, SleepCount =? where PeerId=?");
            ret = eap_noob_exec_query(data, query, NULL, 6, INT, data->server_state, INT,
                  data->sleep_count, TEXT, data->peerid);
            break;
        case UPDATE_PERSISTENT_KEYS_SECRET:
            os_snprintf(query, MAX_LINE_SIZE, "DELETE FROM EphemeralState WHERE PeerId=?");
            if (FAILURE == eap_noob_exec_query(data, query, NULL, 2, TEXT, data->peerid))
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Unexpected error in deleting entry in EphemeralState");
            os_snprintf(query, MAX_LINE_SIZE, "DELETE FROM EphemeralNoob WHERE PeerId=?");
            if (FAILURE == eap_noob_exec_query(data, query, NULL, 2, TEXT, data->peerid))
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Unexpected error in deleting entry in EphemeralNoob");
            os_snprintf(query, MAX_LINE_SIZE, "INSERT INTO PersistentState (PeerId, Verp, Cryptosuitep, Realm, Kz, "
                    "ServerState, PeerInfo) VALUES(?, ?, ?, ?, ?, ?, ?)");
            ret = eap_noob_exec_query(data, query, NULL, 14, TEXT, data->peerid, INT, data->version,
                  INT, data->cryptosuite, TEXT, server_conf.realm, BLOB, KZ_LEN, data->kdf_out->Kz, INT,
                  data->server_state, TEXT, data->peer_info);
            break;
        case UPDATE_INITIALEXCHANGE_INFO:
            os_snprintf(query, MAX_LINE_SIZE, "INSERT INTO EphemeralState ( PeerId, Verp, Cryptosuitep, Realm, Dirp, PeerInfo, "
                  "Ns, Np, Z, MacInput, SleepCount, ServerState, JwkServer, JwkPeer, OobRetries) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            ret = eap_noob_exec_query(data, query, NULL, 33, TEXT, data->peerid, INT, data->version,
                  INT, data->cryptosuite, TEXT, server_conf.realm, INT, data->dirp, TEXT,
                  data->peer_info, BLOB, NONCE_LEN, data->kdf_nonce_data->Ns, BLOB, NONCE_LEN,
                  data->kdf_nonce_data->Np, BLOB, ECDH_SHARED_SECRET_LEN, data->ecdh_exchange_data->shared_key,
                  TEXT, data->mac_input_str, INT, data->sleep_count, INT, data->server_state,
                  TEXT, data->ecdh_exchange_data->jwk_serv, TEXT, data->ecdh_exchange_data->jwk_peer, INT, 0);
            os_free(dump_str);
            break;
        case GET_NOOBID:
            os_snprintf(query, MAX_LINE_SIZE, "SELECT * FROM EphemeralNoob WHERE PeerId=? AND NoobId=?;");
            ret = eap_noob_exec_query(data, query, columns_ephemeralnoob, 4, TEXT, data->peerid, TEXT,
                  data->oob_data->NoobId_b64);
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
static int eap_noob_get_next_req(struct eap_noob_data * data)
{
    int retval = NONE;
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: server data is NULL");
        return retval;
    }
    if (EAP_NOOB_STATE_VALID) {
        retval = next_request_type[(data->server_state * NUM_OF_STATES) \
                 + data->peer_state];
    }
    wpa_printf (MSG_DEBUG,"EAP-NOOB:Serv state = %d, Peer state = %d, Next req =%d",
                data->server_state, data->peer_state, retval);
    if (retval == EAP_NOOB_TYPE_RECONNECT_PARAMS) {
        data->server_state = RECONNECTING_STATE;
        if (FAILURE == eap_noob_db_functions(data, UPDATE_PERSISTENT_STATE))
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Error updating state to Reconnecting");
    }

    if ((data->dirp == SERVER_TO_PEER)  && (retval == EAP_NOOB_TYPE_COMPLETION_HMAC)) {
        retval = EAP_NOOB_TYPE_COMPLETION_NOOBID;
        wpa_printf(MSG_DEBUG,"EAP-NOOB: NoobId Required: True");
    }

    if (retval == EAP_NOOB_TYPE_WAITING) { //checking for max WE count if type is 3
        if (server_conf.max_we_count <= data->sleep_count) {
            eap_noob_set_error(data, E2001); return NONE;
        } else {
            data->sleep_count++;
            if (FAILURE == eap_noob_db_functions(data, UPDATE_STATE_MINSLP)) {
                wpa_printf(MSG_DEBUG,"EAP-NOOB: Min Sleep DB update Error");
                eap_noob_set_error(data,E2001); return NONE;
            }
        }
    }
    return retval;
}

/**
 * eap_noob_parse_NAI: Parse NAI
 * @data : server data
 * @NAI  : Network Access Identifier
 * Returns : FAILURE/SUCCESS
 **/
static int eap_noob_parse_NAI(struct eap_noob_data * data, const char * NAI)
{
    char * user_name_peer = NULL;
    char * realm = NULL;
    char * _NAI = NULL;

    if (NULL == NAI || NULL == data) {
        eap_noob_set_error(data, E1001); return FAILURE;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s, parsing NAI (%s)",__func__, NAI);

    _NAI = (char *)NAI;

    if (os_strstr(_NAI, DEFAULT_REALM) || os_strstr(_NAI, server_conf.realm)) {
        user_name_peer = strsep(&_NAI, "@");
        realm = strsep(&_NAI, "@");

        if (strlen(user_name_peer) > MAX_PEER_ID_LEN) {
            eap_noob_set_error(data,E1001);
            return FAILURE;
        }

        // If user part of the NAI is not equal to "noob", the NAI is invalid
        if (strcmp("noob", user_name_peer)) {
			eap_noob_set_error(data, E1001);
			return FAILURE;
		}

        // TODO: This if-else block is unnecessary, taking into account all
        // previously conducted tests.
        if (0 == strcmp(realm, server_conf.realm)) {
            return SUCCESS;
        } else if (0 == strcmp("noob", user_name_peer) && 0 == strcmp(realm, DEFAULT_REALM)) {
            data->peer_state = UNREGISTERED_STATE;
            return SUCCESS;
        }
    }

    // NAI realm is neither the DEFAULT_REALM nor the configured realm
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, setting error E1001",__func__);
    eap_noob_set_error(data, E1001);
    return FAILURE;
}

static int eap_noob_query_ephemeralstate(struct eap_noob_data * data)
{
    if (FAILURE == eap_noob_exec_query(data, QUERY_EPHEMERALSTATE, columns_ephemeralstate, 2,
                   TEXT, data->peerid_rcvd)) {
        wpa_printf(MSG_DEBUG, "Peer not found in ephemeral table");
        if (FAILURE == eap_noob_exec_query(data, QUERY_PERSISTENTSTATE, columns_persistentstate, 2,
                   TEXT, data->peerid_rcvd)) {
            eap_noob_set_error(data, E2004); /* Unexpected peerId */
            return FAILURE;
        } else {
            eap_noob_set_error(data, E1001); /* Invalid NAI or peer state */
            return FAILURE;
        }
    }

    if (data->server_state == OOB_RECEIVED_STATE) {
        if (FAILURE == eap_noob_exec_query(data, QUERY_EPHEMERALNOOB, columns_ephemeralnoob, 2,
                TEXT, data->peerid_rcvd)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in retreiving NoobId");
            return FAILURE;
        }
        wpa_printf(MSG_DEBUG, "EAP-NOOB: PeerId %s", data->peerid_rcvd);
    }
    return SUCCESS;
}

static int eap_noob_query_persistentstate(struct eap_noob_data * data)
{
    if (FAILURE == eap_noob_exec_query(data, QUERY_PERSISTENTSTATE, columns_persistentstate, 2,
                   TEXT, data->peerid_rcvd)) {
        if (FAILURE == eap_noob_exec_query(data, QUERY_EPHEMERALSTATE, columns_ephemeralstate, 2,
                    TEXT, data->peerid_rcvd)) {
            eap_noob_set_error(data, E2004);
            return FAILURE;
        } else {
            eap_noob_set_error(data, E1001);
            return FAILURE;
        }
    }
    return SUCCESS;
}

/**
 * eap_noob_create_db : Creates a new DB or opens the existing DB and
 *                      populates the context
 * @data : server data
 * returns : SUCCESS/FAILURE
 **/
static int eap_noob_create_db(struct eap_noob_data * data)
{
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return FAILURE;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
    if (SQLITE_OK != sqlite3_open_v2(DB_NAME, &data->db,
                SQLITE_OPEN_READWRITE| SQLITE_OPEN_CREATE, NULL)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to open and Create Table");
        return FAILURE;
    }

    if (FAILURE == eap_noob_db_statements(data->db, CREATE_TABLES_EPHEMERALSTATE) ||
        FAILURE == eap_noob_db_statements(data->db, CREATE_TABLES_PERSISTENTSTATE)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Unexpected error in table creation");
        return FAILURE;
    }
    /* Based on peer_state, decide which table to query */
    if (data->peerid_rcvd) {
        data->peerid = os_strdup(data->peerid_rcvd);
        if (data->peer_state <= OOB_RECEIVED_STATE)
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
 * @data : server data
 **/
static void eap_noob_assign_config(char * conf_name, char * conf_value, struct eap_noob_data * data)
{
    if (NULL == conf_name || NULL == conf_value || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return;
    }

    /*TODO : version and csuite are directly converted to integer.
     * This needs to be changed if more than one csuite or version is supported. */
    wpa_printf(MSG_DEBUG, "EAP-NOOB: CONF Name = %s %d", conf_name, (int)strlen(conf_name));
    if (0 == strcmp("Version", conf_name)) {
        data->versions[0] = (int) strtol(conf_value, NULL, 10); data->config_params |= VERSION_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d", data->versions[0]);
    }
    else if (0 == strcmp("Csuite",conf_name)) {
        data->cryptosuites[0] = (int) strtol(conf_value, NULL, 10); data->config_params |= CRYPTOSUITE_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d", data->cryptosuites[0]);
    }
    else if (0 == strcmp("OobDirs",conf_name)) {
        data->dirs = (int) strtol(conf_value, NULL, 10); data->config_params |= DIR_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d", data->dirs);
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
        data->realm = os_strdup(server_conf.realm);
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
static void eap_noob_parse_config(char * buff, struct eap_noob_data * data)
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
static int eap_noob_handle_incomplete_conf(struct eap_noob_data * data)
{
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return FAILURE;
    }

    if (0 == (data->config_params & SERVER_URL_RCVD) ||
        0 == (data->config_params & SERVER_NAME_RCVD)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: ServerName or ServerURL missing"); return FAILURE;
    }

    if (0 == (data->config_params & ENCODE_RCVD)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Encoding Scheme not specified"); return FAILURE;
    }

    /* set default values if not provided via config */
    if (0 == (data->config_params & VERSION_RCVD))
        data->versions[0] = VERSION_ONE;

    if (0 == (data->config_params & CRYPTOSUITE_RCVD))
        data->cryptosuites[0] = SUITE_ONE;

    if (0 == (data->config_params & DIR_RCVD))
        data->dirs = BOTH_DIRECTIONS;

    if (0 == (data->config_params & MAX_OOB_RETRIES_RCVD)) {
        data->max_oob_retries = DEFAULT_MAX_OOB_RETRIES;
    }

    if (0 == (data->config_params & WE_COUNT_RCVD))
        server_conf.max_we_count = MAX_WAIT_EXCHNG_TRIES;

    if (0 == (data->config_params & REALM_RCVD))
        server_conf.realm = os_strdup(DEFAULT_REALM);

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
 * @data : server data
 * Returns : SUCCESS/FAILURE
**/
static int eap_noob_read_config(struct eap_noob_data * data)
{
    FILE * conf_file = NULL;
    char * buff = NULL;
    int ret = SUCCESS;

    if (NULL == data) {
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
    if (NULL == (data->server_config_params =
            os_malloc(sizeof(struct eap_noob_server_config_params)))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in allocating memory.");
        ret = FAILURE; goto ERROR_EXIT;
    }

    data->config_params = 0;
    while(!feof(conf_file)) {
        if (fgets(buff, MAX_CONF_LEN, conf_file)) {
            eap_noob_parse_config(buff, data);
            memset(buff, 0, MAX_CONF_LEN);
        }
    }

    if ((data->versions[0] > MAX_SUP_VER) || (data->cryptosuites[0] > MAX_SUP_CSUITES) ||
        (data->dirs > BOTH_DIRECTIONS)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect confing value");
        ret = FAILURE; goto ERROR_EXIT;
    }

    if (data->config_params != CONF_PARAMS && FAILURE == eap_noob_handle_incomplete_conf(data)) {
        ret = FAILURE; goto ERROR_EXIT;
    }

    data->server_info =  eap_noob_prepare_server_info_string(data->server_config_params);
    if(!data->server_info){
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to prepare ServerInfo string!");
        ret = FAILURE; goto ERROR_EXIT;
    }

ERROR_EXIT:
    if (ret != SUCCESS)
        EAP_NOOB_FREE(data->server_config_params);
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

static void eap_noob_get_sid(struct eap_sm * sm, struct eap_noob_data * data)
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
    if (FAILURE == eap_noob_exec_query(data, query, NULL, 8, TEXT, data->peerid, TEXT, sm->rad_attr->calledSID,
            TEXT, sm->rad_attr->callingSID, TEXT, sm->rad_attr->nasId)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: DB value insertion failed");
    }

    EAP_NOOB_FREE(sm->rad_attr->callingSID);
    EAP_NOOB_FREE(sm->rad_attr->calledSID);
    EAP_NOOB_FREE(sm->rad_attr->nasId);
    EAP_NOOB_FREE(sm->rad_attr);
    EAP_NOOB_FREE(query);
}

static int eap_noob_derive_session_secret(struct eap_noob_data * data, size_t * secret_len)
{
    EVP_PKEY_CTX * ctx = NULL;
    EVP_PKEY * peerkey = NULL;
    unsigned char * peer_pub_key = NULL;
    size_t skeylen = 0, len = 0;
    int ret = SUCCESS;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering function %s", __func__);
    if (NULL == data || NULL == secret_len) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: server data is NULL");
        return FAILURE;
    }

    EAP_NOOB_FREE(data->ecdh_exchange_data->shared_key);
    len = eap_noob_Base64Decode(data->ecdh_exchange_data->x_b64_remote, &peer_pub_key);
    if (len == 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode public key of peer");
        ret = FAILURE; goto EXIT;
    }

    peerkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub_key, len);
    if(peerkey == NULL) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to initialize public key of peer");
        ret = FAILURE; goto EXIT;
    }

    ctx = EVP_PKEY_CTX_new(data->ecdh_exchange_data->dh_key, NULL);
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

    EAP_NOOB_FREE(peer_pub_key);

    if (ret != SUCCESS)
        EAP_NOOB_FREE(data->ecdh_exchange_data->shared_key);

    return ret;
}
static int eap_noob_get_key(struct eap_noob_data * data)
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
   //EVP_PKEY_keygen(pctx, &data->ecdh_exchange_data->dh_key);

/*
    If you are using the RFC 7748 test vector, you do not need to generate a key pair. Instead you use the
    private key from the RFC. For using the test vector, comment out the line above and
    uncomment the following line code
*/
    d2i_PrivateKey_bio(mem1,&data->ecdh_exchange_data->dh_key);

    PEM_write_PrivateKey(stdout, data->ecdh_exchange_data->dh_key,
                         NULL, NULL, 0, NULL, NULL);
    PEM_write_PUBKEY(stdout, data->ecdh_exchange_data->dh_key);

    /* Get public key */
    if (1 != i2d_PUBKEY_bio(mem_pub, data->ecdh_exchange_data->dh_key)) {
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

    EAP_NOOB_FREE(data->ecdh_exchange_data->x_b64);
    eap_noob_Base64Encode(pub_key_char_asn_removed, pub_key_len, &data->ecdh_exchange_data->x_b64);

EXIT:
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    EAP_NOOB_FREE(pub_key_char);
    BIO_free_all(mem_pub);
    return ret;
}

static int eap_noob_get_sleeptime(struct eap_noob_data * data)
{
    /* TODO:  Include actual implementation for calculating the waiting time.
     * return  \
     * (int)((eap_noob_cal_pow(2,data->sleep_count))* (rand()%8) + 1) % 3600 ; */
    return 60;
}

/**
 * eap_noob_err_msg : prepares error message
 * @data : server data
 * @id   : response message id
 * Returns : pointer to message buffer or null
 **/
static struct wpabuf * eap_noob_err_msg(struct eap_noob_data * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * req = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(ERRORCODE) + strlen(ERRORINFO);
    size_t code = 0;

    if (!data || !(code = data->err_code)) {
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
    if (data->peerid && code != E1001) {
        json_add_string(json, PEERID, data->peerid);
    } else {
        json_add_string(json, PEERID, data->peerid_rcvd);
    }
    json_value_sep(json);
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
    data->err_code = NO_ERROR;
EXIT:
    wpabuf_free(json);
    EAP_NOOB_FREE(json_str);
    return req;
}

/**
 * eap_noob_build_msg_reconnect_hmac :
 * @data : server data
 * @id  :
 * Returns :
**/
static struct wpabuf * eap_noob_build_msg_reconnect_hmac(struct eap_noob_data * data, u8 id)
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
    mac = eap_noob_gen_MAC(data, MACS_TYPE, data->kdf_out->Kms, KMS_LEN, RECONNECTING_STATE);
    if (!mac) {
        goto EXIT;
    }

    // Convert MAC to base 64
    if (FAILURE == eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64)) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_RECONNECT_HMAC);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peerid);
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
static struct wpabuf * eap_noob_build_msg_reconnect_crypto(struct eap_noob_data * data, u8 id)
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
    data->kdf_nonce_data->Ns = os_zalloc(NONCE_LEN);
    int rc = RAND_bytes(data->kdf_nonce_data->Ns, NONCE_LEN);
    unsigned long error = ERR_get_error();
    if (rc != SUCCESS) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce. Error=%lu", error);
        os_free(data->kdf_nonce_data->Ns);
        goto EXIT;
    }

    // Encode nonce in base 64
    eap_noob_Base64Encode(data->kdf_nonce_data->Ns, NONCE_LEN, &Ns_b64);
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
    json_add_int(json, TYPE, EAP_NOOB_TYPE_RECONNECT_CRYPTO);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peerid);
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
static struct wpabuf * eap_noob_build_msg_reconnect_params(struct eap_noob_data * data, u8 id)
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
    json_add_int(json, TYPE, EAP_NOOB_TYPE_RECONNECT_PARAMS);
    json_value_sep(json);
    json_start_array(json, VERS);
    for (int i = 0; i < MAX_SUP_VER; i++) {
        if (data->versions[i] > 0) {
            wpabuf_printf(json, "%s%u", i ? "," : "", data->versions[i]);
        }
    }
    json_end_array(json);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peerid);
    json_value_sep(json);
    json_start_array(json, CRYPTOSUITES);
    for (int i = 0; i < MAX_SUP_CSUITES; i++) {
        if (data->cryptosuites[i] > 0) {
            wpabuf_printf(json, "%s%u", i ? "," : "", data->cryptosuites[i]);
        }
    }
    json_end_array(json);
    if (strcmp(server_conf.realm, DEFAULT_REALM)) {
        json_add_string(json, REALM, server_conf.realm);
    } else {
        json_add_string(json, REALM, "");
    }
    // Helper method to add the server information object to the wpabuf
    eap_noob_prepare_server_info_json(data->server_config_params, json, SERVERINFO);
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
static struct wpabuf * eap_noob_build_msg_completion_hmac(struct eap_noob_data * data, u8 id)
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

    mac = eap_noob_gen_MAC(data, MACS_TYPE, data->kdf_out->Kms,
            KMS_LEN, data->server_state);
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
    json_add_int(json, TYPE, EAP_NOOB_TYPE_COMPLETION_HMAC);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peerid);
    json_value_sep(json);
    json_add_string(json, NOOBID, data->oob_data->NoobId_b64);
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
static struct wpabuf * eap_noob_build_msg_waiting(struct eap_noob_data * data, u8 id)
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

    data->sleeptime = eap_noob_get_sleeptime(data);

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_WAITING);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peerid);
    json_value_sep(json);
    json_add_int(json, SLEEPTIME, data->sleeptime);
    json_end_object(json);

    clock_gettime(CLOCK_REALTIME, &time);
    data->last_used_time = time.tv_sec;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Current time is %ld", data->last_used_time);

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
static struct wpabuf * eap_noob_build_msg_initial_crypto(struct eap_noob_data *data, u8 id)
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
    data->kdf_nonce_data->Ns = os_malloc(NONCE_LEN);
    int rc = RAND_bytes(data->kdf_nonce_data->Ns, NONCE_LEN);
    unsigned long error = ERR_get_error();
    if (rc != 1) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce. Error= %lu", error);
        os_free(data->kdf_nonce_data->Ns);
        goto EXIT;
    }

    // Encode the nonce in base 64
    eap_noob_Base64Encode(data->kdf_nonce_data->Ns, NONCE_LEN, &Ns_b64);
    wpa_printf(MSG_DEBUG,"EAP-NOOB: Nonce %s", Ns_b64);

    // Generate key material
    if (eap_noob_get_key(data) == FAILURE) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate keys");
        eap_noob_set_done(data, DONE);
        eap_noob_set_success(data, FAILURE);
        goto EXIT;
    }

    // Build JWK to represent server
    if (FAILURE == eap_noob_build_JWK(&data->ecdh_exchange_data->jwk_serv,
                data->ecdh_exchange_data->x_b64)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate JWK");
        goto EXIT;
    }

    // Get time the peer is expected to sleep
    data->sleeptime = eap_noob_get_sleeptime(data);

    // Create JSON EAP message

    json = wpabuf_alloc(len);
    if (!json) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for json response");
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_INITIAL_CRYPTO);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peerid);
    json_value_sep(json);
    wpabuf_printf(json, "\"%s\":%s", PKS, data->ecdh_exchange_data->jwk_serv);
    json_value_sep(json);
    json_add_string(json, NS, Ns_b64);
    json_value_sep(json);
    json_add_int(json, SLEEPTIME, data->sleeptime);
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
static struct wpabuf * eap_noob_build_msg_initial_params(struct eap_noob_data * data, u8 id)
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

    EAP_NOOB_FREE(data->peerid);
    data->peerid = os_malloc(MAX_PEER_ID_LEN);
    if (eap_noob_get_id_peer(data->peerid, MAX_PEER_ID_LEN)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to generate PeerId");
        return NULL;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_INITIAL_PARAMS);
    json_value_sep(json);
    json_start_array(json, VERS);
    for (int i = 0; i < MAX_SUP_VER; i++) {
        if (data->versions[i] > 0) {
            wpabuf_printf(json, "%s%u", i ? "," : "", data->versions[i]);
        }
    }
    json_end_array(json);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peerid);
    json_value_sep(json);
    if (strcmp(server_conf.realm, DEFAULT_REALM)) {
        json_add_string(json, REALM, server_conf.realm);
    } else {
        json_add_string(json, REALM, "");
    }
    json_value_sep(json);
    json_start_array(json, CRYPTOSUITES);
    for (int i = 0; i < MAX_SUP_CSUITES; i++) {
        if (data->cryptosuites[i] > 0) {
            wpabuf_printf(json, "%s%u", i ? "," : "", data->cryptosuites[i]);
        }
    }
    json_end_array(json);
    json_value_sep(json);
    json_add_int(json, DIRS, data->dirs);
    json_value_sep(json);
    // Helper method to add the server information object to the wpabuf
    eap_noob_prepare_server_info_json(data->server_config_params, json, SERVERINFO);
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
 * eap_noob_build_msg_completion_noobid -
 * @data: Pointer to private EAP-NOOB data
 * @id: EAP response to be processed (eapRespData)
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_build_msg_completion_noobid(struct eap_noob_data * data, u8 id)
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
    json_add_int(json, TYPE, EAP_NOOB_TYPE_COMPLETION_NOOBID);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peerid);
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
 * Prepare handshake message type request (for PeerId and PeerState)
 * @data: Pointer to private EAP-NOOB data
 * @id: EAP response to be processed (eapRespData)
 * Return: Pointer to allocated EAP-Request packet, or NULL if an error occurred
 */
static struct wpabuf * eap_noob_build_msg_handshake(struct eap_noob_data * data, u8 id)
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
    json_add_int(json, TYPE, EAP_NOOB_TYPE_HANDSHAKE);
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
    struct eap_noob_data *data = NULL;

    if (NULL == sm || NULL == priv) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    data = priv;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: next request = %d", data->next_req);
    //TODO : replce switch case with function pointers.
    switch (data->next_req) {
        case NONE:
            return eap_noob_err_msg(data,id);

        case EAP_NOOB_TYPE_HANDSHAKE:
            return eap_noob_build_msg_handshake(data, id);

        case EAP_NOOB_TYPE_INITIAL_PARAMS:
            return eap_noob_build_msg_initial_params(data, id);

        case EAP_NOOB_TYPE_INITIAL_CRYPTO:
            return eap_noob_build_msg_initial_crypto(data, id);

        case EAP_NOOB_TYPE_WAITING:
            return eap_noob_build_msg_waiting(data, id);

        case EAP_NOOB_TYPE_COMPLETION_NOOBID:
            return eap_noob_build_msg_completion_noobid(data, id);

        case EAP_NOOB_TYPE_COMPLETION_HMAC:
            return eap_noob_build_msg_completion_hmac(data, id);

        case EAP_NOOB_TYPE_RECONNECT_PARAMS:
            return eap_noob_build_msg_reconnect_params(data, id);

        case EAP_NOOB_TYPE_RECONNECT_CRYPTO:
            return eap_noob_build_msg_reconnect_crypto(data, id);

        case EAP_NOOB_TYPE_RECONNECT_HMAC:
            return eap_noob_build_msg_reconnect_hmac(data, id);

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
    struct eap_noob_data * data = NULL;
    struct json_token * resp_obj = NULL;
    struct json_token * resp_type = NULL;
    const u8 * pos = NULL;
    u32 state = 0;
    size_t len = 0;
    bool ret = false;

    if (!priv || !sm || !respData) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        ret = true;
        goto EXIT;
    }

    wpa_printf(MSG_INFO, "EAP-NOOB: Checking EAP-Response packet.");

    // Retrieve information from the response

    data = priv;
    state = data->server_state;
    pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_NOOB, respData, &len);

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Received response = %s", pos);

    // Check for possible errors

    resp_obj = json_parse((char *) pos, len);
    if (resp_obj && resp_obj->type == JSON_OBJECT) {
        resp_type = json_get_member(resp_obj, TYPE);

        if (resp_type && resp_type->type == JSON_NUMBER) {
            data->recv_msg = resp_type->number;
        } else {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown message type");
            eap_noob_set_error(data, E1002);
            ret = true;
            goto EXIT;
        }
    } else {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown format received");
        eap_noob_set_error(data, E1002);
        ret = true;
        goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Received frame: opcode = %d", data->recv_msg);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: STATE = %d",data->server_state);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: VERIFY STATE SERV = %d PEER = %d",
            data->server_state, data->peer_state);

    if ((data->recv_msg != NONE) &&
            (state >= NUM_OF_STATES ||
            data->recv_msg >= NUM_MSG_TYPES ||
            state_message_check[state][data->recv_msg] != VALID)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Setting error in received message."
            "state (%d), message type (%d), state received (%d)",
            state, data->recv_msg,
            state_message_check[state][data->recv_msg]);
        eap_noob_set_error(data,E1004);
        ret = true;
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
static int eap_noob_del_temp_tuples(struct eap_noob_data * data)
{
    char * query = os_malloc(MAX_LINE_SIZE);
    int ret = SUCCESS;

    if (NULL == data || NULL == query) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null or malloc failed.", __func__);
        ret = FAILURE; goto EXIT;
    }

    os_snprintf(query, MAX_LINE_SIZE, "Delete from %s WHERE PeerId=?", DEVICE_TABLE);
    if (FAILURE == eap_noob_exec_query(data, query, NULL, 2, data->peerid_rcvd)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: DB tuple deletion failed");
        ret = FAILURE; goto EXIT;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: TEMP Tuples removed");
EXIT:
    EAP_NOOB_FREE(query);
    return ret;
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
 * eap_oob_rsp_type_seven - Process EAP-Response
 * @data: Pointer to private EAP-NOOB data
 **/
static void eap_noob_processs_msg_reconnect_hmac(struct eap_noob_data * data)
{
    u8 * mac = NULL; char * mac_b64 = NULL;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        return;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-FR-3");

    /* TODO :  validate MAC address along with peerID */
    if (data->rcvd_params != TYPE_SEVEN_PARAMS) {
        eap_noob_set_error(data, E1002);
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if ((data->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if (eap_noob_verify_peerId(data) == SUCCESS) {
        mac = eap_noob_gen_MAC(data, MACP_TYPE, data->kdf_out->Kmp, KMP_LEN, RECONNECTING_STATE);
        eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64);
        if (0 != strcmp(data->mac, (char *)mac)) {
            eap_noob_set_error(data,E4001);
            eap_noob_set_done(data, NOT_DONE); goto EXIT;
        }
        eap_noob_change_state(data, REGISTERED_STATE);
        if (FAILURE == eap_noob_db_functions(data, UPDATE_PERSISTENT_STATE)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Updating server state failed ");
            goto EXIT;
        }
        data->next_req = NONE;
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
static void eap_noob_processs_msg_reconnect_crypto(struct eap_noob_data * data)
{
    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-FR-2");
    if (data->rcvd_params != TYPE_SIX_PARAMS) {
        eap_noob_set_error(data, E1002);
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if ((data->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce Peer", data->kdf_nonce_data->Np, NONCE_LEN);
    if (eap_noob_verify_peerId(data) == SUCCESS) {
        data->next_req = EAP_NOOB_TYPE_RECONNECT_HMAC;
        eap_noob_set_done(data, NOT_DONE); data->rcvd_params = 0;
    }
}

/**
 * eap_oob_rsp_type_five - Process EAP-Response Type 5
 * @data: Pointer to private EAP-NOOB data
 **/
static void eap_noob_processs_msg_reconnect_params(struct eap_noob_data * data)
{
    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-FR-1");
    /* TODO: Check for the current cryptosuite and the previous to
     * decide whether new key exchange has to be done. */
    if ((data->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if (data->rcvd_params != TYPE_FIVE_PARAMS) {
        eap_noob_set_error(data, E1002);
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if (eap_noob_verify_peerId(data) == SUCCESS)
        data->next_req = EAP_NOOB_TYPE_RECONNECT_CRYPTO;

    eap_noob_set_done(data, NOT_DONE);
    data->rcvd_params = 0;
}

/**
 * eap_oob_rsp_type_four - Process EAP-Response Type 4
 * @data: Pointer to private EAP-NOOB data
 **/
static void eap_noob_processs_msg_completion_hmac(struct eap_noob_data * data)
{
    u8 * mac = NULL; char * mac_b64 = NULL; int dir = 0;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
    dir = (data->dirs & data->dirp);
    /* TODO :  validate MAC address along with peerID */
    if (data->rcvd_params != TYPE_FOUR_PARAMS) {
        eap_noob_set_error(data,E1002);
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if ((data->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }

    if (eap_noob_verify_peerId(data) == SUCCESS) {
        mac = eap_noob_gen_MAC(data, MACP_TYPE, data->kdf_out->Kmp, KMP_LEN, data->peer_state);
        eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64);
        if (0 != strcmp(data->mac, (char *)mac)) {
            eap_noob_set_error(data,E4001); eap_noob_set_done(data, NOT_DONE); goto EXIT;
        }
        eap_noob_change_state(data, REGISTERED_STATE);
        if (FAILURE == eap_noob_db_functions(data,UPDATE_PERSISTENT_KEYS_SECRET)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Updating server state failed "); goto EXIT;
        }
        if (dir == SERVER_TO_PEER) eap_noob_del_temp_tuples(data);

        data->next_req = NONE;
        eap_noob_set_done(data, DONE); eap_noob_set_success(data, SUCCESS);
    }
EXIT:
    EAP_NOOB_FREE(mac_b64);
}

/**
 * eap_oob_rsp_type_three - Process EAP-Response Type 3
 * @data: Pointer to private EAP-NOOB data
 **/
static void eap_noob_processs_msg_waiting(struct eap_noob_data * data)
{
    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-WE-3");

    if (data->rcvd_params != TYPE_THREE_PARAMS) {
        eap_noob_set_error(data,E1002);
        eap_noob_set_done(data, NOT_DONE);
        return;
    }
    if ((data->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE);
        return;
    }

    if (eap_noob_verify_peerId(data) == SUCCESS) {
        eap_noob_change_state(data, WAITING_FOR_OOB_STATE);
        data->next_req = NONE;
        eap_noob_set_done(data, DONE);
        eap_noob_set_success(data, FAILURE);
    }
}

/**
 * eap_oob_rsp_type_two - Process EAP-Response/Initial Exchange 2
 * @data: Pointer to private EAP-NOOB data
 **/
static void eap_noob_processs_msg_initial_crypto(struct eap_noob_data * data)
{
    size_t secret_len = ECDH_SHARED_SECRET_LEN;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-IE-2");

    if (data->rcvd_params != TYPE_TWO_PARAMS) {
        eap_noob_set_error(data,E1002);
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Did not match type 2 parameters");
        eap_noob_set_done(data, NOT_DONE); return;
    }
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce Peer", data->kdf_nonce_data->Np, NONCE_LEN);
    if ((data->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }

    if (eap_noob_verify_peerId(data) == SUCCESS) {
        wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce Peer", data->kdf_nonce_data->Np, NONCE_LEN);
        if (eap_noob_derive_session_secret(data,&secret_len) != SUCCESS) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in deriving shared key"); return;
        }
        eap_noob_Base64Encode(data->ecdh_exchange_data->shared_key,
          ECDH_SHARED_SECRET_LEN, &data->ecdh_exchange_data->shared_key_b64);
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Shared secret %s", data->ecdh_exchange_data->shared_key_b64);
        eap_noob_change_state(data, WAITING_FOR_OOB_STATE);

        // Generate the MAC input string such that it can be used for
        // calculating the Hoob.
        data->mac_input_str = eap_noob_build_mac_input(data, data->dirp, data->server_state);

        if (FAILURE == eap_noob_db_functions(data, UPDATE_INITIALEXCHANGE_INFO)) {
            eap_noob_set_done(data, DONE);
            eap_noob_set_success(data,FAILURE);
            return;
        }

        data->next_req = NONE;
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
static void eap_noob_processs_msg_initial_params(struct eap_sm *sm,
                                  struct eap_noob_data *data)
{
    /* Check for the supporting cryptosuites, PeerId, version, direction*/
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-IE-1");

    if (!data || !sm) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    if ((data->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if (data->rcvd_params != TYPE_ONE_PARAMS) {
        eap_noob_set_error(data,E1002);
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if (eap_noob_verify_peerId(data) == SUCCESS) {
        data->next_req = EAP_NOOB_TYPE_INITIAL_CRYPTO;
    }
    eap_noob_get_sid(sm, data); eap_noob_set_done(data, NOT_DONE);
    data->rcvd_params = 0;
}

static void eap_noob_processs_msg_completion_noobid(struct eap_noob_data * data)
{
    if ((data->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE);
        return;
    }

    if (data->rcvd_params != TYPE_EIGHT_PARAMS) {
        eap_noob_set_error(data,E1002);
        eap_noob_set_done(data, NOT_DONE);
        return;
    }

    if (eap_noob_verify_peerId(data) != SUCCESS) {
        eap_noob_set_error(data,E2004);
        eap_noob_set_done(data, NOT_DONE);
        return;
    }

    if (!eap_noob_db_functions(data, GET_NOOBID) || NULL == data->oob_data->NoobId_b64) {
        eap_noob_set_error(data,E2003);
        eap_noob_set_done(data,NOT_DONE);
    } else {
        eap_noob_set_done(data, NOT_DONE);
        data->next_req = EAP_NOOB_TYPE_COMPLETION_HMAC;
    }

    data->rcvd_params = 0;
}

static void eap_noob_processs_msg_handshake(struct eap_noob_data * data)
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
    if (data->server_state == UNREGISTERED_STATE ||
        data->server_state == WAITING_FOR_OOB_STATE ||
        data->server_state == RECONNECTING_STATE) {
        if (FAILURE == (result = eap_noob_read_config(data))) {
            goto EXIT;
        }
    }

    // Check whether new OOB data has arrived, if so, verify the Hoob
    if (data->server_state == WAITING_FOR_OOB_STATE &&
        data->dirp == PEER_TO_SERVER) {
        // Retrieve OOB data from the database
        if (FAILURE == eap_noob_exec_query(data, QUERY_EPHEMERALNOOB, columns_ephemeralnoob, 2, TEXT, data->peerid_rcvd)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Error while retrieving OOB data from the database");
            result = FAILURE;
            goto EXIT;
        }

        // There must be OOB data available before continuing
        if (data->oob_data->Hoob_b64 &&
            data->oob_data->Noob_b64) {
            // Build the Hoob input for the local calculation
            input = eap_noob_build_mac_input(data, data->dirp, data->server_state);
            if (!input) {
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to build Hoob input");
                result = FAILURE;
                goto EXIT;
            }

            wpa_printf(MSG_DEBUG, "EAP-NOOB: Local Hoob input = %s", input);

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
            if (!os_strcmp(hoob_b64, data->oob_data->Hoob_b64)) {
                // Both Hoobs are equal, thus the received OOB data is valid and
                // the server moves on to the next state.
                eap_noob_change_state(data, OOB_RECEIVED_STATE);
            } else {
                wpa_printf(MSG_INFO, "EAP-NOOB: Received Hoob does not match local Hoob");

                // Increase number of invalid Hoobs received
                data->oob_retries++;
                wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB retries = %d", data->oob_retries);
                eap_noob_db_functions(data, UPDATE_OOB_RETRIES);

                // Reset the server to Unregistered state if the maximum
                // number of OOB retries (i.e. invalid Hoobs) has been reached.
                if (data->oob_retries >= data->max_oob_retries) {
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
    if (data->err_code == NO_ERROR) {
        data->next_req = eap_noob_get_next_req(data);
    } else {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Could not get next request type, error in peer attr: %d", data->err_code);
        result = FAILURE;
        goto EXIT;
    }
EXIT:
    if (result == FAILURE) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Error while handling response message type 9");
    }
    data->rcvd_params = 0;
}

/**
 * eap_oob_process - Control Process EAP-Response.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @priv: Pointer to private EAP-NOOB data
 * @respData: EAP response to be processed (eapRespData)
 **/
static void eap_noob_process(struct eap_sm * sm, void * priv, struct wpabuf * respData)
{
    struct eap_noob_data * data = NULL;
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

    if (data->err_code != NO_ERROR) {
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
    eap_noob_decode_obj(data, resp_obj);
    if (data->err_code != NO_ERROR) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Decoding gave error: %s", error_info[data->err_code]);
        goto EXIT;
    }

    wpa_printf(MSG_ERROR, "EAP-NOOB: Passed decode_obj");

    /* TODO : replce switch case with function pointers. */
    switch (data->recv_msg) {
        case EAP_NOOB_TYPE_HANDSHAKE:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 9");
            eap_noob_processs_msg_handshake(data);
            break;

        case EAP_NOOB_TYPE_INITIAL_PARAMS:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 1");
            eap_noob_processs_msg_initial_params(sm, data);
            break;

        case EAP_NOOB_TYPE_INITIAL_CRYPTO:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 2");
            eap_noob_processs_msg_initial_crypto(data);
            break;

        case EAP_NOOB_TYPE_WAITING:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 3");
            eap_noob_processs_msg_waiting(data);
            break;

        case EAP_NOOB_TYPE_COMPLETION_NOOBID:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE NoobId");
            eap_noob_processs_msg_completion_noobid(data);
            break;

        case EAP_NOOB_TYPE_COMPLETION_HMAC:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 4");
            eap_noob_processs_msg_completion_hmac(data);
            break;

        case EAP_NOOB_TYPE_RECONNECT_PARAMS:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 5");
            eap_noob_processs_msg_reconnect_params(data);
            break;

        case EAP_NOOB_TYPE_RECONNECT_CRYPTO:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 6");
            eap_noob_processs_msg_reconnect_crypto(data);
            break;

        case EAP_NOOB_TYPE_RECONNECT_HMAC:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 7");
            eap_noob_processs_msg_reconnect_hmac(data);
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
    data->recv_msg = 0;
EXIT:
    ;
    //json_free(resp_obj);
}


static _Bool eap_noob_isDone(struct eap_sm *sm, void *priv)
{

    struct eap_noob_data *data = priv;
    printf("DONE   = %d\n",data->is_done);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: IS Done? %d",(data->is_done == DONE));
    return (data->is_done == DONE);
}

/**
 * eap_oob_isSuccess - Check EAP-NOOB was successful.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @priv: Pointer to private EAP-NOOB data
 * Returns: True if EAP-NOOB is successful, False otherwise.
 **/
static _Bool eap_noob_isSuccess(struct eap_sm *sm, void *priv)
{
    struct eap_noob_data *data = priv;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: IS SUCCESS? %d",(data->is_success == SUCCESS));
    return (data->is_success == SUCCESS);
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
    struct eap_noob_data *data = NULL;
    u8 *key = NULL;

    if (!priv || !sm || !len) return NULL;
    data = priv;

    if ((data->server_state != REGISTERED_STATE) || (!data->kdf_out->msk))
        return NULL;

    //Base64Decode((char *)data->kdf_out->msk_b64, &data->kdf_out->msk, len);
    if (NULL == (key = os_malloc(MSK_LEN)))
        return NULL;

    *len = MSK_LEN;
    os_memcpy(key, data->kdf_out->msk, MSK_LEN);
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
    struct eap_noob_data *data = NULL;
    u8 *session_id = NULL;

    if (!priv || !sm || !len) return NULL;
  	data = priv;

    if ((data->server_state != REGISTERED_STATE) || (!data->kdf_out->MethodId))
        return NULL;

    if (NULL == (session_id = os_malloc(1 + METHOD_ID_LEN)))
        return NULL;


    *len = 1 + METHOD_ID_LEN;

    session_id[0] = EAP_TYPE_NOOB;
    os_memcpy(session_id + 1, data->kdf_out->MethodId, METHOD_ID_LEN);
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
    struct eap_noob_data * data = NULL;
    u8 * emsk = NULL;
    wpa_printf(MSG_DEBUG, "EAP-NOOB:Get EMSK called");

    if (!priv || !sm || !len) return NULL;
    data = priv;

    if ((data->server_state != REGISTERED_STATE) || (!data->kdf_out->emsk))
        return NULL;
    if (NULL == (emsk = os_malloc(EAP_EMSK_LEN)))
        return NULL;
    os_memcpy(emsk, data->kdf_out->emsk, EAP_EMSK_LEN);
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
 * eap_noob_server_ctxt_init -Supporting Initializer for EAP-NOOB server Method
 * Allocates memory for the EAP-NOOB data
 * @data: Pointer to EAP-NOOB data
 * @sm : eap method context
 **/
static int eap_noob_server_ctxt_init(struct eap_noob_data * data, struct eap_sm * sm)
{
    char * NAI = NULL;
    int retval = FAILURE;

    if (FAILURE == eap_noob_ctxt_alloc(data))
        return FAILURE;

    data->server_state = UNREGISTERED_STATE;
    data->peer_state = UNREGISTERED_STATE;
    data->err_code = NO_ERROR;
    data->rcvd_params = 0;
    data->sleep_count = 0;

    if (server_conf.read_conf == 0 && FAILURE == eap_noob_read_config(data)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to initialize context");
        return FAILURE;
    }

    if (sm->identity) {
        NAI = os_zalloc(sm->identity_len+1);
        if (NULL == NAI) {
            eap_noob_set_error(data, E1001);
            return FAILURE;
        }
        os_memcpy(NAI, sm->identity, sm->identity_len);
        strcat(NAI, "\0");
    }

    if (SUCCESS == (retval = eap_noob_parse_NAI(data, NAI))) {
        if (data->err_code == NO_ERROR) {
            // Always set the next request to type 9, because every Exchange
            // must start with the Common Handshake,
            // as per version 8 of the draft.
            data->next_req = EAP_NOOB_TYPE_HANDSHAKE;
        }
    }

    EAP_NOOB_FREE(NAI);
    if (retval == FAILURE)
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to initialize context");
    return retval;
}

/**
 * eap_noob_free_ctx : Free up all memory in server data
 * @data: Pointer to EAP-NOOB data
 **/
static void eap_noob_free_ctx(struct eap_noob_data * data)
{
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    EAP_NOOB_FREE(data->server_info);
    if (data->server_config_params) {
        EAP_NOOB_FREE(data->server_config_params->ServerName);
        EAP_NOOB_FREE(data->server_config_params->ServerURL);
        os_free(data->server_config_params);
        data->server_config_params = NULL;
    }
    EAP_NOOB_FREE(data->peerid);
    EAP_NOOB_FREE(data->peerid_rcvd);
    EAP_NOOB_FREE(data->peer_info);
    EAP_NOOB_FREE(data->mac);
    if (data->kdf_nonce_data) {
        EAP_NOOB_FREE(data->kdf_nonce_data->Np);
        EAP_NOOB_FREE(data->kdf_nonce_data->Ns);
        os_free(data->kdf_nonce_data);
        data->kdf_nonce_data = NULL;
    }
    if (data->ecdh_exchange_data) {
        EVP_PKEY_free(data->ecdh_exchange_data->dh_key);
        EAP_NOOB_FREE(data->ecdh_exchange_data->shared_key);
        EAP_NOOB_FREE(data->ecdh_exchange_data->shared_key_b64);
        EAP_NOOB_FREE(data->ecdh_exchange_data->x_b64_remote);
        EAP_NOOB_FREE(data->ecdh_exchange_data->y_b64_remote);
        EAP_NOOB_FREE(data->ecdh_exchange_data->x_b64);
        EAP_NOOB_FREE(data->ecdh_exchange_data->y_b64);
        EAP_NOOB_FREE(data->ecdh_exchange_data->jwk_serv);
        EAP_NOOB_FREE(data->ecdh_exchange_data->jwk_peer);
        os_free(data->ecdh_exchange_data);
        data->ecdh_exchange_data = NULL;
    }
    if (data->oob_data) {
        EAP_NOOB_FREE(data->oob_data->Noob_b64);
        EAP_NOOB_FREE(data->oob_data->NoobId_b64);
        EAP_NOOB_FREE(data->oob_data->Hoob_b64);
        os_free(data->oob_data);
        data->oob_data = NULL;
    }
    if (data->kdf_out) {
        EAP_NOOB_FREE(data->kdf_out->msk);
        EAP_NOOB_FREE(data->kdf_out->emsk);
        EAP_NOOB_FREE(data->kdf_out->amsk);
        EAP_NOOB_FREE(data->kdf_out->MethodId);
        EAP_NOOB_FREE(data->kdf_out->Kms);
        EAP_NOOB_FREE(data->kdf_out->Kmp);
        EAP_NOOB_FREE(data->kdf_out->Kz);
        os_free(data->kdf_out);
        data->kdf_out = NULL;
    }

    if (SQLITE_OK != sqlite3_close_v2(data->db)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error closing DB");
        char * sql_error = (char *)sqlite3_errmsg(data->db);
        if (sql_error != NULL)
            wpa_printf(MSG_DEBUG,"EAP-NOOB: SQL error : %s\n", sql_error);
    }

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
    struct eap_noob_data *data = priv;

    eap_noob_free_ctx(data);
}

/**
 * eap_noob_init - Initialize the EAP-NOOB Peer Method
 * Allocates memory for the EAP-NOOB data
 * @sm: Pointer to EAP State Machine data
 **/
static void * eap_noob_init(struct eap_sm *sm)
{
    struct eap_noob_data * data = NULL;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: INIT SERVER");

    if (NULL == (data = os_zalloc( sizeof (struct eap_noob_data)))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: INIT SERVER Fail to Allocate Memory");
        return NULL;
    }

    //TODO: check if hard coded initialization can be avoided
    if (FAILURE == eap_noob_server_ctxt_init(data,sm) && data->err_code == NO_ERROR) {
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
