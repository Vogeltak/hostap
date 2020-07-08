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

#include "includes.h"

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <signal.h>

#include <base64.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sqlite3.h>
#include "common.h"
#include "json.h"
#include "crypto/crypto.h"
#include "eap_common/eap_noob_common.h"
#include "eap_i.h"
#include "eap_noob.h"
#include "../../wpa_supplicant/config.h"
#include "../../wpa_supplicant/wpa_supplicant_i.h"
#include "../../wpa_supplicant/blacklist.h"

static struct eap_noob_global_conf eap_noob_global_conf = {0};

/**
 * eap_noob_prepare_peer_info_json : Append a Json object for peer information.
 * @data : peer data.
 * @json : wpabuf json object to which the peer info object should be appended.
 * @name : name for the peer info json object, or NULL.
**/
static void eap_noob_prepare_peer_info_json(struct eap_sm * sm, struct eap_noob_peer_config_params * data, struct wpabuf * json, char * name)
{
    struct wpa_supplicant * wpa_s = (struct wpa_supplicant *) sm->msg_ctx;
    char bssid[18] = {0};

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return;
    }

    json_start_object(json, name);
    json_add_string(json, PEER_MAKE, data->Peer_name);
    json_value_sep(json);
    json_add_string(json, PEER_TYPE, eap_noob_global_conf.peer_type);
    json_value_sep(json);
    json_add_string(json, PEER_SERIAL_NUM, data->Peer_ID_Num);
    json_value_sep(json);
    json_add_string(json, PEER_SSID, (char *) wpa_s->current_ssid->ssid);
    json_value_sep(json);

    sprintf(bssid,"%x:%x:%x:%x:%x:%x",wpa_s->current_ssid->bssid[0],wpa_s->current_ssid->bssid[1],
            wpa_s->current_ssid->bssid[2],wpa_s->current_ssid->bssid[3],wpa_s->current_ssid->bssid[4],
            wpa_s->current_ssid->bssid[5]);

    json_add_string(json, PEER_BSSID, bssid);
    json_end_object(json);
}

/**
 * Generate a string representation of a JSON peer information object.
 * @data: peer data
 */
static char * eap_noob_prepare_peer_info_string(struct eap_sm * sm,
        struct eap_noob_peer_config_params * data)
{
    struct wpabuf * json = NULL;
    char * resp = NULL;

    json = wpabuf_alloc(MAX_INFO_LEN);
    if (!json) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for JSON wpabuf");
        return NULL;
    }

    // Append JSON peer info object without a name
    eap_noob_prepare_peer_info_json(sm, data, json, NULL);

    // Get a string representation of the JSON object
    resp = strndup(wpabuf_head(json), wpabuf_len(json));

    wpabuf_free(json);

    return resp;
}


static int eap_noob_encode_vers_cryptosuites(struct eap_noob_data * data,
        char ** Vers, char ** Cryptosuites)
{
    struct wpabuf * vers = wpabuf_alloc(100);
    struct wpabuf * cryptosuites = wpabuf_alloc(100);

    if (!vers || !cryptosuites) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: JSON allocation for Vers and Cryptosuites failed");
        return FAILURE;
    }

    // Populate the vers array
    json_start_array(vers, NULL);
    for (int i = 0; i < MAX_SUP_VER; i++) {
        if (data->versions[i] > 0)
            wpabuf_printf(vers, "%s%u", i ? "," : "", data->versions[i]);
    }
    json_end_array(vers);

    // Populate the cryptosuites array
    json_start_array(cryptosuites, NULL);
    for (int i = 0; i < MAX_SUP_CSUITES; i++) {
        if (data->cryptosuites[i] > 0)
            wpabuf_printf(cryptosuites, "%s%u", i ? "," : "", data->cryptosuites[i]);
    }
    json_end_array(cryptosuites);

    // Duplicate strings to output pointers
    *Vers = strndup(wpabuf_head(vers), wpabuf_len(vers));
    *Cryptosuites = strndup(wpabuf_head(cryptosuites), wpabuf_len(cryptosuites));

    return SUCCESS;
}

static void eap_noob_decode_vers_cryptosuites(struct eap_noob_data * data,
        const char * Vers, const char * Cryptosuites)
{
    struct json_token * vers_obj = json_parse(Vers, os_strlen(Vers));
    struct json_token * cryptosuites_obj = json_parse(Cryptosuites, os_strlen(Cryptosuites));

    struct json_token * child = vers_obj->child;
    int i = 0;

    // Populate the version array
    while (child) {
        data->versions[i] = child->number;
        child = child->sibling;
        i++;
    }

    child = cryptosuites_obj->child;
    i = 0;

    // Populate the cryptosuite array
    while (child) {
        data->cryptosuites[i] = child->number;
        child = child->sibling;
        i++;
    }
}

/**
 *  eap_noob_build_JWK : Builds a JWK object to send in the inband message
 *  @jwk : output json object
 *  @x_64 : x co-ordinate in base64url format
 *  Returns : FAILURE/SUCCESS
**/
static int eap_noob_build_JWK(struct eap_noob_data * data, char ** jwk, const char * x_b64)
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
    json_add_string(json, CURVE, cryptosuites_names[data->cryptosuitep]);
    json_value_sep(json);
    json_add_string(json, X_COORDINATE, x_b64);
    if (data->ecdh_exchange_data->y_b64) {
        json_value_sep(json);
        json_add_string(json, Y_COORDINATE, data->ecdh_exchange_data->y_b64);
    }
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
 * eap_noob_assign_config : identify each config item and store the read value
 * @confname : name of the conf item
 * @conf_value : value of the conf item
 * @data : peer data
**/
static void eap_noob_assign_config(char * conf_name,char * conf_value, struct eap_noob_data * data)
{
    //TODO : version and csuite are directly converted to integer.This needs to be changed if
    //more than one csuite or version is supported.

    wpa_printf(MSG_DEBUG, "EAP-NOOB:CONF Name = %s %d", conf_name, (int)strlen(conf_name));
    if (0 == strcmp("Version",conf_name)) {
        data->version = (int) strtol(conf_value, NULL, 10);
        data->config_params |= VERSION_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d",data->version);
    }
    else if (0 == strcmp("Csuite",conf_name)) {
        int csuite = (int) strtol(conf_value, NULL, 10);
        // If the cryptosuite specified in the EAP-NOOB configuration file has
        // changed, save the old value from the persistent association in
        // the cryptosuitep_prev field.
        if (data->cryptosuitep && csuite != data->cryptosuitep) {
            data->cryptosuitep_prev = data->cryptosuitep;
        }
        data->cryptosuitep = csuite;
        data->config_params |= CRYPTOSUITE_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d",data->cryptosuitep);
    }
    else if (0 == strcmp("OobDirs",conf_name)) {
        data->dirp = (int) strtol(conf_value, NULL, 10);
        data->config_params |= DIR_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d",data->dirp);
    }
    else if (0 == strcmp("PeerMake", conf_name)) {
        data->peer_config_params->Peer_name = os_strdup(conf_value);
        data->config_params |= PEER_MAKE_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s",data->peer_config_params->Peer_name);
    }
    else if (0 == strcmp("PeerType", conf_name)) {
        eap_noob_global_conf.peer_type = os_strdup(conf_value);
        data->config_params |= PEER_TYPE_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s",eap_noob_global_conf.peer_type);
    }
    else if (0 == strcmp("PeerSNum", conf_name)) {
        data->peer_config_params->Peer_ID_Num = os_strdup(conf_value);
        data->config_params |= PEER_ID_NUM_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s",data->peer_config_params->Peer_ID_Num);
    }
    else if (0 == strcmp("OobRetries", conf_name)) {
        data->max_oob_retries = (int) strtol(conf_value, NULL, 10);
        data->config_params |= MAX_OOB_RETRIES_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE READ = %d", data->max_oob_retries);
    }
    else if (0 == strcmp("MinSleepDefault", conf_name)) {
        eap_noob_global_conf.default_minsleep = (int) strtol(conf_value, NULL, 10);
        data->config_params |= DEF_MIN_SLEEP_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d",eap_noob_global_conf.default_minsleep);
    }
    else if (0 == strcmp("OobMessageEncoding", conf_name)) {
        eap_noob_global_conf.oob_enc_fmt = (int) strtol(conf_value, NULL, 10);
        data->config_params |= MSG_ENC_FMT_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d",eap_noob_global_conf.oob_enc_fmt);
    }

}

/**
 * eap_noob_parse_config : parse each line from the config file
 * @buff : read line
 * data : peer data
**/
static void eap_noob_parse_config(char * buff, struct eap_noob_data * data)
{
    char * pos = buff;
    char * conf_name = NULL;
    char * conf_value = NULL;
    char * token = NULL;

    for(; *pos == ' ' || *pos == '\t' ; pos++);

    if (*pos == '#')
        return;

    if (os_strstr(pos, "=")) {
        conf_name = strsep(&pos,"=");
        /*handle if there are any space after the conf item name*/
        token = conf_name;
        for(; (*token != ' ' && *token != 0 && *token != '\t'); token++);
        *token = '\0';

        token = strsep(&pos,"=");
        /*handle if there are any space before the conf item value*/
        for(; (*token == ' ' || *token == '\t' ); token++);

        /*handle if there are any comments after the conf item value*/
        //conf_value = strsep(&token,"#");
        conf_value = token;

        for(; (*token != '\n' && *token != '\t'); token++);
        *token = '\0';
        //wpa_printf(MSG_DEBUG, "EAP-NOOB: conf_value = %s token = %s\n",conf_value,token);
        eap_noob_assign_config(conf_name,conf_value, data);
    }
}

/**
 * eap_noob_handle_incomplete_conf :  assigns defult value of the configuration is incomplete
 * @data : peer config
 * Returs : FAILURE/SUCCESS
**/
static int eap_noob_handle_incomplete_conf(struct eap_noob_data * data)
{
    if (!(data->config_params & PEER_MAKE_RCVD) ||
        !(data->config_params & PEER_ID_NUM_RCVD) ||
        !(data->config_params&PEER_TYPE_RCVD)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Peer Make or Peer Type or Peer Serial number missing");
        return FAILURE;
    }
    if (! (data->config_params & VERSION_RCVD))
        data->version = VERSION_ONE;
    if (! (data->config_params & CRYPTOSUITE_RCVD))
        data->cryptosuitep = SUITE_ONE;
    if (! (data->config_params & DIR_RCVD))
        data->dirp = PEER_TO_SERVER;
    if (! (data->config_params & MAX_OOB_RETRIES_RCVD))
        data->max_oob_retries = DEFAULT_MAX_OOB_RETRIES;
    if (! (data->config_params & DEF_MIN_SLEEP_RCVD))
        eap_noob_global_conf.default_minsleep = 0;
    if (! (data->config_params & MSG_ENC_FMT_RCVD))
        eap_noob_global_conf.oob_enc_fmt = FORMAT_BASE64URL;

    return SUCCESS;
}

/**
 * eap_noob_read_config : read configuraions from config file
 * @data : peer data
 * Returns : SUCCESS/FAILURE
**/

static int eap_noob_read_config(struct eap_sm *sm, struct eap_noob_data * data)
{
    FILE * conf_file = NULL;
    char * buff = NULL;

    if (NULL == (conf_file = fopen(CONF_FILE,"r"))) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Configuration file not found");
        return FAILURE;
    }

    if ((NULL == (buff = malloc(MAX_CONF_LEN))) || (NULL == (data->peer_config_params = \
                 malloc(sizeof(struct eap_noob_peer_config_params)))) )
        return FAILURE;

    data->config_params = 0;
    while(!feof(conf_file)) {
        if (fgets(buff,MAX_CONF_LEN, conf_file)) {
            eap_noob_parse_config(buff, data);
            memset(buff,0,MAX_CONF_LEN);
        }
    }
    free(buff);
    fclose(conf_file);

    if ((data->version >MAX_SUP_VER) || (data->cryptosuitep > MAX_SUP_CSUITES) ||
        (data->dirp > BOTH_DIRECTIONS)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect confing value");
        return FAILURE;
    }

    if (eap_noob_global_conf.oob_enc_fmt != FORMAT_BASE64URL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Unsupported OOB message encoding format");
        return FAILURE;
    }

    if (data->config_params != CONF_PARAMS && FAILURE == eap_noob_handle_incomplete_conf(data))
        return FAILURE;

    if (NULL != (data->peer_info = eap_noob_prepare_peer_info_string(sm, data->peer_config_params))) {
            if (!data->peer_info || os_strlen(data->peer_info) > MAX_INFO_LEN) {
                wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect or no peer info");
                return FAILURE;
            }
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: PEER INFO = %s", data->peer_info);
    return SUCCESS;
}

static void columns_persistentstate(struct eap_noob_data * data, sqlite3_stmt * stmt)
{
    data->ssid = os_strdup((char *)sqlite3_column_text(stmt, 0));
    data->peerid = os_strdup((char *)sqlite3_column_text(stmt, 1));
    data->version = sqlite3_column_int(stmt, 2);
    data->cryptosuitep = sqlite3_column_int(stmt, 3);
    data->cryptosuitep_prev = sqlite3_column_int(stmt, 4);
    data->realm = os_strdup((char *) sqlite3_column_text(stmt, 5));
    data->Kz = os_memdup(sqlite3_column_blob(stmt, 6), KZ_LEN);
    data->KzPrev = os_memdup(sqlite3_column_blob(stmt, 7), KZ_LEN);
    data->peer_state = RECONNECTING_STATE;
}

static void columns_ephemeralstate(struct eap_noob_data * data, sqlite3_stmt * stmt)
{
    char * Vers, * Cryptosuites;
    data->ssid = os_strdup((char *)sqlite3_column_text(stmt, 0));
    data->peerid = os_strdup((char *) sqlite3_column_text(stmt, 1));
    Vers = os_strdup((char *)sqlite3_column_text(stmt, 2));
    Cryptosuites = os_strdup((char *)sqlite3_column_text(stmt, 3));
    data->realm = os_strdup((char *) sqlite3_column_text(stmt, 4));
    data->dirs = sqlite3_column_int(stmt, 5);
    data->server_info = os_strdup((char *) sqlite3_column_text(stmt, 6));
    data->kdf_nonce_data->Ns = os_memdup(sqlite3_column_blob(stmt, 7), NONCE_LEN);
    data->kdf_nonce_data->Np = os_memdup(sqlite3_column_blob(stmt, 8), NONCE_LEN);
    data->ecdh_exchange_data->shared_key = os_memdup(sqlite3_column_blob(stmt, 9), ECDH_SHARED_SECRET_LEN) ;
    data->mac_input_str = os_strdup((char *) sqlite3_column_text(stmt, 10));
    //data->creation_time = (uint64_t) sqlite3_column_int64(stmt, 11);
    data->err_code = sqlite3_column_int(stmt, 12);
    data->peer_state = sqlite3_column_int(stmt, 13);
    data->ecdh_exchange_data->jwk_serv = os_strdup((char *) sqlite3_column_text(stmt, 14));
    data->ecdh_exchange_data->jwk_peer = os_strdup((char *) sqlite3_column_text(stmt, 15));
    data->oob_retries = sqlite3_column_int(stmt, 16);
    data->dirp = sqlite3_column_int(stmt, 17);
    eap_noob_decode_vers_cryptosuites(data, Vers, Cryptosuites);
}

static void columns_ephemeralnoob(struct eap_noob_data * data, sqlite3_stmt * stmt)
{
    data->ssid = os_strdup((char *)sqlite3_column_text(stmt, 0));
    data->peerid = os_strdup((char *) sqlite3_column_text(stmt, 1));
    data->oob_data->NoobId_b64 = os_strdup((char *)sqlite3_column_text(stmt, 2));
    data->oob_data->Noob_b64 = os_strdup((char *)sqlite3_column_text(stmt, 3));
    data->oob_data->Hoob_b64 = os_strdup((char *)sqlite3_column_text(stmt, 4));
    //sent time
}

/**
 * eap_noob_assign_waittime : assign time fow which the SSID should be disabled.
 * @sm : eap state machine context
 * data: peer data
**/
static void eap_noob_assign_waittime(struct eap_sm * sm, struct eap_noob_data * data)
{
    struct timespec tv;
    struct wpa_supplicant * wpa_s = (struct wpa_supplicant *) sm->msg_ctx;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
    clock_gettime(CLOCK_BOOTTIME, &tv);
    if (0 == data->minsleep && 0 != eap_noob_global_conf.default_minsleep)
        data->minsleep = eap_noob_global_conf.default_minsleep;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Wait time  = %d", data->minsleep);
    if (0 == os_strcmp(wpa_s->driver->name,"wired")) {
        sm->disabled_wired = tv.tv_sec + data->minsleep;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: disabled untill = %ld", sm->disabled_wired);
        data->wired = 1; return;
    }

    sm->disabled_wired = 0;
    wpa_s->current_ssid->disabled_until.sec = tv.tv_sec + data->minsleep;
    wpa_blacklist_add(wpa_s, wpa_s->current_ssid->bssid);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: SSID %s, time now : %ld  disabled untill = %ld", wpa_s->current_ssid->ssid, tv.tv_sec,
               wpa_s->current_ssid->disabled_until.sec);
}

/**
 * eap_noob_check_compatibility : check peer's compatibility with server.
 * The type 1 message params are used for making any dicision
 * @data : peer data
 * Returns : SUCCESS/FAILURE
 **/
int eap_noob_check_compatibility(struct eap_noob_data *data)
{
    u32 count = 0;
    u8 vers_supported = 0;
    u8 csuite_supp = 0;

    // Only verify directions during the initial exchange.
    if (data->peer_state != RECONNECTING_STATE) {
        if (0 == (data->dirs & data->dirp)) {
            data->err_code = E3003; return FAILURE;
        }
    }

    for(count = 0; count < MAX_SUP_CSUITES ; count ++) {
        if (0 != (data->cryptosuitep & data->cryptosuites[count])) {
            csuite_supp = 1; break;
        }
    }

    if (csuite_supp == 0) {
        data->err_code = E3002;
        return FAILURE;
    }

    for(count = 0; count < MAX_SUP_VER ; count ++) {
        if (0 != (data->version & data->versions[count])) {
            vers_supported = 1; break;
        }
    }

    if (vers_supported == 0) {
        data->err_code = E3001; return FAILURE;
    }
    return SUCCESS;
}

/**
 * eap_noob_config_change : write back the content of identity into .conf file
 * @data : peer data
 * @sm : eap state machine context.
**/
static void eap_noob_config_change(struct eap_sm *sm , struct eap_noob_data *data)
{
    char buff[120] = {0};
    size_t len = 0;
    struct wpa_supplicant * wpa_s = (struct wpa_supplicant *)sm->msg_ctx;

    if (wpa_s) {
        snprintf(buff,120,"%s+s%d@%s", data->peerid, data->peer_state, data->realm);
        len = os_strlen(buff);

        os_free(wpa_s->current_ssid->eap.identity);
        wpa_s->current_ssid->eap.identity = os_malloc(os_strlen(buff));

        os_memcpy(wpa_s->current_ssid->eap.identity, buff, len);
        wpa_s->current_ssid->eap.identity_len = len;

        wpa_config_write(wpa_s->confname,wpa_s->conf);
    }
}

/**
 * eap_noob_db_entry_check : check for an PeerId entry inside the DB
 * @priv : server context
 * @argc : argument count
 * @argv : argument 2d array
 * @azColName : colomn name 2d array
**/
int eap_noob_db_entry_check(void * priv , int argc, char **argv, char **azColName)
{
    struct eap_noob_data * data = priv;

    if (strtol(argv[0],NULL,10) == 1) {
        data->record_present = true;
    }
    return 0;
}


/**
 * eap_noob_db_update : prepare a DB update query
 * @data : peer data
 * Returns : SUCCESS/FAILURE
**/
static int eap_noob_db_update(struct eap_noob_data * data, u8 type)
{
    char * query = os_zalloc(MAX_QUERY_LEN);
    int ret = FAILURE;

    switch(type) {
        case UPDATE_PERSISTENT_STATE:
            snprintf(query, MAX_QUERY_LEN, "UPDATE PersistentState SET Cryptosuitep=?, CryptosuitepPrev=?, Kz=?, PeerState=? where PeerID=?");
            ret = eap_noob_exec_query(data, query, NULL, 11, INT, data->cryptosuitep, INT, data->cryptosuitep_prev, BLOB, KZ_LEN, data->kdf_out->Kz, INT, data->peer_state, TEXT, data->peerid);
            break;
        case UPDATE_STATE_ERROR:
            snprintf(query, MAX_QUERY_LEN, "UPDATE EphemeralState SET ErrorCode=? where PeerId=?");
            ret = eap_noob_exec_query(data, query, NULL, 4, INT, data->err_code, TEXT, data->peerid);
            break;
        case UPDATE_OOB_RETRIES:
            snprintf(query, MAX_QUERY_LEN, "UPDATE EphemeralState SET OobRetries=? WHERE PeerId=?");
            ret = eap_noob_exec_query(data, query, NULL, 4, INT, data->oob_retries, TEXT, data->peerid);
            break;
        case DELETE_SSID:
            snprintf(query, MAX_QUERY_LEN, "DELETE FROM EphemeralState WHERE Ssid=?");
            ret = eap_noob_exec_query(data, query, NULL, 2, TEXT, data->ssid);
            snprintf(query, MAX_QUERY_LEN, "DELETE FROM EphemeralNoob WHERE Ssid=?");
            ret = eap_noob_exec_query(data, query, NULL, 2, TEXT, data->ssid);
            break;
        default:
            wpa_printf(MSG_ERROR, "EAP-NOOB: Wrong DB update type");
            return FAILURE;
    }
    if (FAILURE == ret) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: DB update failed");
    }

    os_free(query);
    return ret;
}

/**
 * eap_noob_db_entry : Make an entery of the current SSID context inside the DB
 * @sm : eap statemachine context
 * @data : peer data
 * Returns : FAILURE/SUCCESS
**/
static int eap_noob_db_update_initial_exchange_info(struct eap_sm * sm, struct eap_noob_data * data)
{
    struct wpa_supplicant * wpa_s = NULL;
    char query[MAX_QUERY_LEN] = {0};
    char * Vers = NULL;
    char * Cryptosuites = NULL;
    int ret = 0, err = 0;

    if (NULL == data || NULL == sm) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__); return FAILURE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);
    wpa_s = (struct wpa_supplicant *)sm->msg_ctx;
    err -= (FAILURE == eap_noob_encode_vers_cryptosuites(data, &Vers, &Cryptosuites));
    //err -= (NULL == (data->mac_input_str = json_dumps(data->mac_input, JSON_COMPACT|JSON_PRESERVE_ORDER)));
    if (data->mac_input_str)
        wpa_printf(MSG_DEBUG, "EAP-NOOB: MAC str %s", data->mac_input_str);
    if (err < 0) { ret = FAILURE; goto EXIT; }

    snprintf(query, MAX_QUERY_LEN,"INSERT INTO EphemeralState (Ssid, PeerId, Vers, Cryptosuites, Realm, Dirs, "
            "ServerInfo, Ns, Np, Z, MacInput, PeerState, JwkServer, JwkPeer, OobRetries, Dirp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    ret = eap_noob_exec_query(data, query, NULL, 35, TEXT, wpa_s->current_ssid->ssid, TEXT, data->peerid,
            TEXT,  Vers, TEXT, Cryptosuites, TEXT, data->realm, INT, data->dirs,
            TEXT, data->server_info, BLOB, NONCE_LEN, data->kdf_nonce_data->Ns, BLOB,
            NONCE_LEN, data->kdf_nonce_data->Np, BLOB, ECDH_SHARED_SECRET_LEN,
            data->ecdh_exchange_data->shared_key, TEXT, data->mac_input_str, INT,
            data->peer_state, TEXT, data->ecdh_exchange_data->jwk_serv,
            TEXT, data->ecdh_exchange_data->jwk_peer, INT, 0, INT, data->dirp);

    if (FAILURE == ret) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: DB value insertion failed");
    }
EXIT:
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s",__func__);
    if (Vers)
        EAP_NOOB_FREE(Vers);
    if (Cryptosuites)
        EAP_NOOB_FREE(Cryptosuites);
    return ret;
}

static int eap_noob_update_persistentstate(struct eap_noob_data * data)
{
    char query[MAX_QUERY_LEN] = {0};
    int ret = SUCCESS, err = 0;

    if (NULL == data) { wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__); return FAILURE; }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);

    err -= (FAILURE == eap_noob_db_statements(data->db, DELETE_EPHEMERAL_FOR_ALL));
    if (err < 0) { ret = FAILURE; goto EXIT; }
    /* snprintf(query, MAX_QUERY_LEN, "INSERT INTO PersistentState (Ssid, PeerId, Vers, Cryptosuites, Realm, Kz, "
        "creation_time, last_used_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"); */
    snprintf(query, MAX_QUERY_LEN, "INSERT INTO PersistentState (Ssid, PeerId, Verp, Cryptosuitep, CryptosuitepPrev, Realm, Kz, KzPrev, PeerState) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");

    if(data->Kz){
    	 wpa_printf(MSG_DEBUG, "NOT NULL and state %d",data->peer_state);
    	 wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: KZ is", data->Kz, KZ_LEN);}
    else
    	 wpa_printf(MSG_DEBUG, "Kz is somehow null and state %d", data->peer_state);



    err -= (FAILURE == eap_noob_exec_query(data, query, NULL, 20, TEXT, data->ssid, TEXT, data->peerid,
            INT, data->version, INT, data->cryptosuitep, INT, data->cryptosuitep_prev, TEXT, data->realm, BLOB, KZ_LEN, data->Kz, BLOB, KZ_LEN, data->KzPrev,
            INT, data->peer_state));
    if (err < 0) { ret = FAILURE; goto EXIT; }
EXIT:
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, return %d",__func__, ret);
    return ret;
}

/**
 * eap_noob_create_db : Creates a new DB or opens the existing DB and populates the context
 * @sm : eap statemachine context
 * @data : peer data
 * returns : SUCCESS/FAILURE
**/
static int eap_noob_create_db(struct eap_sm *sm, struct eap_noob_data * data)
{
    struct wpa_supplicant * wpa_s = (struct wpa_supplicant *) sm->msg_ctx;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Opening database");

    if (SQLITE_OK != sqlite3_open_v2(DB_NAME, &data->db,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: No DB found,new DB willbe created");
        wpa_printf(MSG_ERROR, "EAP-NOOB: sqlite error: %s", sqlite3_errmsg(data->db));
        return FAILURE;
    }

    if (FAILURE == eap_noob_db_statements(data->db, CREATE_TABLES_EPHEMERALSTATE) ||
        FAILURE == eap_noob_db_statements(data->db, CREATE_TABLES_PERSISTENTSTATE)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Unexpected error in table cration");
        return FAILURE;
    }
    if ((wpa_s->current_ssid->ssid) || (0 == os_strcmp(wpa_s->driver->name,"wired"))) {

        int ret = eap_noob_exec_query(data, QUERY_EPHEMERALSTATE, columns_ephemeralstate, 2,
                       TEXT, wpa_s->current_ssid->ssid);
        if (ret == FAILURE || ret == EMPTY ) {
            ret = eap_noob_exec_query(data, QUERY_PERSISTENTSTATE, columns_persistentstate, 2,
                       TEXT, wpa_s->current_ssid->ssid);
            if (ret == FAILURE || ret == EMPTY ) {
                wpa_printf(MSG_DEBUG, "EAP-NOOB: SSID not present in any tables");
                return SUCCESS;
            } else {
                // TODO: Why set the peer state explicitly to registered, while
                // it just reads out the peer state from the database?
                //data->peer_state = REGISTERED_STATE;
            }
        } else {
            if (FAILURE != eap_noob_exec_query(data, QUERY_EPHEMERALNOOB, columns_ephemeralnoob, 2,
                           TEXT, wpa_s->current_ssid->ssid)) {
                wpa_printf(MSG_DEBUG, "EAP-NOOB: WAITING FOR OOB state");
                return SUCCESS;
            }
        }
    }
    if (data->peerid)
        data->peerid = os_strdup(data->peerid);
    return SUCCESS;
}

/**
 * eap_noob_err_msg : prepares error message
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_err_msg(struct eap_noob_data * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(ERRORCODE) + strlen(ERRORINFO);
    size_t code = 0;

    if (!data || !(code = data->err_code)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is NULL", __func__);
        goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Build error message");

    len += strlen(error_info[code]);

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, NONE);
    json_value_sep(json);
    if (data->peerid) {
        json_add_string(json, PEERID, data->peerid);
        json_value_sep(json);
    }
    json_add_int(json, ERRORCODE, error_code[code]);
    json_value_sep(json);
    json_add_string(json, ERRORINFO, error_info[code]);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str) + 1;

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for error message response");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    if (json_str)
        EAP_NOOB_FREE(json_str);
    return resp;
}

/**
 * eap_noob_verify_PeerId : compares recived PeerId with the assigned one
 * @data : peer data
 * @id : response message ID
**/
static struct wpabuf * eap_noob_verify_PeerId(struct eap_noob_data * data, u8  id)
{
    if ((data->peerid) && (data->peerid_rcvd) &&
        (0 != os_strcmp(data->peerid, data->peerid_rcvd))) {
        data->err_code = E2004;
        return eap_noob_err_msg(data, id);
    }
    return NULL;
}

/**
 * eap_noob_build_type_9
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_build_type_9(const struct eap_noob_data * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN + strlen(MACP2) + MAC_LEN;
    u8 * mac = NULL;
    char * mac_b64 = NULL;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING BUILD TYPE 9");

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    // Generate the MAC
    mac = eap_noob_gen_MAC(data, MACP_TYPE, data->kdf_out->Kmp, KMP_LEN, RECONNECTING_STATE);
    if (!mac) {
        goto EXIT;
    }

    // Convert MAC to base 64
    if (FAILURE == eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64)) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_9);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peerid);
    json_value_sep(json);
    json_add_string(json, MACP2, mac_b64);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str) + 1;

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for Response/NOOB-RE");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    if (json_str)
        EAP_NOOB_FREE(json_str);
    return resp;
}

/**
 * To-Do Based on the cryptosuite and server request decide whether new key has to be derived or not
 * eap_noob_build_type_8
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_build_type_8(struct eap_noob_data * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN
        + strlen(NP) + NONCE_LEN * 1.5;
    size_t secret_len = ECDH_SHARED_SECRET_LEN;
    char * Np_b64;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING BUILD TYPE 8");

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        goto EXIT;
    }

    // Generate peer nonce
    data->kdf_nonce_data->Np = os_zalloc(NONCE_LEN);
    int rc = RAND_bytes(data->kdf_nonce_data->Np, NONCE_LEN);
    unsigned long error = ERR_get_error();
    if (rc != SUCCESS) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce. Error=%lu", error);
        os_free(data->kdf_nonce_data->Np);
        goto EXIT;
    }

    // Encode the nonce in base 64
    eap_noob_Base64Encode(data->kdf_nonce_data->Np, NONCE_LEN, &Np_b64);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Nonce %s", Np_b64);

    // If KeyingMode is 2 or 3, generate a fresh ECDH key pair
    if (data->keying_mode == KEYING_RECONNECT_EXCHANGE_ECDHE
        || data->keying_mode == KEYING_RECONNECT_EXCHANGE_NEW_CRYPTOSUITE) {
        // Generate key material
        if (eap_noob_get_key(data, true) == FAILURE) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate keys");
            goto EXIT;
        }

        // Build JWK to represent server
        if (FAILURE == eap_noob_build_JWK(data, &data->ecdh_exchange_data->jwk_peer,
                    data->ecdh_exchange_data->x_b64)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate JWK");
            goto EXIT;
        }

        // Derive shared secret and encode in base 64
        eap_noob_derive_session_secret(data, &secret_len);
        data->ecdh_exchange_data->shared_key_b64_len = eap_noob_Base64Encode(
                    data->ecdh_exchange_data->shared_key,
                    ECDH_SHARED_SECRET_LEN,
                    &data->ecdh_exchange_data->shared_key_b64
                );

        // Increase the length to be allocated to the wpabuf because it will
        // also contain a JWK object.
        // TODO: Figure out a good default max length for JWK objects.
        len += strlen(PKP2) + 500;
    }

    // Create JSON EAP message

    json = wpabuf_alloc(len);
    if (!json) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for json response");
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_8);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peerid);
    json_value_sep(json);
    if (data->keying_mode == KEYING_RECONNECT_EXCHANGE_ECDHE
        || data->keying_mode == KEYING_RECONNECT_EXCHANGE_NEW_CRYPTOSUITE) {
        wpabuf_printf(json, "\"%s\":%s", PKP2, data->ecdh_exchange_data->jwk_peer);
        json_value_sep(json);
    }
    json_add_string(json, NP2, Np_b64);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str) + 1;

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for Response/RE");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    if (json_str)
        EAP_NOOB_FREE(json_str);
    EAP_NOOB_FREE(Np_b64);
    return resp;
}

/**
 * eap_noob_build_type_7
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_build_type_7(struct eap_sm *sm, struct eap_noob_data *data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(VERP) + strlen(PEERID) + MAX_PEER_ID_LEN + strlen(CRYPTOSUITEP)
        + strlen(PEERINFO) + MAX_INFO_LEN;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING BUILD TYPE 7");

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        goto EXIT;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, VERP, data->version);
    json_value_sep(json);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_7);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peerid);
    json_value_sep(json);
    json_add_int(json, CRYPTOSUITEP, data->cryptosuitep);

    // TODO: Only include the PeerInfo if it has changed
    // TODO: Figure out how to determine whether it has changed compared to what the server knows
    json_value_sep(json);
    // Helper method to add JSON object to the wpabuf
    eap_noob_prepare_peer_info_json(sm, data->peer_config_params, json, PEERINFO);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str) + 1;

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for Reconnect Exchange Response");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    if (json_str)
        EAP_NOOB_FREE(json_str);
    return resp;
}

/**
 * eap_noob_build_type_6
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_build_type_6(const struct eap_noob_data * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN + strlen(MACP) + MAC_LEN;
    char * mac_b64 = NULL;
    u8 * mac = NULL;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING BUILD TYPE 6");

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        return NULL;
    }

    mac = eap_noob_gen_MAC(data, MACP_TYPE, data->kdf_out->Kmp,
            KMP_LEN, data->peer_state);
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
    json_add_int(json, TYPE, EAP_NOOB_TYPE_6);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peerid);
    json_value_sep(json);
    json_add_string(json, MACP, mac_b64);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str) + 1;

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for Completion Response");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    if (json_str)
        EAP_NOOB_FREE(json_str);
    EAP_NOOB_FREE(mac_b64);
    return resp;
}

/**
 * eap_noob_build_type_5
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_build_type_5(const struct eap_noob_data * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN
        + strlen(NOOBID) + NOOBID_LEN;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING BUILD TYPE 5");

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_5);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peerid);
    json_value_sep(json);
    json_add_string(json, NOOBID, data->oob_data->NoobId_b64);
    json_end_object(json);

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Hint is %s", data->oob_data->NoobId_b64);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str) + 1;

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for NoobId hint response");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    if (json_str)
        EAP_NOOB_FREE(json_str);
    return resp;
}

/**
 * eap_noob_build_type_4
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_build_type_4(const struct eap_noob_data *data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING BUILD TYPE 4");

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        goto EXIT;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_4);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peerid);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str) + 1;

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (resp == NULL) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for Response/NOOB-WE");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    if (json_str)
        EAP_NOOB_FREE(json_str);
    return resp;
}

/**
 * eap_noob_build_type_3
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_build_type_3(struct eap_noob_data * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN
        + strlen(PKP) + 500 + strlen(NP) + NONCE_LEN * 1.5;
    size_t secret_len = ECDH_SHARED_SECRET_LEN;
    char * Np_b64;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING BUILD TYPE 3");

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        goto EXIT;
    }

    // Generate peer nonce
    data->kdf_nonce_data->Np = os_zalloc(NONCE_LEN);
    int rc = RAND_bytes(data->kdf_nonce_data->Np, NONCE_LEN);
    unsigned long error = ERR_get_error();
    if (rc != 1) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce. Error=%lu", error);
        os_free(data->kdf_nonce_data->Np);
        goto EXIT;
    }

    // Encode the nonce in base 64
    eap_noob_Base64Encode(data->kdf_nonce_data->Np, NONCE_LEN, &Np_b64);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Nonce %s", Np_b64);

    // Generate key material
    if (eap_noob_get_key(data, true) == FAILURE) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate keys");
        goto EXIT;
    }

    // Build JWK to represent peer
    if (FAILURE == eap_noob_build_JWK(data, &data->ecdh_exchange_data->jwk_peer,
                data->ecdh_exchange_data->x_b64)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to build JWK in response type 2");
        goto EXIT;
    }

    // Derive shared secret and encode in base 64
    eap_noob_derive_session_secret(data, &secret_len);
    data->ecdh_exchange_data->shared_key_b64_len = eap_noob_Base64Encode(
                data->ecdh_exchange_data->shared_key,
                ECDH_SHARED_SECRET_LEN,
                &data->ecdh_exchange_data->shared_key_b64
            );

    // Create JSON EAP message

    json = wpabuf_alloc(len);
    if (!json) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for json response");
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_3);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peerid);
    json_value_sep(json);
    wpabuf_printf(json, "\"%s\":%s", PKP, data->ecdh_exchange_data->jwk_peer);
    json_value_sep(json);
    json_add_string(json, NP, Np_b64);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str) + 1;

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for Response/NOOB-IE");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    if (json_str)
        EAP_NOOB_FREE(json_str);
    EAP_NOOB_FREE(Np_b64);
    return resp;
}

/**
 * eap_noob_build_type_2
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_build_type_2(struct eap_sm *sm, struct eap_noob_data *data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(VERP) + strlen(PEERID) + MAX_PEER_ID_LEN
        + strlen(CRYPTOSUITEP) + strlen(DIRP) + strlen(PEERINFO) + MAX_INFO_LEN;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING BUILD TYPE 2");

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        goto EXIT;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_2);
    json_value_sep(json);
    json_add_int(json, VERP, data->version);
    json_value_sep(json);
    json_add_string(json, PEERID, data->peerid);
    json_value_sep(json);
    json_add_int(json, CRYPTOSUITEP, data->cryptosuitep);
    json_value_sep(json);
    json_add_int(json, DIRP, data->dirp);
    json_value_sep(json);
    eap_noob_prepare_peer_info_json(sm, data->peer_config_params,
                                    json, PEERINFO);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str) + 1;

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for Response/NOOB-IE");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    if (json_str)
        EAP_NOOB_FREE(json_str);
    return resp;
}

/**
 * Prepare peer response to common handshake
 * @data   : peer data
 * @id     : response message id
 * Returns : pointer to message buffer containing json response as string
 */
static struct wpabuf * eap_noob_build_type_1(const struct eap_noob_data * data, u8 id)
{
    struct wpabuf * json = NULL;
    struct wpabuf * resp = NULL;
    char * json_str = NULL;
    size_t len = 100 + strlen(TYPE) + strlen(PEERID) + MAX_PEER_ID_LEN + strlen(PEERSTATE);

    wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING BUILD TYPE 1");

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        goto EXIT;
    }

    json = wpabuf_alloc(len);
    if (!json) {
        goto EXIT;
    }

    json_start_object(json, NULL);
    json_add_int(json, TYPE, EAP_NOOB_TYPE_1);
    json_value_sep(json);

    // Only include PeerId if peer is not in Unregistered state (0)
    if (data->peer_state != UNREGISTERED_STATE) {
        json_add_string(json, PEERID, data->peerid);
        json_value_sep(json);
    }

    json_add_int(json, PEERSTATE, data->peer_state);
    json_end_object(json);

    json_str = strndup(wpabuf_head(json), wpabuf_len(json));
    len = os_strlen(json_str) + 1;

    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (!resp) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for handshake response");
        goto EXIT;
    }

    wpabuf_put_data(resp, json_str, len);
EXIT:
    wpabuf_free(json);
    if (json_str)
        EAP_NOOB_FREE(json_str);
    return resp;
}

/**
 * eap_noob_process_type_9
 * @eap_sm : eap statemachine context
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_process_type_9(struct eap_sm * sm, struct eap_noob_data * data, u8 id)
{
    struct wpabuf * resp = NULL;
    u8 * mac = NULL;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__); return NULL;
    }
    if (data->rcvd_params != TYPE_NINE_PARAMS) {
        data->err_code = E1002;
        resp = eap_noob_err_msg(data,id); return resp;
    }
    data->rcvd_params = 0;
    if (NULL != (resp = eap_noob_verify_PeerId(data,id))) return resp;

    /* Generate KDF and MAC */
    if (SUCCESS != eap_noob_gen_KDF(data, RECONNECT_EXCHANGE, false)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Error in KDF during Request/NOOB-FR"); return NULL;
    }
    mac = eap_noob_gen_MAC(data, MACS_TYPE, data->kdf_out->Kms, KMS_LEN, RECONNECTING_STATE);
    if (NULL == mac) return NULL;

    /*
     * Rules for verifying MACs2
     * As specified in the current draft
     * https://tools.ietf.org/html/draft-ietf-emu-eap-noob-01#section-3.4.2
     */

    // 1. Compare received MACs2 against locally computed one using Kz from
    // the persistent EAP-NOOB association
    if (0 != strcmp((char *)mac,data->mac)) {
        // 2. Check if MAC computed with KzPrev is equal to MACs2
        if (data->KzPrev) {
            // Run KDF but tell it to use KzPrev instead of Kz
            if (SUCCESS != eap_noob_gen_KDF(data, RECONNECT_EXCHANGE, true)) {
                wpa_printf(MSG_ERROR, "EAP-NOOB: Error in KDF during Request/NOOB-FR"); return NULL;
            }
            mac = eap_noob_gen_MAC(data, MACS_TYPE, data->kdf_out->Kms, KMS_LEN, RECONNECTING_STATE);
            if (NULL == mac) return NULL;
        }

        // Check if the MAC values are the same when using KzPrev
        // Note: If there is no KzPrev value, this will do the same check as
        // before and thus it will still fail, as is expected.
        if (strcmp((char *) mac, data->mac)) {
            // 4. Both do not match the received MAC, return error message
            data->err_code = E4001;
            resp = eap_noob_err_msg(data, id); return resp;
        }

        // If the second MAC matched the received value, rollback the upgrade
        memcpy(data->Kz, data->KzPrev, KZ_LEN);
        data->cryptosuitep = data->cryptosuitep_prev;
    }

    // 3. One of two matched, proceed to send final response

    // Prepare for possible synchronization failure caused by the loss of
    // the final response (Type=9) during cryptosuite upgrade
    if (data->keying_mode == KEYING_RECONNECT_EXCHANGE_NEW_CRYPTOSUITE) {
        data->KzPrev = os_zalloc(KZ_LEN);
        memcpy(data->KzPrev, data->Kz, KZ_LEN);
        data->Kz = os_zalloc(KZ_LEN);
        memcpy(data->Kz, data->kdf_out->Kz, KZ_LEN);
    }

    resp = eap_noob_build_type_9(data, id);
    data->peer_state = REGISTERED_STATE;
    eap_noob_config_change(sm, data);

    if (FAILURE == eap_noob_db_update(data, UPDATE_PERSISTENT_STATE)) {
        wpabuf_free(resp); return NULL;
    }
    return resp;
}

/**
 * eap_noob_process_type_8
 * @eap_sm : eap statemachine context
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_process_type_8(struct eap_sm *sm, struct eap_noob_data *data, u8 id)
{
    struct wpabuf * resp = NULL;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    if ((data->rcvd_params & TYPE_EIGHT_PARAMS) != TYPE_EIGHT_PARAMS) {
        data->err_code = E1002;
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (NULL == (resp = eap_noob_verify_PeerId(data,id))) {
        resp = eap_noob_build_type_8(data,id);
    }

    data->rcvd_params = 0;
    return resp;
}

/**
 * eap_noob_process_type_7
 * @eap_sm : eap statemachine context
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_process_type_7(struct eap_sm *sm, struct eap_noob_data * data, u8 id)
{
    struct wpabuf * resp = NULL;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    if (FAILURE == eap_noob_read_config(sm, data)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to read config file");
        return NULL;
    }

    if ((data->rcvd_params & TYPE_SEVEN_PARAMS) != TYPE_SEVEN_PARAMS) {
        data->err_code = E1002;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Mismatch in received parameters");
        resp = eap_noob_err_msg(data,id);
        return resp;
    }
    data->peerid = os_strdup(data->peerid);
    //TODO: handle eap_noob failure scenario
    if (SUCCESS == eap_noob_check_compatibility(data))
        resp = eap_noob_build_type_7(sm,data, id);
    else
        resp = eap_noob_err_msg(data,id);

    data->rcvd_params = 0;
    return resp;
}

static int eap_noob_exec_noobid_queries(struct eap_noob_data * data)
{
    char query[MAX_QUERY_LEN] = {0};
    snprintf(query, MAX_QUERY_LEN, "SELECT * from EphemeralNoob WHERE PeerId = ? AND NoobId = ?;");
    return eap_noob_exec_query(data, query, columns_ephemeralnoob, 4, TEXT, data->peerid, TEXT,
        data->oob_data->NoobId_b64);
}

/**
 * eap_noob_process_type_6
 * @eap_sm : eap statemachine context
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_process_type_6(struct eap_sm * sm, struct eap_noob_data * data, u8 id)
{
    struct wpabuf * resp = NULL;
    u8 * mac = NULL;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    if (data->rcvd_params != TYPE_SIX_PARAMS) {
        data->err_code = E1002;
        resp = eap_noob_err_msg(data,id); return resp;
    }
    data->rcvd_params = 0;
    /* Execute NoobId query in peer to server direction */
    if (data->dirp == PEER_TO_SERVER){
       int ret = eap_noob_exec_noobid_queries(data);
       if(ret == FAILURE || ret == EMPTY){
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Unrecognized NoobId");
        data->err_code = E2003;
        resp = eap_noob_err_msg(data,id);
        return resp;
       }
    }
    /* generate Keys */
    if (SUCCESS != eap_noob_gen_KDF(data, COMPLETION_EXCHANGE, false)) {
    	wpa_printf(MSG_ERROR, "EAP-NOOB: Error in KDF during Request/NOOB-CE"); return NULL;
    }
    if (NULL != (resp = eap_noob_verify_PeerId(data, id))) return resp;

    mac = eap_noob_gen_MAC(data, MACS_TYPE, data->kdf_out->Kms, KMS_LEN, data->peer_state);
    if (!mac) {
        wpabuf_free(resp);
        return NULL;
    }

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: MAC received ", data->mac, 32);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: MAC calculated ", mac, 32);
    if (0 != os_memcmp(mac, data->mac, MAC_LEN)) {
        data->err_code = E4001;
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    resp = eap_noob_build_type_6(data, id);
    data->peer_state = REGISTERED_STATE;
    eap_noob_config_change(sm, data);
    if (resp == NULL) wpa_printf(MSG_DEBUG, "EAP-NOOB: Null resp 4");

    if (FAILURE == eap_noob_update_persistentstate(data)) {
        wpabuf_free(resp); return NULL;
    }
    wpa_printf(MSG_DEBUG,"PEER ID IS STILL: %s",data->peerid);
    return resp;
}

/**
 * eap_noob_process_type_5
 * @eap_sm : eap statemachine context
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_process_type_5(struct eap_sm *sm, struct eap_noob_data * data, u8 id)
{
    struct wpabuf *resp = NULL;

    if (data->rcvd_params != TYPE_FIVE_PARAMS) {
        data->err_code = E1002;
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (NULL == (resp = eap_noob_verify_PeerId(data,id))) {
        resp = eap_noob_build_type_5(data,id);
    }
    return resp;
}

/**
 * eap_noob_process_type_4
 * @eap_sm : eap statemachine context
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_process_type_4(struct eap_sm * sm, struct eap_noob_data * data, u8 id)
{
    struct wpabuf * resp = NULL;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__); return NULL;
    }

    if (data->rcvd_params != TYPE_FOUR_PARAMS) {
        data->err_code = E1002;
        resp = eap_noob_err_msg(data,id); return resp;
    }

    if (NULL == (resp = eap_noob_verify_PeerId(data,id))) {
        resp = eap_noob_build_type_4(data,id);
        if (0 != data->minsleep) eap_noob_assign_waittime(sm,data);
    }

    return resp;
}

/**
 * eap_noob_process_type_3
 * @eap_sm : eap statemachine context
 * @data : peer data
 * @id : pointer to response message buffer or null
**/
static struct wpabuf * eap_noob_process_type_3(struct eap_sm *sm, struct eap_noob_data * data, u8 id)
{
    struct wpabuf *resp = NULL;

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    if (data->rcvd_params != TYPE_THREE_PARAMS) {
        data->err_code = E1002;
        resp = eap_noob_err_msg(data,id); return resp;
    }

    if (NULL == (resp = eap_noob_verify_PeerId(data,id))) {
        resp = eap_noob_build_type_3(data,id);
        data->peer_state = WAITING_FOR_OOB_STATE;
        // Generate the MAC input string such that it can be used for
        // calculating the Hoob
        data->mac_input_str = eap_noob_build_mac_input(data, data->dirp, data->peer_state);
        if (SUCCESS == eap_noob_db_update_initial_exchange_info(sm, data)) eap_noob_config_change(sm, data);
    }
    if (0!= data->minsleep)
        eap_noob_assign_waittime(sm,data);

    return resp;
}

/**
 * eap_noob_process_type_2
 * @eap_sm : eap statemachine context
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_process_type_2(struct eap_sm * sm, struct eap_noob_data * data, u8 id)
{
    struct wpabuf * resp = NULL;
    char * url = NULL;
    char url_cpy[2 * MAX_URL_LEN] = {0};

    if (!data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    if (FAILURE == eap_noob_read_config(sm, data)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to read config file");
        return NULL;
    }

    if (data->rcvd_params != TYPE_TWO_PARAMS) {
        data->err_code = E1002;
        resp = eap_noob_err_msg(data,id); return resp;
    }

    /* checks on the received URL */
    if ( NULL == (url = os_strstr(data->server_info, "https://"))) {
        data->err_code = E5003;
        resp = eap_noob_err_msg(data,id); return resp;
    }
    strcpy(url_cpy,url);
    url_cpy[strlen(url_cpy)-2] = '\0';

    if (NULL == url || strlen(url_cpy) > MAX_URL_LEN ) {
        data->err_code = E5003;
        resp = eap_noob_err_msg(data,id); return resp;
    }

    data->peerid = os_strdup(data->peerid_rcvd);

    // If the server did not send a realm, use the default realm instead
    if (!data->realm || strlen(data->realm) == 0) {
        data->realm = os_strdup(DEFAULT_REALM);
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Realm %s", data->realm);

    if (SUCCESS == eap_noob_check_compatibility(data)) {
        resp = eap_noob_build_type_2(sm,data, id);
    } else resp = eap_noob_err_msg(data,id);

    data->rcvd_params = 0;
    return resp;
}

/**
 * eap_noob_process_type_1
 * @eap_sm : eap statemachine context
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_process_type_1(struct eap_sm * sm, struct eap_noob_data * data, u8 id)
{
    struct wpabuf *resp = NULL;

    // Common handshake from server does not contain any information,
    // thus the request object does not need to be parsed.

    resp = eap_noob_build_type_1(data, id);

    return resp;
}

/**
 * eap_noob_process_msg_error :  handle received error message
 * @eap_sm : eap statemachine context
 * @data : peer data
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static void eap_noob_process_msg_error(struct eap_sm *sm, struct eap_noob_data * data, u8 id)
{
    if (!data->err_code) {
        eap_noob_db_update(data, UPDATE_STATE_ERROR);
    }
}

/**
 * eap_noob_process :  Process recieved message
 * @eap_sm : eap statemachine context
 * @priv : peer data
 * @ret : eap method data
 * @reqData : received request message objecti
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_process(struct eap_sm * sm, void * priv, struct eap_method_ret *ret,
                                        const struct wpabuf * reqData)
{
    struct eap_noob_data * data = priv;
    struct wpabuf * resp = NULL;
    const u8 * pos;
    size_t len;
    struct json_token * req_obj = NULL;
    struct json_token * req_type = NULL;
    int msgtype;
    u8 id =0;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_NOOB, reqData, &len);
    if (pos == NULL || len < 1) {
        ret->ignore = true;
        return NULL;
    }
 /**
 * https://tools.ietf.org/html/rfc4137 Not dropping packets if header is valid.
 * Consider using this for Error messages received when not expected.
**/
    ret->ignore = false;

    ret->methodState = METHOD_CONT;
    ret->decision = DECISION_FAIL;

  /**
 * https://tools.ietf.org/html/rfc3748 EAP-NOOB does not use
 * or handle EAP Notificiation type messages.
**/
    ret->allowNotifications = false;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Received Request = %s", pos);
    req_obj = json_parse((char *) pos, os_strlen((char *) pos));
    id = eap_get_id(reqData);

    if (req_obj) {
        req_type = json_get_member(req_obj, TYPE);

        if (req_type) {
            msgtype = req_type->number;
        } else {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown type received");
            data->err_code = E1003;
            resp = eap_noob_err_msg(data,id);
            goto EXIT;
        }
    } else {
        data->err_code = E1003;
        resp = eap_noob_err_msg(data,id);
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown format received");
        goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: state = %d, message type = %d",data->peer_state, msgtype);
    if (VALID != state_message_check[data->peer_state][msgtype]) {
        data->err_code = E2002;
        resp = eap_noob_err_msg(data, id);
        wpa_printf(MSG_DEBUG, "EAP-NOOB: State mismatch"); goto EXIT;
    } else if ((data->peer_state == WAITING_FOR_OOB_STATE || data->peer_state == OOB_RECEIVED_STATE) &&
                msgtype == EAP_NOOB_TYPE_2) {
        if (FAILURE == eap_noob_db_update(data, DELETE_SSID)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to delete SSID"); goto EXIT;
        }
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Deleted SSID");
    }

    // Decode the JSON object and store it locally
    // This way, all methods will be able to access it.
    eap_noob_decode_obj(data, req_obj);
    if (data->err_code != NO_ERROR) {
        resp = eap_noob_err_msg(data,id);
        goto EXIT;
    }

    switch(msgtype) {
        case NONE:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Error message received");
            eap_noob_process_msg_error(sm, data, id);
            break;
        case EAP_NOOB_TYPE_1:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING PROCESS TYPE 1");
            resp = eap_noob_process_type_1(sm, data, id);
            break;
        case EAP_NOOB_TYPE_2:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING PROCESS TYPE 2");
            resp = eap_noob_process_type_2(sm, data, id);
            break;
        case EAP_NOOB_TYPE_3:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING PROCESS TYPE 3");
            resp = eap_noob_process_type_3(sm, data, id);
            break;
        case EAP_NOOB_TYPE_4:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING PROCESS TYPE 4");
            resp = eap_noob_process_type_4(sm, data, id);
            break;
        case EAP_NOOB_TYPE_5:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING PROCESS TYPE 5");
            resp = eap_noob_process_type_5(sm, data, id);
            break;
        case EAP_NOOB_TYPE_6:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING PROCESS TYPE 6");
            resp = eap_noob_process_type_6(sm, data, id);
            if(data->err_code == NO_ERROR) {
                ret->methodState = METHOD_MAY_CONT;
                ret->decision = DECISION_COND_SUCC;
            }
            break;
        case EAP_NOOB_TYPE_7:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING PROCESS TYPE 7");
            resp = eap_noob_process_type_7(sm, data, id);
            break;
        case EAP_NOOB_TYPE_8:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING PROCESS TYPE 8");
            resp = eap_noob_process_type_8(sm, data, id);
            break;
        case EAP_NOOB_TYPE_9:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING PROCESS TYPE 9");
            resp = eap_noob_process_type_9(sm, data, id);
            if(data->err_code == NO_ERROR) {
                ret->methodState = METHOD_MAY_CONT;
                ret->decision = DECISION_COND_SUCC;
            }
            break;
        default:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Unknown EAP-NOOB request received");
            break;
    }
EXIT:
    data->err_code = NO_ERROR;
    /*
    if (req_type)
        json_free(req_type);
    else if (req_obj)
        json_free(req_obj);
     */
    return resp;
}

/**
 * eap_noob_free_ctx : free all the allocations from peer data
 * @data : peer data
 *
**/
static void eap_noob_free_ctx(struct eap_noob_data * data)
{
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    wpa_printf(MSG_DEBUG, "EAP_NOOB: Clearing server data");
    EAP_NOOB_FREE(data->server_info);
    EAP_NOOB_FREE(data->mac);
    EAP_NOOB_FREE(data->ssid);
    EAP_NOOB_FREE(data->peerid);
    EAP_NOOB_FREE(data->realm);
    EAP_NOOB_FREE(data->mac_input_str);

    if (data->ecdh_exchange_data) {
        EVP_PKEY_free(data->ecdh_exchange_data->dh_key);
        EAP_NOOB_FREE(data->ecdh_exchange_data->x_b64_remote);
        EAP_NOOB_FREE(data->ecdh_exchange_data->y_b64_remote);
        EAP_NOOB_FREE(data->ecdh_exchange_data->x_b64);
        EAP_NOOB_FREE(data->ecdh_exchange_data->y_b64);
        EAP_NOOB_FREE(data->ecdh_exchange_data->jwk_serv);
        EAP_NOOB_FREE(data->ecdh_exchange_data->jwk_peer);
        EAP_NOOB_FREE(data->ecdh_exchange_data->shared_key);
        EAP_NOOB_FREE(data->ecdh_exchange_data->shared_key_b64);
        os_free(data->ecdh_exchange_data);
    }
    if (data->oob_data) {
        EAP_NOOB_FREE(data->oob_data->Noob_b64);
        EAP_NOOB_FREE(data->oob_data->Hoob_b64);
        EAP_NOOB_FREE(data->oob_data->NoobId_b64);
        os_free(data->oob_data);
    }
    if (data->kdf_nonce_data) {
        EAP_NOOB_FREE(data->kdf_nonce_data->Ns);
        EAP_NOOB_FREE(data->kdf_nonce_data->Np);
        os_free(data->kdf_nonce_data);
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
    }

    EAP_NOOB_FREE(data->peer_info);
    if (data->peer_config_params) {
        EAP_NOOB_FREE(data->peer_config_params->Peer_name);
        EAP_NOOB_FREE(data->peer_config_params->Peer_ID_Num);
        os_free(data->peer_config_params);
    }

    /* Close DB */
    /* TODO check again */
    if (data->db)
    if (SQLITE_OK != sqlite3_close_v2(data->db)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB:Error closing DB");
        const char * sql_error = sqlite3_errmsg(data->db);
        if (sql_error != NULL)
            wpa_printf(MSG_DEBUG,"EAP-NOOB: SQL error : %s", sql_error);
    }
    os_free(data); data = NULL;
    wpa_printf(MSG_DEBUG, "EAP_NOOB: Exit %s", __func__);
}

static int eap_noob_oob_step(struct eap_sm * sm, struct eap_noob_data * data) {
    char * input = NULL;
    const u8 * addr[1];
    size_t len[1];
    u8 hash[32];
    char * hoob_b64;
    int error = 0;
    int retval = SUCCESS;

    // Check whether new OOB data has arrived, and if so, verify the Hoob
    if (FAILURE == eap_noob_exec_query(data, QUERY_EPHEMERALNOOB, columns_ephemeralnoob, 2, TEXT, data->peerid)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error while retrieving OOB data from the database");
        retval = FAILURE;
        goto EXIT;
    }

    // There must be OOB data available before continuing
    if (data->oob_data->Hoob_b64 &&
        data->oob_data->Noob_b64) {
        // If there is OOB data available, first read the config file again
        // to extact the information needed for calculating the local Hoob
        if (FAILURE == eap_noob_read_config(sm, data)) {
            wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to read config file");
            retval = FAILURE;
            goto EXIT;
        }


        // Build the Hoob input for the local calculation
        input = eap_noob_build_mac_input(data, data->dirp, data->peer_state);
        if (!input) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to build Hoob input");
            retval = FAILURE;
            goto EXIT;
        }

        addr[0] = (u8 *) input;
        len[0] = os_strlen(input);

        // Perform the SHA-256 hash operation on the Hoob input
        error = sha256_vector(1, addr, len, hash);
        if (error) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Error while creating SHA-256 hash");
            retval = FAILURE;
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
            // the peer moves on to the next state.
            data->peer_state = OOB_RECEIVED_STATE;
        } else {
            wpa_printf(MSG_INFO, "EAP-NOOB: Received Hoob does not match local Hoob");

            // Increase number of invalid Hoobs received
            data->oob_retries++;
            wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB retries = %d", data->oob_retries);
            eap_noob_db_update(data, UPDATE_OOB_RETRIES);

            // Reset the peer to Unregistered state if the maximum
            // number of OOB retries (i.e. invalid Hoobs) has been reached.
            if (data->oob_retries >= data->max_oob_retries) {
                data->peer_state = UNREGISTERED_STATE;
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Max OOB retries exceeded. Reset peer to Unregistered state");
                // Remove the current Ephemeral entries
                eap_noob_db_update(data, DELETE_SSID);
            }
        }
    }

EXIT:
    return retval;
}

/**
 * eap_noob_peer_ctxt_init : initialises peer data
 * @sm : eap statemachine data
 * @data : peer data
 * Returns: SUCCESS/FAILURE
**/
static int eap_noob_peer_ctxt_init(struct eap_sm * sm, struct eap_noob_data * data)
{
    int retval = FAILURE;

    if (FAILURE == (retval = eap_noob_ctxt_alloc(data))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in allocating peer data");
        goto EXIT;
    }

    data->peer_state = UNREGISTERED_STATE;
    data->rcvd_params = 0;
    data->err_code = 0;

    if (FAILURE == (retval = eap_noob_create_db(sm , data)))
        goto EXIT;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: State = %d", data->peer_state);

    if (data->peer_state == WAITING_FOR_OOB_STATE &&
        data->dirp == SERVER_TO_PEER &&
        FAILURE == eap_noob_oob_step(sm, data)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB data is not available");
    }
EXIT:
    if (FAILURE == retval)
        eap_noob_free_ctx(data);
    return retval;
}

/**
 * eap_noob_init : initialise the eap noob method
 *  @sm : eap statemachine context
 * Returns : eap noob data
**/
static void * eap_noob_init(struct eap_sm * sm)
{
    struct eap_noob_data * data = NULL;
    wpa_printf(MSG_DEBUG, "Entering %s", __func__);
    if (NULL == (data = os_zalloc(sizeof(struct eap_noob_data))) )
        return NULL;

    if (FAILURE == eap_noob_peer_ctxt_init(sm,data)) return NULL;
    return data;
}

/**
 * eap_noob_deinit : de initialises the eap method context
 * @sm : eap statemachine context
 * @priv : method context
**/
static void eap_noob_deinit(struct eap_sm * sm, void * priv)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB DEINIT");
    struct eap_noob_data * data = priv;

    eap_noob_free_ctx(data);
}

/**
 * eap_noob_isKeyAvailable : Checks if the shared key is presesnt
 * @sm : eap statemachine context
 * @priv : eap noob data
 * Returns : TRUE/FALSE
*/
static bool eap_noob_isKeyAvailable(struct eap_sm *sm, void *priv)
{
    struct eap_noob_data * data = priv;
    bool retval = ((data->peer_state == REGISTERED_STATE) && (data->kdf_out->msk != NULL));
    wpa_printf(MSG_DEBUG, "EAP-NOOB: State = %d, Key Available? %d", data->peer_state, retval);
    return retval;
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
    struct eap_noob_data * data = priv;
    u8 * key;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: GET  KEY");
    if ((data->peer_state != REGISTERED_STATE) || (!data->kdf_out->msk))
        return NULL;

    if (NULL == (key = os_malloc(MSK_LEN))) return NULL;

    *len = MSK_LEN; os_memcpy(key, data->kdf_out->msk, MSK_LEN);
    wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: MSK Derived",key,MSK_LEN);
    return key;
}

/**
 * eap_noob_get_emsk : gets the msk if available
 * @sm : eap statemachine context
 * @priv : eap noob data
 * @len : msk len
 * Returns EMSK or NULL
**/
static u8 * eap_noob_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
    struct eap_noob_data *data = priv;
    u8 *key;
    wpa_printf(MSG_DEBUG,"EAP-NOOB:Get EMSK Called");
    if ((data->peer_state != REGISTERED_STATE) || (!data->kdf_out->emsk))
        return NULL;

    if (NULL == (key = os_malloc(MSK_LEN)))
        return NULL;

    *len = EAP_EMSK_LEN;
    os_memcpy(key, data->kdf_out->emsk, EAP_EMSK_LEN);
    wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: EMSK",key,EAP_EMSK_LEN);
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
    struct eap_noob_data *data = priv;
    u8 *session_id=NULL;
    wpa_printf(MSG_DEBUG,"EAP-NOOB:Get Session ID Called");
    if ((data->peer_state != REGISTERED_STATE) || (!data->kdf_out->MethodId))
        return NULL;

    *len = 1 + METHOD_ID_LEN;
    session_id = os_malloc(*len);
    if (session_id == NULL)
    return NULL;

    session_id[0] = EAP_TYPE_NOOB;

    os_memcpy(session_id + 1, data->kdf_out->MethodId, METHOD_ID_LEN);
    *len = 1 + METHOD_ID_LEN;

    return session_id;
}



/**
 * eap_noob_deinit_for_reauth : release data not needed for fast reauth
 * @sm : eap statemachine context
 * @priv : eap noob data
 */
static void eap_noob_deinit_for_reauth(struct eap_sm *sm, void *priv)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
}

/**
 * eap_noob_init_for_reauth : initialise the reauth context
 * @sm : eap statemachine context
 * @priv : eap noob data
 */
static void * eap_noob_init_for_reauth(struct eap_sm * sm, void * priv)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
    struct eap_noob_data * data=priv;
    data->peer_state = RECONNECTING_STATE;
    return data;
}

/**
 * eap_noob_has_reauth_data : Changes the state to RECONNECT. Called by state machine to check if method has enough data to do fast reauth
 * if the current state is REGISTERED_STATE
 * @sm : eap statemachine context
 * @priv : eap noob data
 */
static bool eap_noob_has_reauth_data(struct eap_sm * sm, void * priv)
{
    struct eap_noob_data * data = priv;
    struct wpa_supplicant * wpa_s = (struct wpa_supplicant *) sm->msg_ctx;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s, Current SSID = %s, Stored SSID = %s", __func__,
               wpa_s->current_ssid->ssid, data->ssid);
    if ((data->peer_state == REGISTERED_STATE ||  data->peer_state == RECONNECTING_STATE) &&
        (0 == strcmp((char *)wpa_s->current_ssid->ssid, data->ssid))) {
        data->peer_state = RECONNECTING_STATE;
        data->peer_state = RECONNECTING_STATE;
        if(!data->realm || os_strlen(data->realm)==0)
            data->realm = os_strdup(DEFAULT_REALM);
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Peer ID and Realm Reauth, %s %s", data->peerid, data->realm);
        eap_noob_config_change(sm, data); eap_noob_db_update(data, UPDATE_PERSISTENT_STATE);
        return true;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Returning False, %s", __func__);
    return false;
}

/**
 * eap_peer_noob_register : register eap noob method
**/
int eap_peer_noob_register(void)
{
    struct eap_method * eap = NULL;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: NOOB REGISTER");
    eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION, EAP_VENDOR_IETF, EAP_TYPE_NOOB, "NOOB");

    if (eap == NULL) return -1;

    eap->init = eap_noob_init;
    eap->deinit = eap_noob_deinit;
    eap->process = eap_noob_process;
    eap->isKeyAvailable = eap_noob_isKeyAvailable;
    eap->getKey = eap_noob_getKey;
    eap->get_emsk = eap_noob_get_emsk;
    eap->getSessionId = eap_noob_get_session_id;
    eap->has_reauth_data = eap_noob_has_reauth_data;
    eap->init_for_reauth = eap_noob_init_for_reauth;
    eap->deinit_for_reauth = eap_noob_deinit_for_reauth;

    return eap_peer_method_register(eap);
}
