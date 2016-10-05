/*
 * Copyright (C) 2015 SektionEins GmbH / Ben Fuhrmannek
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// for asprintf on linux
#define _GNU_SOURCE

#include "common.h"
#include "scd.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gcrypt.h>
#include <locale.h>

// for asprintf with not too old libgpg-error
#ifdef GPGRT_VERSION
#define asprintf gpgrt_asprintf
#endif


struct sec_signature {
	uchar *pSignature;
	unsigned long *pulSignatureLen;
};


static gpg_error_t find_gpg_socket(char *buf, size_t len)
{
	char *tmp, *t, *ext = "/.gnupg/S.gpg-agent";
	tmp = getenv("GPG_AGENT_INFO");
	if (tmp) {
		t = strchr(tmp, ':');
		if (t) {
			*t = '\0';
			strncpy(buf, tmp, len-1);
			buf[len-1] = '\0';
			return 0;
		}
	}
	tmp = getenv("HOME");
	if (tmp) {
		if (strlen(tmp) + strlen(ext) + 1 > len)
			return 1;
		t = stpcpy(buf, tmp);
		stpcpy(t, ext);
		return 0;
	}
	return 1;
}

static inline int is_optstr_clean(char *str)
{
	while (*str != 0) {
		if (*str < 32) { return 0; }
		str++;
	}
	return 1;
}

gpg_error_t scd_set_option(assuan_context_t ctx, char *key, char *value)
{
	if (!key || *key == 0) {
		SDEBUG("OPTION key not set");
		return 1;
	}
	if (!value) {
		SDEBUG("OPTION value not set for key '%s'", key);
		return 1;
	}

	if (!is_optstr_clean(value) || !is_optstr_clean(key)) {
		SDEBUG("OPTION key or value contains illegal characters for key '%s'", key);
		return 1;
	}

	char *cmd;
	if (asprintf(&cmd, "OPTION %s=%s", key, value) < 0) {
		SDEBUG("OPITON out of memory for key '%s'", key);
		return 1;
	}

	gpg_error_t err;
	err = assuan_transact(ctx, cmd, NULL, NULL, NULL, NULL, NULL, NULL);

	if (err) {
		sec_log_err("error setting OPTION '%s=%s'", key, value);
	}

	free(cmd);
	return err;
}

gpg_error_t scd_agent_connect(assuan_context_t *ctx)
{
	gpg_error_t err;
	char gpg_agent_socket_name[1024];

	if (ctx == NULL) { return 1; }
	if (*ctx != NULL) { return 0; }

	err = find_gpg_socket(gpg_agent_socket_name, 1024);
	if (err) { return err; }

	err = assuan_new(ctx);
	if (err) { return err; }

	err = assuan_socket_connect(*ctx, gpg_agent_socket_name, ASSUAN_INVALID_PID, 0);
	if (err) {
		assuan_release(*ctx);
		*ctx = NULL;
		return err;
	}

	// set options. ignore errors - see debug log for debugging problems
	char *val = NULL;
	val = getenv("GPG_TTY");
	if (!val) {
		val = getenv("TTY");
	}
	if (!val) {
		val = ttyname(0);
	}
	scd_set_option(*ctx, "ttyname", val);

	scd_set_option(*ctx, "display", getenv("DISPLAY"));
	scd_set_option(*ctx, "ttytype", getenv("TERM"));
	scd_set_option(*ctx, "lc-ctype", setlocale(LC_CTYPE, NULL));
	scd_set_option(*ctx, "lc-messages", setlocale(LC_MESSAGES, NULL));
	scd_set_option(*ctx, "xauthority", getenv("XAUTHORITY"));
	scd_set_option(*ctx, "pinentry-user-data", getenv("PINENTRY_USER_DATA"));
	scd_set_option(*ctx, "use-cache-for-signing", getenv("GPG_USE_CACHE_FOR_SIGNING"));
	scd_set_option(*ctx, "allow-pinentry-notify", getenv("GPG_ALLOW_PINENTRY_NOTIFY"));
	scd_set_option(*ctx, "pinentry-mode", getenv("PINENTRY_MODE"));
	scd_set_option(*ctx, "cache-ttl-opt-preset", getenv("GPG_CACHE_TTL_OPT_PRESET"));
	scd_set_option(*ctx, "s2k-count", getenv("GPG_S2K_COUNT"));

	return 0;
}

gpg_error_t scd_serialno_openpgp(assuan_context_t ctx)
{
	gpg_error_t err;
	err = assuan_transact(ctx, "SCD SERIALNO openpgp", NULL, NULL, NULL, NULL, NULL, NULL);
	SDEBUG("[%u] token %spresent", err, err? "not ":"");
	return err;
}

int scd_token_present(assuan_context_t ctx)
{
	return !scd_serialno_openpgp(ctx);
}


#define ISHEX(p) ((*(p) >= '0' && *(p) <= '9') \
	|| (*(p) >= 'a' && *(p) <= 'f') \
	|| (*(p) >= 'F' && *(p) <= 'F'))
#define HEXC2I(p) (*(p) <= '9' ? *(p) - '0' :\
	*(p) <= 'F' ? *(p) - 'A' + 10 :\
	*(p) - 'a' + 10)
#define HEXC2I2(p) (16 * HEXC2I(p) + HEXC2I((p)+1))

gpg_error_t scd_unescape_data(uchar *out, size_t *poutlen, uchar *data, size_t datalen)
{
	gpg_error_t rv = 0;
	uchar *pin = data, *pout = out;
	int countmode = 0; // if buffer is too short, return required buffer size in *poutlen
	SDEBUG("maxlen=%zu datalen=%zu", *poutlen, datalen);

	while (pin < data + datalen) {
		if (!countmode && pout >= out + *poutlen) {
			rv = GPG_ERR_BUFFER_TOO_SHORT;
			countmode = 1;
			// break;
		}

		if (*pin == '%' && pout + 2 < data + datalen && ISHEX(pout + 1) && ISHEX(pout + 2)) {
			if (!countmode) {
				*pout = HEXC2I2(pout+1);
				SDEBUG("c=%c", *pout);
			}
			pin += 2;
		} else {
			if (!countmode) *pout = *pin;
		}

		pin++; pout++;
	}
	*poutlen = pout - out;
	return rv;
}


static gpg_error_t sign_data_cb(void *arg, const void *data, size_t datalen)
{
	struct sec_signature *psig = (struct sec_signature*)arg;
	gpg_error_t err = scd_unescape_data(psig->pSignature, psig->pulSignatureLen, (unsigned char *)data, datalen);
	return err;
}

gpg_error_t scd_sign_data(assuan_context_t ctx, uchar *pSignature, unsigned long *pulSignatureLen, uchar *pData, unsigned long ulDataLen)
{
	gpg_error_t err = 0;
	if (ulDataLen > SEC_SIGN_MAXLEN)
		return 1;
	char *cmdstart = "SCD SETDATA ";
	int offset = strlen(cmdstart);
	char *tmp = malloc(ulDataLen * 2 + offset + 1);
	strcpy(tmp, cmdstart);
	for (unsigned long i = 0; i < ulDataLen; i ++)
		sprintf(tmp + offset + i*2, "%02X", pData[i]);
	SDEBUG("cmd=%s", tmp);
	err = assuan_transact(ctx, tmp, NULL, NULL, NULL, NULL, NULL, NULL);
	free(tmp);
	if (err) {
		SDEBUG("ERROR: SETDATA failed [%x]: %s", err, gpg_strerror(err));
		return err;
	}
	// if (g_state.sign.pSignature != NULL) {
	// 	sec_free(g_state.sign.pSignature);
	// }
	struct sec_signature sig = {pSignature, pulSignatureLen};
	err = assuan_transact(ctx, "SCD PKAUTH OPENPGP.3", sign_data_cb, &sig, NULL, NULL, NULL, NULL);
	// if (err == GPG_ERR_BUFFER_TOO_SHORT) {}
	if (err) {
		SDEBUG("ERROR: PKAUTH failed [%x]: %s", err, gpg_strerror(err));
		return err;
	}

	return err;
}

static inline gpg_error_t sec_sexp_strcmp(gcry_sexp_t sexp, int n, const char *v) {
	gpg_error_t err = 0;
	char *tmp;

	tmp = gcry_sexp_nth_string(sexp, n);
	if (tmp == NULL) { return 1; }

	if (strcmp(tmp, v) != 0) {
		SDEBUG("got '%s' instead of '%s'", tmp, v);
		err = 1;
	}

	gcry_free(tmp);
	return err;
}

gpg_error_t scd_unpack_pubkey(uchar **pn, size_t *pnlen,
	uchar **pe, size_t *pelen,
	uchar *pubkey, size_t pubkeylen)
{
	// pubkey S-expression: (public-key (rsa      (n ...)  (e ...)))
	//                      |-> sexp    |-> sexp2 |->sexp3 |->sexp3
	gpg_error_t err = 0;
	size_t len;
	char *tmp;

	*pn = NULL;
	*pe = NULL;

	gcry_sexp_t sexp = NULL;
	gcry_sexp_t sexp2 = NULL;
	gcry_sexp_t sexp3 = NULL;
	err = gcry_sexp_new(&sexp, pubkey, pubkeylen, 0);
	if (err) goto pubkey_error;

	// gcry_sexp_dump(sexp);

	err = sec_sexp_strcmp(sexp, 0, "public-key");
	if (err) goto pubkey_error;

	sexp2 = gcry_sexp_nth(sexp, 1);
	if (sexp2 == NULL) goto pubkey_error;

	err = sec_sexp_strcmp(sexp2, 0, "rsa");
	if (err) goto pubkey_error;

	sexp3 = gcry_sexp_nth(sexp2, 1);
	if (sexp3 == NULL) goto pubkey_error;

	err = sec_sexp_strcmp(sexp3, 0, "n");
	if (err) goto pubkey_error;

	tmp = gcry_sexp_nth_buffer(sexp3, 1, &len);
	if (tmp == NULL) goto pubkey_error;
	*pn = malloc(len);
	memcpy(*pn, tmp, len);
	*pnlen = len;

	gcry_free(tmp);

	sexp3 = gcry_sexp_nth(sexp2, 2);
	if (sexp3 == NULL) goto pubkey_error;

	err = sec_sexp_strcmp(sexp3, 0, "e");
	if (err) goto pubkey_error;

	tmp = gcry_sexp_nth_buffer(sexp3, 1, &len);
	if (tmp == NULL) goto pubkey_error;
	*pe = malloc(len);
	memcpy(*pe, tmp, len);
	*pelen = len;

	gcry_free(tmp);
	if (sexp) gcry_sexp_release(sexp);
	if (sexp2) gcry_sexp_release(sexp2);
	if (sexp3) gcry_sexp_release(sexp3);
	return 0;

pubkey_error:
	if (err == 0) err = 1;
	SDEBUG("error %d: %s\n", err, gcry_strerror(err));
	if (sexp) gcry_sexp_release(sexp);
	if (sexp2) gcry_sexp_release(sexp2);
	if (sexp3) gcry_sexp_release(sexp3);
	if (*pn) { free(*pn); *pn = NULL; *pnlen = 0; }
	if (*pe) { free(*pe); *pe = NULL; *pelen = 0; }
	return err;

}
