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

#include <gpg-error.h>

#ifdef HAVE_SSL
#include <openssl/ssl.h>
#endif

#include "common.h"
#include "sec.h"
#include "scd.h"

struct sec_internal g_state;

#define SEC_LABEL1 "Signature certificate"
#define SEC_LABEL2 "Encryption certificate"
#define SEC_LABEL3 "Authentication certificate"

/* ---- MEMORY MGMT */

#define SEC_ALLOC_COPY(type, name, value, length) \
	type *name = calloc(1, length); memcpy(name, value, length);
#define SEC_ALLOC_STRCPY(type, name, value) \
	SEC_ALLOC_COPY(type, name, value, strlen(value)+1)
#define SEC_ALLOC_ASSIGN(type, name, value) \
	type *name = calloc(1, sizeof(type)); *name = value;



static void sec_free_alist(struct sec_ck_alist *al)
{
	if (al == NULL) {
		return;
	}
	if (al->p != NULL) {
		for (CK_ULONG i = 0; i < al->cnt; i++) {
			if (al->p[i].pValue != NULL) {
				free(al->p[i].pValue);
			}
		}
	}
	sec_free(al->p);
}

void sec_free_token()
{
	if (g_state.token == NULL)
		return;
	
	for (int i = 0; i < 3; i++) {
		sec_free_alist(&g_state.token->alCert[i]);
		sec_free_alist(&g_state.token->alPriv[i]);
		sec_free_alist(&g_state.token->alPub[i]);
	}
	
	sec_free(g_state.token);
}


/* ---- BUILD ATTRIBUTE LISTS */


	
static void sec_convert_cert3_to_attribute_list()
{
	if (g_state.token == NULL) {
		return;
	}
	SDEBUG("called certlen[SEC_KEY3]=%zu", g_state.token->certlen[SEC_KEY3]);
	sec_free_alist(&g_state.token->alCert[SEC_KEY3]);
	
	if (g_state.token->certlen[SEC_KEY3] == 0)
		return;
	
	const char *label3 = SEC_LABEL3;
	
	// cert3 atttribute list
	SDEBUG("converting cert3 to CK template");
	SEC_ALLOC_ASSIGN(CK_OBJECT_CLASS, class, CKO_CERTIFICATE)
	SEC_ALLOC_ASSIGN(CK_CERTIFICATE_TYPE, certType, CKC_X_509)
	SEC_ALLOC_ASSIGN(CK_BBOOL, token, CK_TRUE)
	SEC_ALLOC_STRCPY(CK_UTF8CHAR, label, label3)
	SEC_ALLOC_COPY(CK_BYTE, certificate, g_state.token->cert[SEC_KEY3], g_state.token->certlen[SEC_KEY3])
	SEC_ALLOC_ASSIGN(CK_BYTE, id, 3)
	
	CK_BYTE *subject = NULL; CK_ULONG subject_len = -1;
	CK_BYTE *issuer = NULL; CK_ULONG issuer_len = -1;
	CK_BYTE *serial = NULL; CK_ULONG serial_len = -1;

#ifdef HAVE_SSL
	unsigned char *p = g_state.token->cert[SEC_KEY3];
	X509 *x = d2i_X509(NULL, (const unsigned char **)&p, g_state.token->certlen[SEC_KEY3]);
	if (x != NULL) {
		CK_ULONG n;
		n = i2d_X509_NAME(x->cert_info->subject, NULL);
		if (n > 0) {
			subject = p = malloc(n);
			subject_len = i2d_X509_NAME(x->cert_info->subject, &p);
		}
		n = i2d_X509_NAME(x->cert_info->issuer, NULL);
		if (n > 0) {
			issuer = p = malloc(n);
			issuer_len = i2d_X509_NAME(x->cert_info->issuer, &p);
		}
		n = i2d_ASN1_INTEGER(x->cert_info->serialNumber, NULL);
		if (n > 0) {
			serial = p = malloc(n);
			serial_len = i2d_ASN1_INTEGER(x->cert_info->serialNumber, &p);
		}
		X509_free(x);
	}
#endif /* HAVE_SSL */
	// CKA_ISSUER            000000011559de00 / 89
	// 00000000  30 57 31 0B 30 09 06 03 55 04 06 13 02 41 55 31  0W1.0...U....AU1
	// 00000010  13 30 11 06 03 55 04 08 13 0A 53 6F 6D 65 2D 53  .0...U....Some-S
	// 00000020  74 61 74 65 31 21 30 1F 06 03 55 04 0A 13 18 49  tate1!0...U....I
	// 00000030  6E 74 65 72 6E 65 74 20 57 69 64 67 69 74 73 20  nternet Widgits 
	// 00000040  50 74 79 20 4C 74 64 31 10 30 0E 06 03 55 04 03  Pty Ltd1.0...U..
	// 00000050  13 07 4D 49 43 52 4F 43 41                       ..MICROCA       
	// DN: C=AU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=MICROCA
	// CKA_SUBJECT           000000011559de88 / 23
	// 00000000  30 15 31 13 30 11 06 03 55 04 03 0C 0A 48 61 6E  0.1.0...U....Han
	// 00000010  73 20 57 75 72 73 74                             s Wurst         
	// DN: CN=Hans Wurst

	
	CK_ATTRIBUTE template[] = {
		{CKA_CLASS, class, sizeof(*class)},
		{CKA_CERTIFICATE_TYPE, certType, sizeof(*certType)},
		{CKA_TOKEN, token, sizeof(*token)},
		{CKA_LABEL, label, strlen((char*)label)+1},
		{CKA_ID, id, sizeof(*id)},
		{CKA_VALUE, certificate, g_state.token->certlen[SEC_KEY3]},
#ifdef HAVE_SSL
		{CKA_SUBJECT, subject, subject_len},
		{CKA_ISSUER, issuer, issuer_len},
		{CKA_SERIAL_NUMBER, serial, serial_len},
#endif
	};
	
	g_state.token->alCert[SEC_KEY3].p = malloc(sizeof(template));
	memcpy(g_state.token->alCert[SEC_KEY3].p, template, sizeof(template));
	g_state.token->alCert[SEC_KEY3].cnt = sizeof(template)/sizeof(CK_ATTRIBUTE);
	
	
	
}

static void sec_convert_pubkey3_to_al()
{
	if (g_state.token == NULL) {
		return;
	}
	SDEBUG("called pubkeylen[SEC_KEY3]=%zu", g_state.token->pubkeylen[SEC_KEY3]);
	sec_free_alist(&g_state.token->alPub[SEC_KEY3]);
	
	if (g_state.token->pubkeylen[SEC_KEY3] == 0)
		return;

	const char *label3 = SEC_LABEL3;
	gpg_error_t err;
	
	uchar *n = NULL, *e = NULL;
	size_t nlen, elen;
	err = scd_unpack_pubkey(&n, &nlen, &e, &elen, g_state.token->pubkey[SEC_KEY3], g_state.token->pubkeylen[SEC_KEY3]);
	if (err) { SDEBUG("error %d: %s\n", err, gpg_strerror(err)); return; }

	// public key attribute list
	SEC_ALLOC_ASSIGN(CK_OBJECT_CLASS, class, CKO_PUBLIC_KEY)
	SEC_ALLOC_ASSIGN(CK_BYTE, id, 3)
	SEC_ALLOC_STRCPY(CK_UTF8CHAR, label, label3)
	SEC_ALLOC_ASSIGN(CK_BBOOL, encrypt, 0)
	SEC_ALLOC_ASSIGN(CK_BBOOL, verify, 1)
	SEC_ALLOC_ASSIGN(CK_BBOOL, verify_recover, 0)
	SEC_ALLOC_ASSIGN(CK_BBOOL, wrap, 0)
	SEC_ALLOC_ASSIGN(CK_BBOOL, trusted, 1)
	SEC_ALLOC_ASSIGN(CK_KEY_TYPE, key_type, CKK_RSA)
	SEC_ALLOC_ASSIGN(CK_ULONG, modulus_bits, nlen * 8)

	// CKA_MODULUS           00007fc23b50a170 / 256
    // 00000000  9E 8A CC 5E 93 6F 31 9A BF 0A A8 9D 61 21 09 D8  ...^.o1.....a!..
    // 00000010  99 C9 2C 6F 08 ED 39 13 19 9B DA FD C1 23 D3 26  ..,o..9......#.&
    // 00000020  F2 01 C4 70 AA 03 A6 78 B5 13 C1 D6 D2 1D 7B B9  ...p...x......{.
    // 00000030  73 86 65 5E E5 DF 12 34 03 F2 99 9B 1F C4 60 54  s.e^...4......`T
    // 00000040  7E 24 A9 D5 B8 49 DB C7 75 22 73 58 ED CB F4 8F  ~$...I..u"sX....
    // 00000050  A7 71 29 F4 4B 00 C0 D3 6F A9 05 94 72 5F C3 3C  .q).K...o...r_.<
    // 00000060  F5 76 41 7E A8 C7 AE 08 6B EC B8 DC A7 11 F2 E8  .vA~....k.......
    // 00000070  61 64 C6 9D 3D AF D0 F2 92 1B 3B 13 E2 17 E0 4A  ad..=.....;....J
    // 00000080  60 CF 72 85 78 03 5B 86 C8 4B BF 32 E0 BA 4C 62  `.r.x.[..K.2..Lb
    // 00000090  0F FD 7B BD 77 24 84 67 B1 12 AE 93 54 89 CC 0F  ..{.w$.g....T...
    // 000000A0  83 1C 58 BD 24 6F E5 41 01 2B A7 D9 58 22 B3 65  ..X.$o.A.+..X".e
    // 000000B0  2C 66 A9 F2 95 3D DF 8D 04 99 8F 06 B3 0D CC BA  ,f...=..........
    // 000000C0  2A 2E DC 33 C3 73 E7 D6 95 8B B5 AA 9D 1B E3 EC  *..3.s..........
    // 000000D0  93 19 73 C6 A3 85 52 FF A3 58 75 21 4F 41 DC 92  ..s...R..Xu!OA..
    // 000000E0  17 74 A0 F5 C1 1C D4 B2 10 F4 ED 68 33 D5 52 07  .t.........h3.R.
    // 000000F0  A7 8F 64 49 3C 24 B0 A1 EF FC 8D 32 38 EA D8 79  ..dI<$.....28..y
    // CKA_PUBLIC_EXPONENT   00007fc23b509a20 / 3
    // 00000000  01 00 01                                         ...             

	CK_ATTRIBUTE template[] = {
		{CKA_CLASS, class, sizeof(*class)},
		{CKA_ID, id, sizeof(*id)},
		{CKA_ENCRYPT, encrypt, sizeof(*encrypt)},
		{CKA_VERIFY, verify, sizeof(*verify)},
		{CKA_VERIFY_RECOVER, verify_recover, sizeof(*verify_recover)},
		{CKA_WRAP, wrap, sizeof(*wrap)},
		{CKA_TRUSTED, trusted, sizeof(*trusted)},
		{CKA_KEY_TYPE, key_type, sizeof(*key_type)},
		{CKA_LABEL, label, strlen((char*)label)+1},
		{CKA_MODULUS, n, nlen},
		{CKA_MODULUS_BITS, modulus_bits, sizeof(*modulus_bits)},
		{CKA_PUBLIC_EXPONENT, e, elen}

	};

	g_state.token->alPub[SEC_KEY3].p = malloc(sizeof(template));
	memcpy(g_state.token->alPub[SEC_KEY3].p, template, sizeof(template));
	g_state.token->alPub[SEC_KEY3].cnt = sizeof(template)/sizeof(CK_ATTRIBUTE);



}

static void sec_create_privkey3_al()
{
	if (g_state.token == NULL) {
		return;
	}
	sec_free_alist(&g_state.token->alPriv[SEC_KEY3]);
	
	if (g_state.token->pubkeylen[SEC_KEY3] == 0) // only create fake privkey al if pubkey is available
		return;

	const char *label3 = SEC_LABEL3;

	// private key attribute list
	SEC_ALLOC_ASSIGN(CK_OBJECT_CLASS, class, CKO_PRIVATE_KEY)
	SEC_ALLOC_ASSIGN(CK_BYTE, id, 3)
	SEC_ALLOC_ASSIGN(CK_BBOOL, sensitive, CK_TRUE)
	SEC_ALLOC_ASSIGN(CK_BBOOL, decrypt, CK_FALSE)
	SEC_ALLOC_ASSIGN(CK_BBOOL, sign, CK_TRUE)
	SEC_ALLOC_ASSIGN(CK_BBOOL, sign_recover, CK_FALSE)
	SEC_ALLOC_ASSIGN(CK_BBOOL, unwrap, CK_FALSE)
	SEC_ALLOC_ASSIGN(CK_BBOOL, extractable, CK_FALSE)
	SEC_ALLOC_ASSIGN(CK_BBOOL, always_sensitive, CK_TRUE)
	SEC_ALLOC_ASSIGN(CK_BBOOL, never_extractable, CK_TRUE)
	SEC_ALLOC_ASSIGN(CK_BBOOL, derive, CK_FALSE)
	SEC_ALLOC_ASSIGN(CK_BBOOL, always_authenticate, CK_FALSE)
	SEC_ALLOC_ASSIGN(CK_KEY_TYPE, key_type, CKK_RSA)
	SEC_ALLOC_STRCPY(CK_UTF8CHAR, label, label3)
	SEC_ALLOC_ASSIGN(CK_BBOOL, token, CK_TRUE)
	SEC_ALLOC_ASSIGN(CK_BBOOL, private, CK_TRUE)

	uchar *modulus = NULL;
	CK_ULONG modulus_len = -1;
	CK_ATTRIBUTE_PTR paModulus = sec_al_get_attr(CKA_MODULUS, g_state.token->alPub[SEC_KEY3]);
	if (paModulus == NULL) {
		// this is bad!
	} else {
		modulus_len = paModulus->ulValueLen;
		modulus = malloc(modulus_len);
		memset(modulus, 1, modulus_len); // fake data. needed just for key length in NSS/firefox
	}
	
	CK_ATTRIBUTE template[] = {
		{CKA_CLASS, class, sizeof(*class)},
		{CKA_ID, id, sizeof(*id)},
		{CKA_SENSITIVE, sensitive, sizeof(*sensitive)},
		{CKA_DECRYPT, decrypt, sizeof(*decrypt)},
		{CKA_SIGN, sign, sizeof(*sign)},
		{CKA_SIGN_RECOVER, sign_recover, sizeof(*sign_recover)},
		{CKA_UNWRAP, unwrap, sizeof(*unwrap)},
		{CKA_EXTRACTABLE, extractable, sizeof(*extractable)},
		{CKA_ALWAYS_SENSITIVE, always_sensitive, sizeof(*always_sensitive)},
		{CKA_NEVER_EXTRACTABLE, never_extractable, sizeof(*never_extractable)},
		{CKA_DERIVE, derive, sizeof(*derive)},
		{CKA_KEY_TYPE, key_type, sizeof(*key_type)},
		{CKA_LABEL, label, strlen((char*)label)+1},
		{CKA_ALWAYS_AUTHENTICATE, always_authenticate, sizeof(*always_authenticate)},
		{CKA_TOKEN, token, sizeof(*token)},
		{CKA_PRIVATE, private, sizeof(*private)},
		{CKA_MODULUS, modulus, modulus_len},
	};
	g_state.token->alPriv[SEC_KEY3].p = malloc(sizeof(template));
	memcpy(g_state.token->alPriv[SEC_KEY3].p, template, sizeof(template));
	g_state.token->alPriv[SEC_KEY3].cnt = sizeof(template)/sizeof(CK_ATTRIBUTE);


}

/* ---- SCD INTERACTION */

static gpg_error_t learn_status_cb(void *arg, const char *data)
{
	
	// SDEBUG("RAW: %s", data);
	if (strncmp(data, "SERIALNO ", strlen("SERIALNO ")) == 0 && strlen(data) < sizeof(g_state.token->serialno)-1+strlen("SERIALNO ")) {
		sscanf(data, "SERIALNO %s", g_state.token->serialno);
		SDEBUG("found serialno %s", g_state.token->serialno);
		return 0;
	}
	if (strncmp(data, "KEY-FPR 1 ", strlen("KEY-FPR x ")) == 0 && strlen(data) < sizeof(g_state.token->serialno)-1+strlen("KEY-FPR x ")) {
		sscanf(data, "KEY-FPR 1 %s", g_state.token->key_fpr[0]);
		SDEBUG("found key fpr 1 %s", g_state.token->key_fpr[0]);
		return 0;
	}
	if (strncmp(data, "KEY-FPR 2 ", strlen("KEY-FPR x ")) == 0 && strlen(data) < sizeof(g_state.token->serialno)-1+strlen("KEY-FPR x ")) {
		sscanf(data, "KEY-FPR 2 %s", g_state.token->key_fpr[1]);
		SDEBUG("found key fpr 2 %s", g_state.token->key_fpr[1]);
		return 0;
	}
	if (strncmp(data, "KEY-FPR 3 ", strlen("KEY-FPR x ")) == 0 && strlen(data) < sizeof(g_state.token->serialno)-1+strlen("KEY-FPR x ")) {
		sscanf(data, "KEY-FPR 3 %s", g_state.token->key_fpr[2]);
		SDEBUG("found key fpr 3 %s", g_state.token->key_fpr[2]);
		return 0;
	}
	
	return 0;
}

static gpg_error_t cert3_data_cb(void *arg, const void *data, size_t datalen) {
	if (g_state.token == NULL) {
		SDEBUG("cannot store data");
		return 1;
	}
	size_t len = SEC_CERT_MAXLEN - g_state.token->certlen[SEC_KEY3];
	SDEBUG("cert3_data_cb len=%zu", datalen);
	gpg_error_t err = scd_unescape_data(g_state.token->cert[SEC_KEY3] + g_state.token->certlen[SEC_KEY3], &len, (unsigned char*)data, datalen);
	g_state.token->certlen[SEC_KEY3] += len;
	if (err) {SDEBUG("error %d", err);}
	return err;
}

static gpg_error_t readkey3_data_cb(void *arg, const void *data, size_t datalen)
{
	if (g_state.token == NULL) {
		SDEBUG("cannot store data");
		return 1;
	}

	size_t len = SEC_KEY_MAXLEN - g_state.token->pubkeylen[SEC_KEY3];
	gpg_error_t err = scd_unescape_data(g_state.token->pubkey[SEC_KEY3] + g_state.token->pubkeylen[SEC_KEY3], &len, (uchar*)data, datalen);
	g_state.token->pubkeylen[SEC_KEY3] += len;

	SDEBUG("chunklen=%zu\n", len);
	return err;
}

gpg_error_t sec_learn_token(assuan_context_t ctx)
{
	gpg_error_t err;
	if (g_state.token != NULL)
		return 0;

	err = scd_serialno_openpgp(g_state.ctx);
	if (err) goto sec_learn_token_err;

	g_state.token = calloc(1, sizeof(struct sec_token_info));
	
	err = assuan_transact(ctx, "SCD LEARN --force", NULL, NULL, NULL, NULL, learn_status_cb, NULL);
	if (err) goto sec_learn_token_err;

	err = assuan_transact(ctx, "SCD READCERT OPENPGP.3", cert3_data_cb, NULL, NULL, NULL, NULL, NULL);
	if (err == GPG_ERR_BUFFER_TOO_SHORT) goto sec_learn_token_err;
	if (!err) sec_convert_cert3_to_attribute_list();

	err = assuan_transact(ctx, "SCD READKEY OPENPGP.3", readkey3_data_cb, NULL, NULL, NULL, NULL, NULL);
	if (err == GPG_ERR_BUFFER_TOO_SHORT) goto sec_learn_token_err;
	if (!err) {
		sec_convert_pubkey3_to_al();
		sec_create_privkey3_al();
	}

	return err;

sec_learn_token_err:
	SDEBUG("ERROR %x: %s", err, gpg_strerror(err));
	sec_free_token();
	return err;
}


/* ---- helper functions for CK data structures */

int sec_al_match(struct sec_ck_alist template, struct sec_ck_alist al)
{
	int found;
	for (CK_ULONG i = 0; i < template.cnt; i++) {
		CK_ATTRIBUTE_PTR pT = &template.p[i];
		found = 0;
		for (CK_ULONG j = 0; j < al.cnt; j++) {
			CK_ATTRIBUTE_PTR pA = &al.p[j];
			SDEBUG("i=%lu j=%lu t-type=%lx a-type=%lx", i, j, pT->type, pA->type);
			if (pT->type == pA->type) {
				// SDEBUG("type match")
				if (pT->pValue == NULL_PTR || pA->pValue == NULL_PTR) {
					if (pT->pValue == pA->pValue) { // ok. both null pointers
						found = 1;
						SDEBUG("both null ptr. ok?");
						break;
					}
					SDEBUG("null ptr? -> no match");
					return 0;
				}
				if (pT->type == CKA_TOKEN || pT->type == CKA_ID) { // compare by 1-byte value
					if (*(CK_BBOOL*)pT->pValue == *(CK_BBOOL*)pA->pValue) { // comparison works only on little-endian.
						found = 1;
						SDEBUG("found match");
						break;
					}
				} else { // compare memory
					if (pT->ulValueLen != pA->ulValueLen) {
						SDEBUG("value length mismatch");
						return 0;
					}
					if (memcmp(pT->pValue, pA->pValue, pT->ulValueLen) == 0) {
						found = 1;
						SDEBUG("found match");
						break;
					}
				}
				SDEBUG("no match");
				return 0;
			}
		}
		if (found == 0) {
			SDEBUG("attr not found");
			return 0;
		}
	}
	return 1;
}

CK_ATTRIBUTE_PTR sec_al_get_attr(CK_ATTRIBUTE_TYPE type, struct sec_ck_alist al)
{
	if (al.p == NULL)
		return NULL;
	for (CK_ULONG i = 0; i < al.cnt; i++) {
		if (al.p[i].type == type) {
			return &al.p[i];
		}
	}
	return NULL;
}
