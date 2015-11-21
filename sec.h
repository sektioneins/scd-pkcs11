
#ifndef _FOO_H_
#define _FOO_H_

/* ---- */

#include <stdio.h>
#include <string.h>
// #include <stdlib.h>

#include <assuan.h>


/* ---- PKCS11 includes */
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) \
	returnType name
#define CK_DECLARE_FUNCTION(returnType, name) \
	returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
	returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
	returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"


/* ---- INTERNAL STATE & STRUCTS*/
#define SEC_MAX_SESSION_COUNT 1 /* do not change this! only one session is supported */
#define SEC_CERT_MAXLEN 16384
#define SEC_KEY_MAXLEN 4096
#define SEC_FIND_MAXRESULTS 10

#define SEC_OH_PRIV1 21
#define SEC_OH_PRIV2 22
#define SEC_OH_PRIV3 23
#define SEC_OH_PUB1 31
#define SEC_OH_PUB2 32
#define SEC_OH_PUB3 33
#define SEC_OH_CERT1 41
#define SEC_OH_CERT2 42
#define SEC_OH_CERT3 43

#define SEC_KEY1 0
#define SEC_KEY2 1
#define SEC_KEY3 2

struct sec_ck_alist {
	CK_ATTRIBUTE_PTR p;
	CK_ULONG cnt;
};

struct sec_token_info {
	unsigned char serialno[64];
	unsigned char key_fpr[3][41];
	// unsigned int max_certlen_3:16;
	unsigned char cert[3][SEC_CERT_MAXLEN];
	size_t certlen[3];
	unsigned char pubkey[3][SEC_KEY_MAXLEN];
	size_t pubkeylen[3];
	struct sec_ck_alist alPriv[3];
	struct sec_ck_alist alPub[3];
	struct sec_ck_alist alCert[3];
};

struct sec_find_object {
	struct sec_ck_alist template;
	CK_OBJECT_HANDLE phResult[SEC_FIND_MAXRESULTS];
	CK_ULONG ulResultCount;
};

struct sec_sign {
	CK_BBOOL inprogress;
};


struct sec_internal {
	assuan_context_t ctx;
	int session_count;
	struct sec_token_info *token;
	struct sec_find_object find;
	struct sec_sign sign;
};

#define g_state sec_g_state
extern struct sec_internal g_state;



/* ---- FUNCTIONS */
#define sec_free(p) { if (p != NULL) { free(p);	p = NULL; } }

gpg_error_t sec_learn_token(assuan_context_t ctx);
void sec_free_token();
int sec_al_match(struct sec_ck_alist template, struct sec_ck_alist al);
CK_ATTRIBUTE_PTR sec_al_get_attr(CK_ATTRIBUTE_TYPE type, struct sec_ck_alist al);

#endif // _FOO_H_
