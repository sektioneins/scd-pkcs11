/*
 * Copyright (C) 2015-2018 SektionEins GmbH / Ben Fuhrmannek
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "sec.h"
#include "scd.h"

#ifdef SEC_DEBUG
#define RETURN_CKR(ret) { if ((ret) != CKR_OK) { SDEBUG("CKR rv=0x%x", (ret)); } return (ret); }
#else
#define RETURN_CKR(ret) return (ret);
#endif

/* ---- */

static CK_BBOOL g_initialized = 0;

/* ---- GENERATE CK_FUNCTION_LIST */

#define CK_PKCS11_FUNCTION_INFO(name) \
	name,

CK_FUNCTION_LIST pkcs11_function_list = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
	#include "pkcs11f.h"
};
#undef CK_PKCS11_FUNCTION_INFO


/* ---- PKCS11 API IMPLEMENTATION */


#define SEC_PKCS11_FUNCTION(name) \
  extern CK_DEFINE_FUNCTION(CK_RV, name)

/* C_Initialize initializes the Cryptoki library. */
SEC_PKCS11_FUNCTION(C_Initialize)
(
	  CK_VOID_PTR   pInitArgs  /* if this is not NULL_PTR, it gets
	                            * cast to CK_C_INITIALIZE_ARGS_PTR
	                            * and dereferenced */
)
{
	CK_C_INITIALIZE_ARGS_PTR pArgs = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;
	gpg_error_t err;

	SDEBUG("called");
	if (g_initialized) {
		SDEBUG("already initialized.");
		RETURN_CKR(CKR_CRYPTOKI_ALREADY_INITIALIZED);
	}

	memset(&g_state, 0, sizeof(g_state));

	if (pArgs != NULL_PTR) {
		if (pArgs->CreateMutex || pArgs->DestroyMutex || pArgs->LockMutex || pArgs->UnlockMutex) {
			if (pArgs->CreateMutex == NULL_PTR || pArgs->DestroyMutex == NULL_PTR || pArgs->LockMutex == NULL_PTR || pArgs->UnlockMutex == NULL_PTR) {
				SDEBUG("bad arguments -> mutex function ptr is NULL")
				RETURN_CKR(CKR_ARGUMENTS_BAD); // some but not all pointers are NULL_PTR
			}
			sec_log_err("multi-threading not supported");
			RETURN_CKR(CKR_CANT_LOCK);
		}
		if (pArgs->flags & CKF_OS_LOCKING_OK) {
			sec_log_err("OS based multi-threading not supported");
			RETURN_CKR(CKR_CANT_LOCK);
		}
	}

	err = scd_agent_connect(&g_state.ctx);
	if (err) {
		sec_log_err("cannot connect to agent: %d", err);
		RETURN_CKR(CKR_FUNCTION_FAILED);
	}

	g_initialized = 1;
	RETURN_CKR(CKR_OK);
}


/* C_Finalize indicates that an application is done with the
 * Cryptoki library. */
SEC_PKCS11_FUNCTION(C_Finalize)
(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
)
{
	SDEBUG("called");
	if (!g_initialized)
		RETURN_CKR(CKR_CRYPTOKI_NOT_INITIALIZED);

	g_initialized = 0;

	scd_agent_disconnect(g_state.ctx);
	g_state.ctx = NULL;

	sec_free_token();

	RETURN_CKR(CKR_OK);
}



/* C_GetInfo returns general information about Cryptoki. */
SEC_PKCS11_FUNCTION(C_GetInfo)
(
  CK_INFO_PTR   pInfo  /* location that receives information */
)
{
	SDEBUG("called");
	if (pInfo == NULL_PTR)
		RETURN_CKR(CKR_ARGUMENTS_BAD);

	memset(pInfo, 0, sizeof(CK_INFO));
	pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	strncpy((char*)pInfo->manufacturerID, "SektionEins GmbH", sizeof(pInfo->manufacturerID)-1);
	strncpy((char*)pInfo->libraryDescription, "GPG SCDAEMON PKCS#11 API", sizeof(pInfo->libraryDescription)-1);
	pInfo->libraryVersion.major = SEC_MAJOR_VERSION;
	pInfo->libraryVersion.minor = SEC_MINOR_VERSION;

	RETURN_CKR(CKR_OK);
}


/* C_GetFunctionList returns the function list. */
SEC_PKCS11_FUNCTION(C_GetFunctionList)
(
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList  /* receives pointer to
                                            * function list */
)
{
	SDEBUG("called");
	if (ppFunctionList == NULL_PTR)
		RETURN_CKR(CKR_ARGUMENTS_BAD);

	*ppFunctionList = &pkcs11_function_list;
	RETURN_CKR(CKR_OK);
}



/* Slot and token management */

/* C_GetSlotList obtains a list of slots in the system. */
SEC_PKCS11_FUNCTION(C_GetSlotList)
(
  CK_BBOOL       tokenPresent,  /* only slots with tokens? */
  CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
  CK_ULONG_PTR   pulCount       /* receives number of slots */
)
{
	SDEBUG("called");
	if (!g_initialized)
		RETURN_CKR(CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pulCount == NULL_PTR)
		RETURN_CKR(CKR_ARGUMENTS_BAD);

	if (pSlotList == NULL_PTR) {
		*pulCount = 1;
		RETURN_CKR(CKR_OK);
	}

	if (*pulCount < 1) {
		*pulCount = 1;
		RETURN_CKR(CKR_BUFFER_TOO_SMALL);
	}

	*pSlotList = 0;
	RETURN_CKR(CKR_OK);
}


/* C_GetSlotInfo obtains information about a particular slot in
 * the system. */
SEC_PKCS11_FUNCTION(C_GetSlotInfo)
(
  CK_SLOT_ID       slotID,  /* the ID of the slot */
  CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
)
{
	SDEBUG("called");
	if (!g_initialized)
		RETURN_CKR(CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pInfo == NULL_PTR)
		RETURN_CKR(CKR_ARGUMENTS_BAD);
	if (slotID != 0)
		RETURN_CKR(CKR_SLOT_ID_INVALID);

	memset(pInfo, 0, sizeof(CK_SLOT_INFO));
	strncpy((char*)pInfo->slotDescription, "Virtual slot", sizeof(pInfo->slotDescription)-1);
	strncpy((char*)pInfo->manufacturerID, "SektionEins GmbH", sizeof(pInfo->manufacturerID)-1);
	pInfo->flags = CKF_HW_SLOT | CKF_REMOVABLE_DEVICE;
	if (scd_token_present(g_state.ctx)) {
		pInfo->flags |= CKF_TOKEN_PRESENT;
	} else {
		sec_free_token();
	}
	pInfo->hardwareVersion.major = 0;
	pInfo->hardwareVersion.minor = 0;
	pInfo->firmwareVersion.major = 0;
	pInfo->firmwareVersion.minor = 0;

	RETURN_CKR(CKR_OK);
}


/* C_GetTokenInfo obtains information about a particular token
 * in the system. */
SEC_PKCS11_FUNCTION(C_GetTokenInfo)
(
  CK_SLOT_ID        slotID,  /* ID of the token's slot */
  CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
)
{
	SDEBUG("called");
	if (!g_initialized)
		RETURN_CKR(CKR_CRYPTOKI_NOT_INITIALIZED);

	if (slotID != 0)
		RETURN_CKR(CKR_SLOT_ID_INVALID);
	if (pInfo == NULL_PTR)
		RETURN_CKR(CKR_ARGUMENTS_BAD);

	if (!scd_token_present(g_state.ctx)) {
		sec_free_token();
		RETURN_CKR(CKR_TOKEN_NOT_PRESENT);
	}
	if (sec_learn_token(g_state.ctx)) {
		RETURN_CKR(CKR_TOKEN_NOT_PRESENT);
	}

	memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
	strncpy((char*)pInfo->label, "Virtual token", sizeof(pInfo->label)-1);
	strncpy((char*)pInfo->manufacturerID, "SektionEins GmbH", sizeof(pInfo->manufacturerID)-1);
	strncpy((char*)pInfo->model, "OpenPGP-Card", sizeof(pInfo->model)-1);           /* blank padded */
	strncpy((char*)pInfo->serialNumber, (char*)g_state.token->serialno, sizeof(pInfo->serialNumber)-1);
	// pInfo->flags = CKF_RNG | CKF_WRITE_PROTECTED | CKF_USER_PIN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH;
	pInfo->flags = CKF_WRITE_PROTECTED | CKF_USER_PIN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH | CKF_TOKEN_INITIALIZED;   // CKF_LOGIN_REQUIRED

	pInfo->ulMaxSessionCount = SEC_MAX_SESSION_COUNT;     /* max open sessions */
	pInfo->ulSessionCount = g_state.session_count;        /* sess. now open */
	pInfo->ulMaxRwSessionCount = 0;   /* max R/W sessions */
	pInfo->ulRwSessionCount = 0;      /* R/W sess. now open */
	pInfo->ulMaxPinLen = 32;           /* in bytes */
	pInfo->ulMinPinLen = 6;           /* in bytes */
	pInfo->ulTotalPublicMemory = -1;   /* in bytes */
	pInfo->ulFreePublicMemory = -1;    /* in bytes */
	pInfo->ulTotalPrivateMemory = -1;  /* in bytes */
	pInfo->ulFreePrivateMemory = -1;   /* in bytes */

	pInfo->hardwareVersion.major = 2;       /* version of hardware */
	pInfo->hardwareVersion.minor = 1;
	pInfo->firmwareVersion.major = 2;       /* version of firmware */
	pInfo->firmwareVersion.major = 1;
	pInfo->utcTime[0] = 0;           /* time */

	RETURN_CKR(CKR_OK);
}



/* C_GetMechanismList obtains a list of mechanism types
 * supported by a token. */
SEC_PKCS11_FUNCTION(C_GetMechanismList)
(
  CK_SLOT_ID            slotID,          /* ID of token's slot */
  CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
  CK_ULONG_PTR          pulCount         /* gets # of mechs. */
)
{
	SDEBUG("called");
	if (!g_initialized)
		RETURN_CKR(CKR_CRYPTOKI_NOT_INITIALIZED);

	if (slotID != 0)
		RETURN_CKR(CKR_SLOT_ID_INVALID);
	if (pMechanismList == NULL_PTR) {
		*pulCount = 16;
		RETURN_CKR(CKR_OK);
	}
	if (pulCount == NULL_PTR || *pulCount < 16) {
		*pulCount = 16;
		RETURN_CKR(CKR_BUFFER_TOO_SMALL);
	}

	// TODO: somehow get the actual list from the token

	*pulCount = 0;
	pMechanismList[(*pulCount)++] = CKM_SHA_1;
	pMechanismList[(*pulCount)++] = CKM_SHA256;
	pMechanismList[(*pulCount)++] = CKM_SHA384;
	pMechanismList[(*pulCount)++] = CKM_SHA512;
	pMechanismList[(*pulCount)++] = CKM_MD5;
	pMechanismList[(*pulCount)++] = CKM_RIPEMD160;
	pMechanismList[(*pulCount)++] = CKM_GOSTR3411;
	pMechanismList[(*pulCount)++] = CKM_RSA_X_509;
	pMechanismList[(*pulCount)++] = CKM_RSA_PKCS;
	pMechanismList[(*pulCount)++] = CKM_SHA1_RSA_PKCS;
	pMechanismList[(*pulCount)++] = CKM_SHA256_RSA_PKCS;
	pMechanismList[(*pulCount)++] = CKM_SHA384_RSA_PKCS;
	pMechanismList[(*pulCount)++] = CKM_SHA512_RSA_PKCS;
	pMechanismList[(*pulCount)++] = CKM_MD5_RSA_PKCS;
	pMechanismList[(*pulCount)++] = CKM_RIPEMD160_RSA_PKCS;
	pMechanismList[(*pulCount)++] = CKM_RSA_PKCS_KEY_PAIR_GEN;
	RETURN_CKR(CKR_OK);
}


/* C_GetMechanismInfo obtains information about a particular
 * mechanism possibly supported by a token. */
SEC_PKCS11_FUNCTION(C_GetMechanismInfo)
(
  CK_SLOT_ID            slotID,  /* ID of the token's slot */
  CK_MECHANISM_TYPE     type,    /* type of mechanism */
  CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_InitToken initializes a token. */
SEC_PKCS11_FUNCTION(C_InitToken)
/* pLabel changed from CK_CHAR_PTR to CK_UTF8CHAR_PTR for v2.10 */
(
  CK_SLOT_ID      slotID,    /* ID of the token's slot */
  CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
  CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
  CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_InitPIN initializes the normal user's PIN. */
SEC_PKCS11_FUNCTION(C_InitPIN)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_SetPIN modifies the PIN of the user who is logged in. */
SEC_PKCS11_FUNCTION(C_SetPIN)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_UTF8CHAR_PTR   pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}



/* Session management */

/* C_OpenSession opens a session between an application and a
 * token. */
SEC_PKCS11_FUNCTION(C_OpenSession)
(
  CK_SLOT_ID            slotID,        /* the slot's ID */
  CK_FLAGS              flags,         /* from CK_SESSION_INFO */
  CK_VOID_PTR           pApplication,  /* passed to callback */
  CK_NOTIFY             Notify,        /* callback function */
  CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
	SDEBUG("called");
	if (!g_initialized)
		RETURN_CKR(CKR_CRYPTOKI_NOT_INITIALIZED);
	if (slotID != 0)
		RETURN_CKR(CKR_SLOT_ID_INVALID);
	// if (!(flags & CKF_SERIAL_SESSION))
	// 	RETURN_CKR(CKR_PARALLEL_NOT_SUPPORTED);
	if (g_state.session_count >= SEC_MAX_SESSION_COUNT)
		RETURN_CKR(CKR_SESSION_COUNT);

	if (!scd_token_present(g_state.ctx)) {
		sec_free_token();
		RETURN_CKR(CKR_TOKEN_NOT_PRESENT);
	}

	if (sec_learn_token(g_state.ctx)) {
		RETURN_CKR(CKR_TOKEN_NOT_PRESENT);
	}

	*phSession = ++g_state.session_count;
	RETURN_CKR(CKR_OK);
}


/* C_CloseSession closes a session between an application and a
 * token. */
SEC_PKCS11_FUNCTION(C_CloseSession)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	SDEBUG("called");
	if (!g_initialized)
		RETURN_CKR(CKR_CRYPTOKI_NOT_INITIALIZED);
	g_state.session_count = 0;
	RETURN_CKR(CKR_OK);
}


/* C_CloseAllSessions closes all sessions with a token. */
SEC_PKCS11_FUNCTION(C_CloseAllSessions)
(
  CK_SLOT_ID     slotID  /* the token's slot */
)
{
	SDEBUG("called");
	if (!g_initialized)
		RETURN_CKR(CKR_CRYPTOKI_NOT_INITIALIZED);
	g_state.session_count = 0;
	RETURN_CKR(CKR_OK);
}


/* C_GetSessionInfo obtains information about the session. */
SEC_PKCS11_FUNCTION(C_GetSessionInfo)
(
  CK_SESSION_HANDLE   hSession,  /* the session's handle */
  CK_SESSION_INFO_PTR pInfo      /* receives session info */
)
{
	SDEBUG("called");
	if (!g_initialized)
		RETURN_CKR(CKR_CRYPTOKI_NOT_INITIALIZED);
	if (pInfo == NULL_PTR) {
		RETURN_CKR(CKR_ARGUMENTS_BAD);
	}
	memset(pInfo, 0, sizeof(CK_SESSION_INFO));
	pInfo->slotID = 0;
	pInfo->state = CKS_RO_USER_FUNCTIONS;
	// possible states:
	// CKS_RO_PUBLIC_SESSION  0
	// CKS_RO_USER_FUNCTIONS  1
	// --> always assume CKS_RO_USER_FUNCTIONS, because SCD handles login
	pInfo->flags = CKF_SERIAL_SESSION;

	RETURN_CKR(CKR_OK);
}


/* C_GetOperationState obtains the state of the cryptographic operation
 * in a session. */
SEC_PKCS11_FUNCTION(C_GetOperationState)
(
  CK_SESSION_HANDLE hSession,             /* session's handle */
  CK_BYTE_PTR       pOperationState,      /* gets state */
  CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_SetOperationState restores the state of the cryptographic
 * operation in a session. */
SEC_PKCS11_FUNCTION(C_SetOperationState)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR      pOperationState,      /* holds state */
  CK_ULONG         ulOperationStateLen,  /* holds state length */
  CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
  CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_Login logs a user into a token. */
SEC_PKCS11_FUNCTION(C_Login)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen   /* the length of the PIN */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_Logout logs a user out from a token. */
SEC_PKCS11_FUNCTION(C_Logout)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}



/* Object management */

/* C_CreateObject creates a new object. */
SEC_PKCS11_FUNCTION(C_CreateObject)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
  CK_ULONG          ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_CopyObject copies an object, creating a new object for the
 * copy. */
SEC_PKCS11_FUNCTION(C_CopyObject)
(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_OBJECT_HANDLE     hObject,     /* the object's handle */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
  CK_ULONG             ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_DestroyObject destroys an object. */
SEC_PKCS11_FUNCTION(C_DestroyObject)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject    /* the object's handle */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_GetObjectSize gets the size of an object in bytes. */
SEC_PKCS11_FUNCTION(C_GetObjectSize)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_GetAttributeValue obtains the value of one or more object
 * attributes. */
SEC_PKCS11_FUNCTION(C_GetAttributeValue)
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
  CK_ULONG          ulCount     /* attributes in template */
)
{
	CK_RV rv = CKR_OK;
	SDEBUG("called. hSession=%lu hObject=%lu", hSession, hObject);
	if (!g_initialized)
		RETURN_CKR(CKR_CRYPTOKI_NOT_INITIALIZED);

	if (sec_learn_token(g_state.ctx)) {
		RETURN_CKR(CKR_DEVICE_REMOVED);
	}

	if (g_state.token == NULL) {
		RETURN_CKR(CKR_FUNCTION_FAILED);
	}

	struct sec_ck_alist *pA = NULL;
	switch (hObject) {
		case SEC_OH_CERT3:
			pA = &g_state.token->alCert[SEC_KEY3];
			break;
		case SEC_OH_PRIV3:
			pA = &g_state.token->alPriv[SEC_KEY3];
			break;
		case SEC_OH_PUB3:
			pA = &g_state.token->alPub[SEC_KEY3];
			break;
		default:
			RETURN_CKR(CKR_OBJECT_HANDLE_INVALID);
	}

	if (pA == NULL || pA->p == NULL) {
		SDEBUG("failed (null ptr)");
		RETURN_CKR(CKR_FUNCTION_FAILED);
	}

	CK_ATTRIBUTE_PTR pTmp; // pointer to current attribute of pA
	CK_ULONG i, j;
	for (i = 0; i < ulCount; i++) {
		SDEBUG("i=%lu type=0x%lx", i, pTemplate[i].type);
		pTmp = NULL;
		for (j = 0; j < pA->cnt; j++) {
			if (pTemplate[i].type == pA->p[j].type) {
				pTmp = &pA->p[j];
				break;
			}
		}
		if (pTmp == NULL) { // attribute type not found
			SDEBUG("attribute type not found");
			pTemplate[i].ulValueLen = -1;
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
			continue;
		}
		if (pTemplate[i].pValue == NULL_PTR) { // size request
			SDEBUG("size request");
			pTemplate[i].ulValueLen = pTmp->ulValueLen;
			continue;
		}
		if (pTemplate[i].ulValueLen < pTmp->ulValueLen) { // buffer too small
			SDEBUG("buffer too small");
			pTemplate[i].ulValueLen = -1;
			rv = CKR_BUFFER_TOO_SMALL;
			continue;
		}
		memcpy(pTemplate[i].pValue, pTmp->pValue, pTmp->ulValueLen);
		pTemplate[i].ulValueLen = pTmp->ulValueLen;
	}


	return rv;
}


/* C_SetAttributeValue modifies the value of one or more object
 * attributes */
SEC_PKCS11_FUNCTION(C_SetAttributeValue)
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
  CK_ULONG          ulCount     /* attributes in template */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_FindObjectsInit initializes a search for token and session
 * objects that match a template. */
SEC_PKCS11_FUNCTION(C_FindObjectsInit)
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
  CK_ULONG          ulCount     /* attrs in search template */
)
{
	SDEBUG("called count=%lu", ulCount);
	for (int i = 0; i < ulCount; i++) {
		SDEBUG("attribute i=%d type=0x%lx *value=%x", i, pTemplate[i].type, pTemplate[i].pValue == NULL_PTR ? 0 : *(uint*)pTemplate[i].pValue);

	}

	g_state.find.template.p = pTemplate;
	g_state.find.template.cnt = ulCount;
	g_state.find.ulResultCount = 0;

	// note: ulResultCount must not exceed SEC_FIND_MAXRESULTS

	if (g_state.token) {
		if (g_state.token->alCert[SEC_KEY3].p && (ulCount == 0 || sec_al_match(g_state.find.template, g_state.token->alCert[SEC_KEY3])))
			g_state.find.phResult[g_state.find.ulResultCount++] = SEC_OH_CERT3;
		if (g_state.token->alPriv[SEC_KEY3].p && (ulCount == 0 || sec_al_match(g_state.find.template, g_state.token->alPriv[SEC_KEY3])))
			g_state.find.phResult[g_state.find.ulResultCount++] = SEC_OH_PRIV3;
		if (g_state.token->alPub[SEC_KEY3].p && (ulCount == 0 || sec_al_match(g_state.find.template, g_state.token->alPub[SEC_KEY3])))
			g_state.find.phResult[g_state.find.ulResultCount++] = SEC_OH_PUB3;
	}


	SDEBUG("returning %lu objects", g_state.find.ulResultCount);
	RETURN_CKR(CKR_OK);
}


/* C_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles. */
SEC_PKCS11_FUNCTION(C_FindObjects)
(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
 CK_ULONG_PTR         pulObjectCount     /* actual # returned */
)
{
	SDEBUG("called phObject=%p ulMaxObjectCount=%lu", phObject, ulMaxObjectCount);
	if (!g_initialized)
		RETURN_CKR(CKR_CRYPTOKI_NOT_INITIALIZED);

	if (ulMaxObjectCount == 0) {
		RETURN_CKR(CKR_OK);
	}
	if (phObject == NULL_PTR) {
		RETURN_CKR(CKR_ARGUMENTS_BAD);
	}
	if (g_state.find.ulResultCount == 0) {
		// find not initialized or no further results
		*pulObjectCount = 0;
		RETURN_CKR(CKR_OK);
	}

	// copy phResult to phObject in reverse order, so that the first
	// ulResultCount objects will always hold the remaining result
	CK_ULONG i;
	// SDEBUG("ulResultCount=%lu", g_state.find.ulResultCount);
	for (i = 0; i < ulMaxObjectCount && i < g_state.find.ulResultCount; i++) {
		memcpy(phObject + i, g_state.find.phResult + g_state.find.ulResultCount - 1 - i, sizeof(*g_state.find.phResult));
		// SDEBUG("phObject[%lu]=%lu", i, phObject[i]);
	}
	*pulObjectCount = i;
	g_state.find.ulResultCount -= i;

	RETURN_CKR(CKR_OK);
}


/* C_FindObjectsFinal finishes a search for token and session
 * objects. */
SEC_PKCS11_FUNCTION(C_FindObjectsFinal)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	SDEBUG("called");
	if (!g_initialized)
		RETURN_CKR(CKR_CRYPTOKI_NOT_INITIALIZED);

	g_state.find.template.p = NULL;
	g_state.find.template.cnt = 0;
	g_state.find.ulResultCount = 0;
	RETURN_CKR(CKR_OK);
}



/* Encryption and decryption */

/* C_EncryptInit initializes an encryption operation. */
SEC_PKCS11_FUNCTION(C_EncryptInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_Encrypt encrypts single-part data. */
SEC_PKCS11_FUNCTION(C_Encrypt)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pData,               /* the plaintext data */
  CK_ULONG          ulDataLen,           /* bytes of plaintext */
  CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_EncryptUpdate continues a multiple-part encryption
 * operation. */
SEC_PKCS11_FUNCTION(C_EncryptUpdate)
(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_EncryptFinal finishes a multiple-part encryption
 * operation. */
SEC_PKCS11_FUNCTION(C_EncryptFinal)
(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_DecryptInit initializes a decryption operation. */
SEC_PKCS11_FUNCTION(C_DecryptInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_Decrypt decrypts encrypted data in a single part. */
SEC_PKCS11_FUNCTION(C_Decrypt)
(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
  CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
  CK_BYTE_PTR       pData,              /* gets plaintext */
  CK_ULONG_PTR      pulDataLen          /* gets p-text size */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_DecryptUpdate continues a multiple-part decryption
 * operation. */
SEC_PKCS11_FUNCTION(C_DecryptUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_DecryptFinal finishes a multiple-part decryption
 * operation. */
SEC_PKCS11_FUNCTION(C_DecryptFinal)
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}



/* Message digesting */

/* C_DigestInit initializes a message-digesting operation. */
SEC_PKCS11_FUNCTION(C_DigestInit)
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_Digest digests data in a single part. */
SEC_PKCS11_FUNCTION(C_Digest)
(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pData,        /* data to be digested */
  CK_ULONG          ulDataLen,    /* bytes of data to digest */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets digest length */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_DigestUpdate continues a multiple-part message-digesting
 * operation. */
SEC_PKCS11_FUNCTION(C_DigestUpdate)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* data to be digested */
  CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested. */
SEC_PKCS11_FUNCTION(C_DigestKey)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hKey       /* secret key to digest */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_DigestFinal finishes a multiple-part message-digesting
 * operation. */
SEC_PKCS11_FUNCTION(C_DigestFinal)
(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}



/* Signing and MACing */

/* C_SignInit initializes a signature (private key encryption)
 * operation, where the signature is (will be) an appendix to
 * the data, and plaintext cannot be recovered from the
 *signature. */
SEC_PKCS11_FUNCTION(C_SignInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of signature key */
)
{
	SDEBUG("called");
	if (!g_initialized)
		RETURN_CKR(CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pMechanism == NULL_PTR)
		RETURN_CKR(CKR_ARGUMENTS_BAD);
	SDEBUG("mechanism=0x%lx hKey=%lu", pMechanism->mechanism, hKey);
	if (pMechanism->mechanism != CKM_RSA_PKCS)
		RETURN_CKR(CKR_MECHANISM_INVALID);
	if (hKey != SEC_OH_PRIV3)
		RETURN_CKR(CKR_KEY_HANDLE_INVALID);
	g_state.sign.inprogress = 1;
	RETURN_CKR(CKR_OK);
}


/* C_Sign signs (encrypts with private key) data in a single
 * part, where the signature is (will be) an appendix to the
 * data, and plaintext cannot be recovered from the signature. */
SEC_PKCS11_FUNCTION(C_Sign)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	SDEBUG("called pData=%p pSignature=%p pulSignatureLen=%p", pData, pSignature, pulSignatureLen);
	if (!g_initialized)
		RETURN_CKR(CKR_CRYPTOKI_NOT_INITIALIZED);

	if (!g_state.sign.inprogress)
		RETURN_CKR(CKR_OPERATION_NOT_INITIALIZED);

	if (sec_learn_token(g_state.ctx)) {
		RETURN_CKR(CKR_DEVICE_REMOVED);
	}
	if (pSignature == NULL_PTR && pulSignatureLen != NULL_PTR) {
		CK_ATTRIBUTE_PTR pa = sec_al_get_attr(CKA_MODULUS_BITS, g_state.token->alPub[SEC_KEY3]);
		if (pa == NULL) { return CKR_FUNCTION_REJECTED; }
		CK_ULONG siglen = *(CK_ULONG*)pa->pValue + 7 / 8;
		if (*pulSignatureLen < siglen) {
			*pulSignatureLen = siglen;
			RETURN_CKR(CKR_BUFFER_TOO_SMALL);
		}
		RETURN_CKR(CKR_OK);
	}

	if (pData == NULL_PTR || pSignature == NULL_PTR || pulSignatureLen == NULL_PTR)
		RETURN_CKR(CKR_ARGUMENTS_BAD);

	SDEBUG("datalen=%lu siglen=%lu", ulDataLen, *pulSignatureLen);
	if (ulDataLen == 0 || ulDataLen > SEC_SIGN_MAXLEN)
		RETURN_CKR(CKR_DATA_LEN_RANGE);

	gpg_error_t err;
	err = scd_sign_data(g_state.ctx, pSignature, pulSignatureLen, pData, ulDataLen);
	if (err == GPG_ERR_BUFFER_TOO_SHORT) {
		RETURN_CKR(CKR_BUFFER_TOO_SMALL);
	}
	if (err) {

		SDEBUG("something went wrong");
		RETURN_CKR(CKR_GENERAL_ERROR);
	}

	g_state.sign.inprogress = 0;
	RETURN_CKR(CKR_OK);
}


/* C_SignUpdate continues a multiple-part signature operation,
 * where the signature is (will be) an appendix to the data,
 * and plaintext cannot be recovered from the signature. */
SEC_PKCS11_FUNCTION(C_SignUpdate)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* the data to sign */
  CK_ULONG          ulPartLen  /* count of bytes to sign */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_SignFinal finishes a multiple-part signature operation,
 * returning the signature. */
SEC_PKCS11_FUNCTION(C_SignFinal)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	SDEBUG("called");
	g_state.sign.inprogress = 0;
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_SignRecoverInit initializes a signature operation, where
 * the data can be recovered from the signature. */
SEC_PKCS11_FUNCTION(C_SignRecoverInit)
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_SignRecover signs data in a single operation, where the
 * data can be recovered from the signature. */
SEC_PKCS11_FUNCTION(C_SignRecover)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}



/* Verifying signatures and MACs */

/* C_VerifyInit initializes a verification operation, where the
 * signature is an appendix to the data, and plaintext cannot
 *  cannot be recovered from the signature (e.g. DSA). */
SEC_PKCS11_FUNCTION(C_VerifyInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_Verify verifies a signature in a single-part operation,
 * where the signature is an appendix to the data, and plaintext
 * cannot be recovered from the signature. */
SEC_PKCS11_FUNCTION(C_Verify)
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pData,          /* signed data */
  CK_ULONG          ulDataLen,      /* length of signed data */
  CK_BYTE_PTR       pSignature,     /* signature */
  CK_ULONG          ulSignatureLen  /* signature length*/
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_VerifyUpdate continues a multiple-part verification
 * operation, where the signature is an appendix to the data,
 * and plaintext cannot be recovered from the signature. */
SEC_PKCS11_FUNCTION(C_VerifyUpdate)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* signed data */
  CK_ULONG          ulPartLen  /* length of signed data */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_VerifyFinal finishes a multiple-part verification
 * operation, checking the signature. */
SEC_PKCS11_FUNCTION(C_VerifyFinal)
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pSignature,     /* signature to verify */
  CK_ULONG          ulSignatureLen  /* signature length */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_VerifyRecoverInit initializes a signature verification
 * operation, where the data is recovered from the signature. */
SEC_PKCS11_FUNCTION(C_VerifyRecoverInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_VerifyRecover verifies a signature in a single-part
 * operation, where the data is recovered from the signature. */
SEC_PKCS11_FUNCTION(C_VerifyRecover)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* signature to verify */
  CK_ULONG          ulSignatureLen,  /* signature length */
  CK_BYTE_PTR       pData,           /* gets signed data */
  CK_ULONG_PTR      pulDataLen       /* gets signed data len */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}



/* Dual-function cryptographic operations */

/* C_DigestEncryptUpdate continues a multiple-part digesting
 * and encryption operation. */
SEC_PKCS11_FUNCTION(C_DigestEncryptUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_DecryptDigestUpdate continues a multiple-part decryption and
 * digesting operation. */
SEC_PKCS11_FUNCTION(C_DecryptDigestUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_SignEncryptUpdate continues a multiple-part signing and
 * encryption operation. */
SEC_PKCS11_FUNCTION(C_SignEncryptUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_DecryptVerifyUpdate continues a multiple-part decryption and
 * verify operation. */
SEC_PKCS11_FUNCTION(C_DecryptVerifyUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets p-text length */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}



/* Key management */

/* C_GenerateKey generates a secret key, creating a new key
 * object. */
SEC_PKCS11_FUNCTION(C_GenerateKey)
(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
  CK_ULONG             ulCount,     /* # of attrs in template */
  CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_GenerateKeyPair generates a public-key/private-key pair,
 * creating new key objects. */
SEC_PKCS11_FUNCTION(C_GenerateKeyPair)
(
  CK_SESSION_HANDLE    hSession,                    /* session
                                                     * handle */
  CK_MECHANISM_PTR     pMechanism,                  /* key-gen
                                                     * mech. */
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template
                                                     * for pub.
                                                     * key */
  CK_ULONG             ulPublicKeyAttributeCount,   /* # pub.
                                                     * attrs. */
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template
                                                     * for priv.
                                                     * key */
  CK_ULONG             ulPrivateKeyAttributeCount,  /* # priv.
                                                     * attrs. */
  CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub.
                                                     * key
                                                     * handle */
  CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets
                                                     * priv. key
                                                     * handle */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_WrapKey wraps (i.e., encrypts) a key. */
SEC_PKCS11_FUNCTION(C_WrapKey)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
  CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 * key object. */
SEC_PKCS11_FUNCTION(C_UnwrapKey)
(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
  CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
  CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_DeriveKey derives a key from a base key, creating a new key
 * object. */
SEC_PKCS11_FUNCTION(C_DeriveKey)
(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
  CK_OBJECT_HANDLE     hBaseKey,          /* base key */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}



/* Random number generation */

/* C_SeedRandom mixes additional seed material into the token's
 * random number generator. */
SEC_PKCS11_FUNCTION(C_SeedRandom)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pSeed,     /* the seed material */
  CK_ULONG          ulSeedLen  /* length of seed material */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_RANDOM_SEED_NOT_SUPPORTED);
}


/* C_GenerateRandom generates random data. */
SEC_PKCS11_FUNCTION(C_GenerateRandom)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_BYTE_PTR       RandomData,  /* receives the random data */
  CK_ULONG          ulRandomLen  /* # of bytes to generate */
)
{
	SDEBUG("called");
	if (!g_initialized)
		RETURN_CKR(CKR_CRYPTOKI_NOT_INITIALIZED);

	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}



/* Parallel function management */

/* C_GetFunctionStatus is a legacy function; it obtains an
 * updated status of a function running in parallel with an
 * application. */
SEC_PKCS11_FUNCTION(C_GetFunctionStatus)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}


/* C_CancelFunction is a legacy function; it cancels a function
 * running in parallel. */
SEC_PKCS11_FUNCTION(C_CancelFunction)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}



/* Functions added in for Cryptoki Version 2.01 or later */

/* C_WaitForSlotEvent waits for a slot event (token insertion,
 * removal, etc.) to occur. */
SEC_PKCS11_FUNCTION(C_WaitForSlotEvent)
(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
)
{
	SDEBUG("called");
	RETURN_CKR(CKR_FUNCTION_NOT_SUPPORTED);
}
