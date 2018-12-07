#ifndef SCD_H
#define SCD_H

#include <assuan.h>

#define SEC_SIGN_MAXLEN 4096

gpg_error_t scd_agent_connect(assuan_context_t *ctx);
void scd_agent_disconnect(assuan_context_t ctx);
gpg_error_t scd_set_option(assuan_context_t ctx, char *key, char *value);
gpg_error_t scd_serialno_openpgp(assuan_context_t ctx);
int scd_token_present(assuan_context_t ctx);
gpg_error_t scd_unescape_data(uchar *out, size_t *poutlen, uchar *data, size_t datalen);
gpg_error_t scd_sign_data(assuan_context_t ctx, uchar *pSignature, unsigned long *pulSignatureLen, uchar *pData, unsigned long ulDataLen);

gpg_error_t scd_unpack_pubkey(uchar **pn, size_t *pnlen,
	uchar **pe, size_t *pelen,
	uchar *pubkey, size_t pubkeylen);

#endif /* SCD_H */
