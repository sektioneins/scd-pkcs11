/* for stpcpy on linux; possibly other functions */
// #define _GNU_SOURCE
#define _XOPEN_SOURCE 700

// the prefix SEC_ is an acronym for SektionEins Cryptoki 

// #define SEC_DEBUG
#define SEC_LOG "/tmp/ck_log.txt"

#define SEC_MAJOR_VERSION 0
#define SEC_MINOR_VERSION 0

/* ---- */

#ifndef HAVE_UCHAR
typedef unsigned char uchar;
#endif

#ifndef HAVE_UINT
typedef unsigned int uint;
#endif

/* ----- DEBUGGING + LOGGING */

#ifdef SEC_DEBUG
#define SDEBUG(msg...) \
    {FILE *f;f=fopen(SEC_LOG, "a+");if(f){fprintf(f,"%s:%u %s #> ",__FILE__, __LINE__, __func__);fprintf(f, msg);fprintf(f,"\n");fclose(f);}}
#define sec_log(msg...) SDEBUG(msg)
#define sec_log_err(msg...) SDEBUG(msg)

#else

#define SDEBUG(msg...)
#define sec_log(msg...) \
	fprintf(stderr, msg)

#define sec_log_err(msg...) \
	fprintf(stderr, msg)

#endif    
