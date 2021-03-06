#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

typedef X509_STORE *Crypt__OpenSSL__Verify;
typedef X509 *Crypt__OpenSSL__X509;

struct OPTIONS {
   bool  trust_expired;
   bool  trust_no_local;
   bool  trust_onelogin;
};
=pod
=head1 NAME

Verify.xs - C interface to OpenSSL to verify certificates

=head1 METHODS

=head2 verify_cb(int ok, X509_STORE_CTX * ctx)
The C equivalent of the verify_callback perl sub
This code is due to be removed if the perl version
is permanent

=cut

#if DISABLED
int verify_cb(struct OPTIONS * options, int ok, X509_STORE_CTX * ctx)
{

    int cert_error = X509_STORE_CTX_get_error(ctx);

    if (!ok) {
        /*
         * Pretend that some errors are ok, so they don't stop further
         * processing of the certificate chain.  Setting ok = 1 does this.
         * After X509_verify_cert() is done, we verify that there were
         * no actual errors, even if the returned value was positive.
         */
        switch (cert_error) {
            case X509_V_ERR_NO_EXPLICIT_POLICY:
                /* fall thru */
            case X509_V_ERR_CERT_HAS_EXPIRED:
                if ( ! options->trust_expired ) {
                    break;
                }
                ok = 1;
                break;
                /* Continue even if the leaf is a self signed cert */
            case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
                /* Continue after extension errors too */
            case X509_V_ERR_INVALID_CA:
            case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
                if ( !options->trust_onelogin )
                    break;
                ok = 1;
                break;
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
                if ( !options->trust_no_local )
                    break;
                ok = 1;
                break;
            case X509_V_ERR_INVALID_NON_CA:
            case X509_V_ERR_PATH_LENGTH_EXCEEDED:
            case X509_V_ERR_INVALID_PURPOSE:
            case X509_V_ERR_CRL_HAS_EXPIRED:
            case X509_V_ERR_CRL_NOT_YET_VALID:
            case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
                ok = 1;
        }
        return ok;
    }
    return ok;
}
#endif
=head2 int cb1(ok, ctx)

The link to the Perl verify_callback() sub.  This called by OpenSSL
during the verify of the certificates and in turn passes the parameters
to the Perl verify_callback() sub.  It gets a return code from Perl
and returns it to OpenSSL

=head3 Parameters
=over
=item ok
    * ok - the result of the certificate verification in OpenSSL
            ok = 1, !ok = 0

=item ctx
    * ctx - Pointer to the X509_Store_CTX that OpenSSL includes the
            error codes in
=back
=cut


static SV *callback = (SV *) NULL;

static int cb1(ok, ctx)
    int ok;
    UV *ctx;
{
    dSP;
    int count;
    int i;

    /* printf("Callback pointer: %p\n", ctx); */
    /* printf("Callback UL of pointer %lu\n", PTR2UV(ctx)); */
    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    EXTEND(SP, 2);

    PUSHs(newSVuv(ok));                 // Pass ok as integer on the stack
    PUSHs(newSVuv(PTR2UV(ctx)));        // Pass pointer address as integer
    PUTBACK;

    count = call_sv(callback, G_SCALAR);  // Call the verify_callback()

    SPAGAIN;
    if (count != 1)
        croak("ERROR - Perl callback returned more than one value\n");

    i = POPi;   // Get the return code from Perl verify_callback()
    PUTBACK;
    FREETMPS;
    LEAVE;

    return i;
}
=head2 ssl_error(void)

Returns the string description of the ssl error

=cut

static const char *ssl_error(void)
{
    return ERR_error_string(ERR_get_error(), NULL);
}

=head2 ctx_error(void)

Returns the string description of the ctx error

=cut

static const char *ctx_error(X509_STORE_CTX * ctx)
{
    return X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx));
}

MODULE = Crypt::OpenSSL::Verify    PACKAGE = Crypt::OpenSSL::Verify

PROTOTYPES: DISABLE

#if OPENSSL_API_COMPAT >= 0x10100000L
#undef ERR_load_crypto_strings
#define ERR_load_crypto_strings()    /* nothing */
#undef OpenSSL_add_all_algorithms
#define OpenSSL_add_all_algorithms()    /* nothing */
#endif
BOOT:
    ERR_load_crypto_strings();
    ERR_load_ERR_strings();
    OpenSSL_add_all_algorithms();

=head2 register_verify_cb()

Called by the Perl code to register which Perl sub is
the OpenSSL Verify Callback

=cut
void register_verify_cb(fn)
    SV *fn

    CODE:
        /* this code seems to work fine as the perl function is called */
        /* Remember the Perl sub */
        if (callback == (SV *) NULL)
            callback = newSVsv(fn);
        else
            SvSetSV(callback, fn);

=head _new

The main function to setup the OpenSSL Store to hold the CAfile and to
configure the options for the verification.  In particular it sets the
CAfile, and CApat, noCAfile and noCApath if provided.

It also sets the callback function and returns a an integer value containing
the pointer to X509_Store.

Crypt::OpenSSL::Verify _new(class, options)
=cut
UV _new(class, options)
    SV *class
    HV *options

    PREINIT:

        X509_LOOKUP * lookup = NULL;
        X509_STORE * store = NULL;
        SV **svp;
        SV *CAfile = NULL;
        SV *CApath = NULL;
        int noCApath = 0, noCAfile = 0;
        int strict_certs = 1; /* Default is strict openSSL verify */

    CODE:

        (void)SvPV_nolen(class);

        if (hv_exists(options, "CAfile", strlen("CAfile"))) {
            svp = hv_fetch(options, "CAfile", strlen("CAfile"), 0);
            CAfile = *svp;
        }

        if (hv_exists(options, "noCAfile", strlen("noCAfile"))) {
            svp = hv_fetch(options, "noCAfile", strlen("noCAfile"), 0);
            if (SvIOKp(*svp)) {
                noCAfile = SvIV(*svp);
            }
        }

        if (hv_exists(options, "CApath", strlen("CApath"))) {
            svp = hv_fetch(options, "CApath", strlen("CApath"), 0);
            CApath = *svp;
        }

        if (hv_exists(options, "noCApath", strlen("noCApath"))) {
            svp = hv_fetch(options, "noCApath", strlen("noCApath"), 0);
            if (SvIOKp(*svp)) {
                noCApath = SvIV(*svp);
            }
        }

        if (hv_exists(options, "strict_certs", strlen("strict_certs"))) {
            svp = hv_fetch(options, "strict_certs", strlen("strict_certs"), 0);
            if (SvIOKp(*svp)) {
                strict_certs = SvIV(*svp);
            }
        }

    /* BEGIN Source apps.c setup_verify() */
    store = X509_STORE_new();
    if (store == NULL) {
        X509_STORE_free(store);
        croak("failure to allocate x509 store: %s", ssl_error());
    }

    /* In strict mode do not allow any errors to be ignore */
    if ( ! strict_certs ) {
        X509_STORE_set_verify_cb_func(store, cb1);
    }

    /* Load the CAfile to the store as a certificate to lookup against */
    if (CAfile != NULL || !noCAfile) {
        /* Add a lookup structure to the store to load a file */
        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
        if (lookup == NULL) {
            X509_STORE_free(store);
            croak("failure to add lookup to store: %s", ssl_error());
        }
        if (CAfile != NULL) {
            if (!X509_LOOKUP_load_file
                (lookup, SvPV_nolen(CAfile), X509_FILETYPE_PEM)) {
                X509_STORE_free(store);
                croak("Error loading file %s: %s\n", SvPV_nolen(CAfile),
                    ssl_error());
            }
        } else {
            X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
        }
    }

    /* Load the CApath to the store as a hash dir lookup against */
    if (CApath != NULL || !noCApath) {
        /* Add a lookup structure to the store to load hash dir */
        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
        if (lookup == NULL) {
            X509_STORE_free(store);
            croak("failure to add hash_dir lookup to store: %s", ssl_error());
        }
        if (CApath != NULL) {
            if (!X509_LOOKUP_add_dir(lookup, SvPV_nolen(CApath),
                    X509_FILETYPE_PEM)) {
                croak("Error loading directory %s\n", SvPV_nolen(CApath));
            }
        } else {
            X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
        }
    }

    /* Pass the pointer as an integer so it can return
     * unscathed in the call to ctx_error_code() from Perl */
    RETVAL = PTR2UV(store);

    //printf("X509_STORE - Pointer to RETVAL: %p\n", store);
    //printf("X509_STORE - RETVAL: %lu\n", RETVAL);
    ERR_clear_error();
    /* END Source apps.c setup_verify() */

    OUTPUT:

        RETVAL

=head2 ctx_error_code(ctx)
Called by the Perl code's verify_callback() to get the error code
from SSL from the ctx

Receives the pointer to the ctx as an integer that is converted back
to the point address to be used
=cut
int ctx_error_code(ctx)
    UV ctx;

    PREINIT:

    CODE:
        /* printf("ctx_error_code - UL holding pointer: %lu\n", ctx); */
        /* printf("ctx_error_code - Pointer to ctx: %p\n", (void *) INT2PTR(UV , ctx)); */

        RETVAL = X509_STORE_CTX_get_error((X509_STORE_CTX *) INT2PTR(UV, ctx));

    OUTPUT:

        RETVAL

=head2 verify(self, x509)
The actual verify function that calls OpenSSL to verify the x509 Cert that
has been passed in as a parameter against the store that was setup in _new()

=over Parameters

=item self - self object

Contains details about Crypt::OpenSSL::Verify including  the STORE

=item x509 - Crypt::OpenSSL::X509

Certificate to verify

=back
=cut

int verify(self, x509)
    HV * self;
    Crypt::OpenSSL::X509 x509;

    PREINIT:

        X509_STORE_CTX * csc;

    CODE:
        SV **svp;
        X509_STORE * store;
        store = 0;
        //bool strict_certs = 1;
        //struct OPTIONS trust_options;
        //trust_options.trust_expired = 0;
        //trust_options.trust_no_local = 0;
        //trust_options.trust_onelogin = 0;

        if (x509 == NULL)
        {
            croak("no cert to verify");
        }

        csc = X509_STORE_CTX_new();
        if (csc == NULL) {
            croak("X.509 store context allocation failed: %s", ssl_error());
        }

        if (hv_exists(self, "STORE", strlen("STORE"))) {
            svp = hv_fetch(self, "STORE", strlen("STORE"), 0);
            if (SvIOKp(*svp)) {
                store = (X509_STORE *) INT2PTR(UV, SvIV(*svp));
            } else {
                croak("STORE: Integer not found in self!\n");
            }
        } else {
            croak("STORE not found in self!\n");
        }
        //printf("X509_STORE - Pointer to store: %p\n", &svp);
        //printf("X509_STORE - Pointer to store: %p\n",(void *)  INT2PTR(UV, SvIV(*svp)));

        X509_STORE_set_flags(store, 0);

        if (!X509_STORE_CTX_init(csc, store, x509, NULL)) {
            X509_STORE_CTX_free(csc);
            croak("store ctx init: %s", ssl_error());
        }

        RETVAL = X509_verify_cert(csc);

        //if (hv_exists(self, "strict_certs", strlen("strict_certs"))) {
        //    svp = hv_fetch(self, "strict_certs", strlen("strict_certs"), 0);
        //    if (SvIOKp(*svp)) {
        //        strict_certs = SvIV(*svp);
        //    }
        //}
        //if (hv_exists(self, "trust_expired", strlen("trust_expired"))) {
        //    svp = hv_fetch(self, "trust_expired", strlen("trust_expired"), 0);
        //    if (SvIOKp(*svp)) {
        //        trust_options.trust_expired = SvIV(*svp);
        //    }
        //}
        //if (hv_exists(self, "trust_onelogin", strlen("trust_onelogin"))) {
        //    svp = hv_fetch(self, "trust_onelogin", strlen("trust_onelogin"), 0);
        //    if (SvIOKp(*svp)) {
        //        trust_options.trust_onelogin = SvIV(*svp);
        //    }
        //}
        //if (hv_exists(self, "trust_no_local", strlen("trust_no_local"))) {
        //    svp = hv_fetch(self, "trust_no_local", strlen("trust_no_local"), 0);
        //    if (SvIOKp(*svp)) {
        //        trust_options.trust_no_local = SvIV(*svp);
        //    }
        //}
        //
        //This actually does not accomplish what we want as it essentially
        //checks only the last certificate not the chain that might have
        //acceptable errors.  Original code considered errors on this last
        //certificate as real errors.
        //if ( !RETVAL && !strict_certs ) {
        //    int cb = verify_cb(&trust_options, RETVAL, csc);
        //    RETVAL = cb;
        //}
        X509_STORE_CTX_free(csc);

        if (!RETVAL)
            croak("verify: %s", ctx_error(csc));

    OUTPUT:

        RETVAL

void DESTROY(store)
    Crypt::OpenSSL::Verify store;

    PPCODE:

        if (store)
            X509_STORE_free(store);
        store = 0;


#if OPENSSL_API_COMPAT >= 0x10100000L
void __X509_cleanup(void)

    PPCODE:
        /* deinitialisation is done automatically */

#else
void __X509_cleanup(void)

    PPCODE:

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_state(0);
    EVP_cleanup();

#endif

