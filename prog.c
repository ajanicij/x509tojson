#include <stdio.h>
#include <json/json.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

json_object *Parse_CertInfo(X509_CINF *cert_info);
json_object *Parse_X509_algor(X509_ALGOR *algor);

void
error_exit(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(-1);
}

void
errno_exit(const char *fmt, ...)
{
    int errno_keep = errno;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, ": %s\n", strerror(errno_keep));
    exit(-1);
}

void
sslerror(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    ERR_print_errors_fp(stderr);
    exit(-1);
}

void
usage()
{
    fprintf(stderr,
"x509tojson\n"
"Reads certificate from a PEM file and outputs it in JSON format\n"
"Usage: x509tojson <certificate>\n"
    );
    exit(0);
}

json_object *ParseX509(X509 *cert)
{
    json_object *jobj = json_object_new_object();
    assert(jobj);

    json_object *jo_cinfo = Parse_CertInfo(cert->cert_info);
    json_object_object_add(jobj,"cert_info", jo_cinfo);

    // sig_alg
    if (cert->sig_alg != NULL) {
        json_object *jo_sig_alg = Parse_X509_algor(cert->sig_alg);
        json_object_object_add(jobj, "sig_alg", jo_sig_alg);
    }

    return jobj;
}

json_object *
Parse_version(ASN1_INTEGER *version)
{
    int nVersion = ASN1_INTEGER_get(version);
    char strVersion[32];
    snprintf(strVersion, sizeof(strVersion), "%d", nVersion);
    json_object *jobj = json_object_new_string(strVersion);
    return jobj;
}

json_object *
Parse_serialNumber(ASN1_INTEGER *serialNumber)
{
    BIGNUM *bnser = ASN1_INTEGER_to_BN(serialNumber, NULL);
    char *serialNumber_hex = BN_bn2hex(bnser);
    json_object *jobj =
        json_object_new_string(serialNumber_hex);
    return jobj;
}

json_object *
Parse_signature(X509_ALGOR *signature)
{
    json_object *jobj_signature = json_object_new_object();
    int nid = OBJ_obj2nid(signature->algorithm);
    if (nid != 0) {
        const char *str = OBJ_nid2ln(nid);
        json_object *jstring_signature_algorithm_nid_ln =
        json_object_new_string(str);
        json_object_object_add(jobj_signature, "ln",
            jstring_signature_algorithm_nid_ln);

        str = OBJ_nid2sn(nid);
        json_object *jstring_signature_algorithm_nid_sn =
        json_object_new_string(str);
        json_object_object_add(jobj_signature, "sn",
        jstring_signature_algorithm_nid_sn);
        return jobj_signature;
    }
}

json_object *
Parse_rdns(X509_NAME *sn)
{
    int i, n;
    json_object *jarray = json_object_new_array();
    int entries = X509_NAME_entry_count(sn);

    for (i = 0; i < entries; i++) {
        X509_NAME_ENTRY *e = X509_NAME_get_entry(sn, i);
        ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
        char *str = ASN1_STRING_data(d);
        n = OBJ_obj2nid(X509_NAME_ENTRY_get_object(e));
        const char *sn2 = OBJ_nid2sn(n);
        if (sn2 == NULL) sn2 = "<unknown>";
        json_object *jstring = json_object_new_string(str);
        json_object *jo_rdn = json_object_new_object();
        json_object_object_add(jo_rdn, sn2, jstring);
        json_object_array_add(jarray,jo_rdn);
    }
    return jarray;
}

json_object *
Parse_sn(X509_NAME *sn)
{
    json_object *jobj = json_object_new_object();
    char *strSn = X509_NAME_oneline(sn, NULL, 0);
    if (strSn != NULL) {
        json_object *jstring_sn =
            json_object_new_string(strSn);
        json_object_object_add(jobj, "sn", jstring_sn);
        json_object *jo_rdns = Parse_rdns(sn);
        json_object_object_add(jobj, "rdns", jo_rdns);
        return jobj;
    }
    return NULL;
}

json_object *
Parse_time(ASN1_TIME *t)
{
    BIO *bio = BIO_new(BIO_s_mem());
    int res = ASN1_TIME_print(bio, t);
    if (res <= 0)
        return NULL;
    char *buf;
    res = BIO_get_mem_data(bio, &buf);
    assert(res > 0);
    json_object *jobj = json_object_new_string(buf);
    BIO_free(bio);
    return jobj;
}

json_object *
Parse_validity(X509_VAL *validity)
{
    json_object *jobj = json_object_new_object();
    json_object *jo_notBefore = Parse_time(validity->notBefore);
    json_object_object_add(jobj, "notBefore", jo_notBefore);
    json_object *jo_notAfter = Parse_time(validity->notAfter);
    json_object_object_add(jobj, "notAfter", jo_notAfter);
    return jobj;
}

json_object *
Parse_ASN1_OBJECT(ASN1_OBJECT *object)
{
    json_object *jobj = json_object_new_object();
    int nid = OBJ_obj2nid(object);
    if (nid != 0) {
        const char *str = OBJ_nid2ln(nid);
        json_object *jstring_ln =
            json_object_new_string(str);
        json_object_object_add(jobj, "ln",
            jstring_ln);

        str = OBJ_nid2sn(nid);
        json_object *jstring_sn =
            json_object_new_string(str);
        json_object_object_add(jobj, "sn",
            jstring_sn);
    }
    return jobj;
}

json_object *
Parse_asn1_type(ASN1_TYPE *type)
{
    json_object *jobj = json_object_new_object();
    char buf[32];
    snprintf(buf, sizeof(buf), "%d", type->type);
    json_object *jstring_type = json_object_new_string(buf);
    json_object_object_add(jobj, "type", jstring_type);

    json_object *jotmp;
    ASN1_OBJECT *value_object;
    char *key;

    switch (type->type) {
        case V_ASN1_OBJECT:
            value_object = type->value.object;
            jotmp = Parse_ASN1_OBJECT(value_object);
            key = "object";
            break;
        case V_ASN1_NULL:
            jotmp = NULL;
            break;
        default:
            jotmp = json_object_new_object();
            key = "other";
            break;
    }
    if (jotmp != NULL) {
        json_object_object_add(jobj, key, jotmp);
    }
    return jobj;
}

json_object *
Parse_X509_algor(X509_ALGOR *algor)
{
    // struct X509_algor_st {
    //   ASN1_OBJECT *algorithm;
    //   ASN1_TYPE *parameter;
    // } /* X509_ALGOR */ ;
    json_object *jobj = json_object_new_object();
    json_object *jo_algorithm = Parse_ASN1_OBJECT(algor->algorithm);
    json_object_object_add(jobj, "algorithm", jo_algorithm);
    if (algor->parameter != NULL) {
        json_object *jo_parameter = Parse_asn1_type(algor->parameter);
        json_object_object_add(jobj, "parameter", jo_parameter);
    }
    return jobj;
}

json_object *
Parse_int(int x)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%d", x);
    json_object *jstring = json_object_new_string(buf);
    return jstring;
}

json_object *
Parse_data(unsigned char *data, int len)
{
    char *str = (char *) OPENSSL_malloc(len * 3 + 1);
    memset(str, 0, (len * 3 + 1));
    int i;
    char *pch = str;
    int first = 1;
    for (i = 0; i < len; i++, pch += 2) {
        if (!first)
        {
            sprintf(pch, ":");
            pch++;
        }
        sprintf(pch, "%02X", data[i]);
        first = 0;
    }
    json_object *jstring = json_object_new_string(str);
    OPENSSL_free(str);
    return jstring;
}

json_object *
Parse_ASN1_BIT_STRING(ASN1_BIT_STRING *bstr)
{
    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "type", Parse_int(bstr->type));
    json_object_object_add(jobj, "data",
        Parse_data(bstr->data, bstr->length));
    json_object_object_add(jobj, "flags", Parse_int(bstr->flags));
    return jobj;
}

json_object *
Parse_EVP_PKEY(EVP_PKEY *pkey)
{
    unsigned char *buf = NULL;
    int len;
    len = i2d_PUBKEY(pkey, NULL);
    if (len <= 0)
        return json_object_new_object();
    buf = (unsigned char *) OPENSSL_malloc(len);
    i2d_PUBKEY(pkey, &buf);
    json_object *jobj = Parse_data(buf, len);
    OPENSSL_free(buf);
    return jobj;
}

json_object *
Parse_x509_pubkey(X509_PUBKEY *pubkey)
{
    // typedef struct X509_pubkey_st X509_PUBKEY;
    // struct X509_pubkey_st {
    //      X509_ALGOR *algor;
    //      ASN1_BIT_STRING *public_key;
    //      EVP_PKEY *pkey;
    // };
    json_object *jobj = json_object_new_object();
    json_object *jo_algor = Parse_X509_algor(pubkey->algor);
    json_object_object_add(jobj, "algor", jo_algor);

    json_object *jo_public_key = Parse_ASN1_BIT_STRING(pubkey->public_key);
    json_object_object_add(jobj, "public_key", jo_public_key);

    json_object_object_add(jobj, "pkey", Parse_EVP_PKEY(pubkey->pkey));

    return jobj;
}

json_object *
Parse_ASN1_OCTET_STRING(ASN1_OCTET_STRING *os)
{
    // ASN1_OCTET_STRING is defined as ASN1_STRING.

    BIO *bio = BIO_new(BIO_s_mem());
    int res = ASN1_STRING_print(bio, os);
    if (res <= 0)
        return NULL;
    char *buf;
    res = BIO_get_mem_data(bio, &buf);
    assert(res > 0);
    json_object *jobj = json_object_new_string(buf);
    BIO_free(bio);
    return jobj;
}

json_object *
Parse_X509_EXTENSION_inner(X509_EXTENSION *extension)
{
    void *ext_str = NULL;
    char *value = NULL;
    const unsigned char *p;
    const X509V3_EXT_METHOD *method;
    STACK_OF(CONF_VALUE) *nval = NULL;

    json_object *jarray = json_object_new_array();
    method = X509V3_EXT_get(extension);
    if (method == NULL) // unknown extension.
        return jarray;
    p = extension->value->data;
    if (method->it)
        ext_str =
            ASN1_item_d2i(NULL, &p, extension->value->length,
                ASN1_ITEM_ptr(method->it));
    else
        ext_str = method->d2i(NULL, &p, extension->value->length);
    if (ext_str == NULL) // Getting extension data failed.
        return jarray;
    if (method->i2v != NULL)
        nval = method->i2v(method, ext_str, NULL);
    else if (method->i2r != NULL)
    {
        BIO *bio = BIO_new(BIO_s_mem());
        int res = method->i2r(method, ext_str, bio, 0 /* indent */);
        if (res)
        {
            char *buf;
            res = BIO_get_mem_data(bio, &buf);
            if (res > 0)
            {
                json_object *jobj = json_object_new_string(buf);
                json_object_array_add(jarray, jobj);
                BIO_free(bio);
            }
        }
        return jarray;
    }
    else
        return jarray;
    if (nval == NULL)
        return jarray;
    int i;
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++)
    {
        CONF_VALUE *conf = sk_CONF_VALUE_value(nval, i);
        json_object *jobj_name_value = json_object_new_object();
        json_object *jstring;
        const char *key = "";
        if (conf->name != NULL)
            key = conf->name;
        if (conf->value == NULL)
            jstring = json_object_new_string("");
        else
            jstring = json_object_new_string(conf->value);
        json_object_object_add(jobj_name_value, key, jstring);
        json_object_array_add(jarray, jobj_name_value);
    }
    return jarray;
}

json_object *
Parse_X509_EXTENSION(X509_EXTENSION *extension)
{
   // typedef struct X509_extension_st {
   //   ASN1_OBJECT *object;
   //   ASN1_BOOLEAN critical;
   //   ASN1_OCTET_STRING *value;
   // } X509_EXTENSION;
    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "object",
        Parse_ASN1_OBJECT(extension->object));
    json_object_object_add(jobj, "critical",
        Parse_int(X509_EXTENSION_get_critical(extension)));
    // TODO: value
    json_object_object_add(jobj, "value",
        Parse_X509_EXTENSION_inner(extension));
    return jobj;
}

json_object *
Parse_STACK_OF_X509_EXTENSION(STACK_OF(X509_EXTENSION) *extensions)
{
    json_object *jarray = json_object_new_array();
    int count = X509v3_get_ext_count(extensions);
    int i;
    for (i = 0; i < count; i++) {
        json_object *jo_extension = Parse_X509_EXTENSION(
            X509v3_get_ext(extensions, i));
        json_object_array_add(jarray, jo_extension);
    }
    return jarray;
}

json_object *Parse_CertInfo(X509_CINF *cert_info)
{
    int res;
    const char *str;
    int nid;

    json_object *jobj = json_object_new_object();
    assert(jobj);

    json_object *jotmp;

    // version
    jotmp = Parse_version(cert_info->version);
    json_object_object_add(jobj, "version", jotmp);

    // serialNumber
    jotmp = Parse_serialNumber(cert_info->serialNumber);
    json_object_object_add(jobj, "serialNumber", jotmp);

    // signature
    jotmp = Parse_signature(cert_info->signature);
    json_object_object_add(jobj, "signature", jotmp);

    // TODO: signature->parameter

    // issuer
    jotmp = Parse_sn(cert_info->issuer);
    if (jotmp != NULL)
        json_object_object_add(jobj, "issuer", jotmp);

    // validity
    jotmp = Parse_validity(cert_info->validity);
    json_object_object_add(jobj, "validity", jotmp);

    // subject
    jotmp = Parse_sn(cert_info->subject);
    if (jotmp != NULL)
        json_object_object_add(jobj, "subject", jotmp);

    // key
    // typedef struct X509_pubkey_st X509_PUBKEY;
    // struct X509_pubkey_st {
    //      X509_ALGOR *algor;
    //      ASN1_BIT_STRING *public_key;
    //      EVP_PKEY *pkey;
    // };
    jotmp = Parse_x509_pubkey(cert_info->key);
    json_object_object_add(jobj, "key", jotmp);

    if (cert_info->issuerUID != NULL) {
        json_object_object_add(jobj, "issuerUID",
            Parse_ASN1_BIT_STRING(cert_info->issuerUID));
    }

    if (cert_info->subjectUID != NULL) {
        json_object_object_add(jobj, "subjectUID",
            Parse_ASN1_BIT_STRING(cert_info->subjectUID));
    }

    // extensions
    if (cert_info->extensions != NULL) {
        json_object_object_add(jobj, "extensions",
            Parse_STACK_OF_X509_EXTENSION(cert_info->extensions));
    }

    return jobj;
}

int
main(int argc, char **argv)
{
    if (argc < 2)
        usage();

    // Initialize OpenSSL.
    SSL_load_error_strings();
    SSL_library_init();

    char *certfile = argv[1];
    FILE *fp = fopen(certfile, "rb");
    if (fp == NULL)
        errno_exit("Error opening file %s", certfile);
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (cert == NULL)
        sslerror("Error reading certificate");

    json_object *jobj = ParseX509(cert);
    if (jobj == NULL) {
        fprintf(stderr, "Error in ParseX509\n");
        goto End;
    }
    const char *str = json_object_to_json_string(jobj);
    printf("%s\n", str);

End:
    if (fp != NULL)
        fclose(fp);
    return 0;
}
