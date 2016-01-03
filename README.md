# x509tojson
Utility that reads an X.509 certificate and outputs it in JSON.

This utility uses OpenSSL for parsing a certificate and libjson for
generating JSON. It is mostly a product of my effort to learn OpenSSL.
That library is notorious for being poorly documented and the only
way to really learn how to use it is to learn by doing.

- Get the source release from openssl.org and unpack it.
- Read header files in include/openssl.
- Read source files in crypto and ssl.
- Read the sources for the sample application openssl in apps.

Since this project is just about parsing a certificate, the most useful
command of the openssl utility is x509:

    openssl x509 -in <certificate> -text

The source for it is in apps/x509.c.

Any comments, questions, patches or suggestions are welcome. Right now
this utility has only one purpose - learning about OpenSSL's API.
However, if there is interest it could turn into a library that can
be used from other programs.
