#pragma once

#include "vtypes.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string>

class VSocket;

class TLSInternal
{
	SSL_CTX* ctx;
	SSL* ssl;
	const SSL_METHOD* meth;
	X509* cert;
	EVP_PKEY* pkey;

public:
	TLSInternal();
	virtual ~TLSInternal();

	bool beforeListen(VSocket* sock);
	void afterAccept(VSocket* listen, VSocket* client);

	VBool Close();
	VBool Shutdown();

	int Send(char* buf, unsigned int len);
	int Read(char* buf, unsigned int len);

	void FreeSSLContext();

	bool generateX509();

};

