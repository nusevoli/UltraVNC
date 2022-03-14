#pragma once

#include "vtypes.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

class VSocket;

class TLSInternal
{
	SSL_CTX* ctx;
	SSL* ssl;
	const SSL_METHOD* meth;

public:
	TLSInternal();
	virtual ~TLSInternal();

	void beforeListen(VSocket* sock);
	void afterAccept(VSocket* listen, VSocket* client);

	VBool Close();
	VBool Shutdown();

	int Send(char* buf, unsigned int len);
	int Read(char* buf, unsigned int len);

	void FreeSSLContext();

/*	
	VBool Connect(const VString address, const VCard port);

	VBool Listen();
	VSocket* Accept();
*/



};

