#pragma once

#include "vtypes.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

class TLSInternal
{
	SSL_CTX* ctx;
	SSL* ssl;
	X509* client_cert;
	SSL_METHOD* meth;

public:
	TLSInternal();
	~TLSInternal();

	// SSL_free (ssl);
	VBool Close();
/*
	VBool Create();

	// https://cpp.hotexamples.com/examples/-/-/SSL_shutdown/cpp-ssl_shutdown-function-examples.html
	VBool Shutdown();
	
	VBool Connect(const VString address, const VCard port);

	VBool Listen();
	VSocket* Accept();
*/



	/*
	*
	* 골때림...
VInt VSocket::Send(const char *buff, const VCard bufflen)
->
bool sendall(SOCKET RemoteSocket,char *buff,unsigned int bufflen,int dummy)



VInt
VSocket::SendQueued(const char *buff, const VCard bufflen)
->
sendall



VBool
VSocket::SendExact(const char *buff, const VCard bufflen, unsigned char msgType)
->
SendExact(buff, bufflen);



VBool
VSocket::SendExactQueue(const char *buff, const VCard bufflen, unsigned char msgType)
->
SendExactQueue(buff, bufflen);



VBool
VSocket::SendExact(const char *buff, const VCard bufflen)
->
Send(pBuffer, nBufflen);


VBool
VSocket::SendExactQueue(const char *buff, const VCard bufflen)
->
SendQueued(pBuffer, nBufflen);
	*/


/*
* // Read만 잘 하면 될듯.
	VInt Read(char* buff, const VCard bufflen);
	VBool
		VSocket::ReadExact(char* buff, const VCard bufflen)
		-> 
		Read(char* buff, const VCard bufflen)


		VBool
		VSocket::ReadSelect(VCard to)
		=> vnchttpconnect.cpp에서 사용
*/
};

