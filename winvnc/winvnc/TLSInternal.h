#pragma once

#include "vtypes.h"

//#include <openssl/rsa.h>
//#include <openssl/pem.h>
//#include <openssl/err.h>

class TLSInternal
{
/*
	VBool Create();

	// https://cpp.hotexamples.com/examples/-/-/SSL_shutdown/cpp-ssl_shutdown-function-examples.html
	VBool Shutdown();
	// SSL_free (ssl);
	VBool Close();
	VBool Connect(const VString address, const VCard port);

	VBool Listen();
	VSocket* Accept();
*/



	/*
	*
	* �񶧸�...
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
* // Read�� �� �ϸ� �ɵ�.
	VInt Read(char* buff, const VCard bufflen);
	VBool
		VSocket::ReadExact(char* buff, const VCard bufflen)
		-> 
		Read(char* buff, const VCard bufflen)


		VBool
		VSocket::ReadSelect(VCard to)
		=> vnchttpconnect.cpp���� ���
*/
};

