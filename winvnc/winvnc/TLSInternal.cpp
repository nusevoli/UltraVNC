#include "TLSInternal.h"
#include "stdhdrs.h"
#include "vsocket.h"

#define CERT_FILE	"C:\\key\\tls\\certs\\socam.crt"
#define KEY_FILE	"C:\\key\\tls\\private\\socam.key"

TLSInternal::TLSInternal()
	: ctx(NULL)
	, ssl(NULL)
	, meth(NULL)

{
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
}


TLSInternal::~TLSInternal()
{
}


void TLSInternal::beforeListen(VSocket* sock)
{
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);

	if (!ctx) {
		vnclog.Print(LL_SOCKINFO, VNCLOG("%s:%d> %s\n"), __FUNCTION__, __LINE__, ERR_error_string(ERR_peek_last_error(), NULL));
	}

	if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
		vnclog.Print(LL_SOCKINFO, VNCLOG("%s:%d> %s\n"), __FUNCTION__, __LINE__, ERR_error_string(ERR_peek_last_error(), NULL));
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
		vnclog.Print(LL_SOCKINFO, VNCLOG("%s:%d> %s\n"), __FUNCTION__, __LINE__, ERR_error_string(ERR_peek_last_error(), NULL));
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		vnclog.Print(LL_SOCKINFO, VNCLOG("%s:%d> %s\n"), __FUNCTION__, __LINE__, ERR_error_string(ERR_peek_last_error(), NULL));
	}
}


void TLSInternal::afterAccept(VSocket* listen, VSocket* client)
{
	ctx = listen->tls->ctx;

	ssl = SSL_new(ctx);
	if (!ssl)
	{
		vnclog.Print(LL_SOCKINFO, VNCLOG("%s:%d> %s\n"), __FUNCTION__, __LINE__, ERR_error_string(ERR_peek_last_error(), NULL));
	}
	SSL_set_fd(ssl, client->sock);

	const int err = SSL_accept(ssl);

	vnclog.Print(LL_SOCKINFO, VNCLOG("%s:%d> %s\n"), __FUNCTION__, __LINE__, SSL_get_cipher(ssl));

	X509* client_cert = SSL_get_peer_certificate(ssl);

	if (client_cert)
	{
		char* str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
		if (str)
		{
			vnclog.Print(LL_SOCKINFO, VNCLOG("%s:%d> %s\n"), __FUNCTION__, __LINE__, str);
			OPENSSL_free(str);
		}

		str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
		if (str)
		{
			vnclog.Print(LL_SOCKINFO, VNCLOG("%s:%d> %s\n"), __FUNCTION__, __LINE__, str);
			OPENSSL_free(str);
		}

		X509_free(client_cert);
	}
	else
	{
		vnclog.Print(LL_SOCKINFO, VNCLOG("%s:%d> %s\n"), __FUNCTION__, __LINE__, "Client does not have certificate.");
	}
}


VBool TLSInternal::Close()
{
	SSL_free(ssl);
	
	return VTrue;
}


// https://cpp.hotexamples.com/examples/-/-/SSL_shutdown/cpp-ssl_shutdown-function-examples.html
VBool TLSInternal::Shutdown()
{
	int mode = SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN;
	SSL_set_shutdown(ssl, mode);

	return VTrue;
}

int TLSInternal::Send(char* buf, unsigned int len)
{
	const int written = SSL_write(ssl, buf, len);

	vnclog.Print(LL_SOCKINFO, VNCLOG("%s> %d\n"), __FUNCTION__, written);

	return written;
}

int TLSInternal::Read(char* buf, unsigned int len)
{
	const int read_ = SSL_read(ssl, buf, len);

	vnclog.Print(LL_SOCKINFO, VNCLOG("%s> %d\n"), __FUNCTION__, read_);

	return read_;
}



void TLSInternal::FreeSSLContext()
{
	if (ctx)
	{
		SSL_CTX_free(ctx);
	}	
}