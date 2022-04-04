#include "TLSInternal.h"
#include "stdhdrs.h"
#include "vsocket.h"
#include <memory>

#define CERT_FILE	"C:\\key\\tls\\socam.crt"
#define KEY_FILE	"C:\\key\\tls\\socam.key"

TLSInternal::TLSInternal()
	: ctx(NULL)
	, ssl(NULL)
	, meth(NULL)
	, cert(NULL)
	, pkey(NULL)
{
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
}


TLSInternal::~TLSInternal()
{
	if (cert)
	{
		X509_free(cert);
		cert = NULL;
	}

	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}


bool TLSInternal::beforeListen(VSocket* sock)
{
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);

	if (!ctx) {
		vnclog.Print(LL_SOCKINFO, VNCLOG("%s:%d> %s\n"), __FUNCTION__, __LINE__, ERR_error_string(ERR_peek_last_error(), NULL));
		return false;
	}

#ifdef USE_CERT_AND_PKEY_FROM_FILE

	if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
		vnclog.Print(LL_SOCKINFO, VNCLOG("%s:%d> %s\n"), __FUNCTION__, __LINE__, ERR_error_string(ERR_peek_last_error(), NULL));
		return false;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
		vnclog.Print(LL_SOCKINFO, VNCLOG("%s:%d> %s\n"), __FUNCTION__, __LINE__, ERR_error_string(ERR_peek_last_error(), NULL));
		return false;
	}

#else

	if (! generateX509())
	{
		return false;
	}

	if (cert)
	{
		if (!SSL_CTX_use_certificate(ctx, cert))
		{
			vnclog.Print(LL_SOCKINFO, VNCLOG("%s:%d> %s\n"), __FUNCTION__, __LINE__, ERR_error_string(ERR_peek_last_error(), NULL));
			return false;
		}
	}

	if (pkey)
	{
		if (!SSL_CTX_use_PrivateKey(ctx, pkey))
		{
			vnclog.Print(LL_SOCKINFO, VNCLOG("%s:%d> %s\n"), __FUNCTION__, __LINE__, ERR_error_string(ERR_peek_last_error(), NULL));
			return false;
		}
	}

#endif // USE_CERT_AND_PKEY_FROM_FILE

	if (!SSL_CTX_check_private_key(ctx)) {
		vnclog.Print(LL_SOCKINFO, VNCLOG("%s:%d> %s\n"), __FUNCTION__, __LINE__, ERR_error_string(ERR_peek_last_error(), NULL));
		return false;
	}

	return true;
}

bool TLSInternal::generateX509()
{
	const unsigned char country[] = "KR";
	const unsigned char company[] = "Softcamp";
	const unsigned char common_name[] = "localhost";

	const long daysValid = 365;
	const int RSA_KEY_LENGTH = 4096;

	std::unique_ptr<RSA, void (*)(RSA*)> rsa{ RSA_new(), RSA_free };
	std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> bn{ BN_new(), BN_free };

	BN_set_word(bn.get(), RSA_F4);
	int rsa_ok = RSA_generate_key_ex(rsa.get(), RSA_KEY_LENGTH, bn.get(), nullptr);

	if (!rsa_ok)
	{
		vnclog.Print(LL_SOCKINFO, VNCLOG("%s:%d> %s\n"), __FUNCTION__, __LINE__, ERR_error_string(ERR_peek_last_error(), NULL));
		return false;
	}


	// --- cert generation ---
	cert = X509_new();
	pkey = EVP_PKEY_new();

	// The RSA structure will be automatically freed when the EVP_PKEY structure is freed.
	EVP_PKEY_assign(pkey, EVP_PKEY_RSA, reinterpret_cast<char*>(rsa.release()));
	ASN1_INTEGER_set(X509_get_serialNumber(cert), 1); // serial number

	X509_gmtime_adj(X509_get_notBefore(cert), 0); // now
	X509_gmtime_adj(X509_get_notAfter(cert), daysValid * 24 * 3600); // accepts secs

	X509_set_pubkey(cert, pkey);

	// 1 -- X509_NAME may disambig with wincrypt.h
	// 2 -- DO NO FREE the name internal pointer
	X509_name_st* name = X509_get_subject_name(cert);

	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, country, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, company, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, common_name, -1, -1, 0);

	X509_set_issuer_name(cert, name);
	X509_sign(cert, pkey, EVP_sha256());
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

	//vnclog.Print(LL_SOCKINFO, VNCLOG("%s> %d\n"), __FUNCTION__, written);

	return written;
}

int TLSInternal::Read(char* buf, unsigned int len)
{
	const int read_ = SSL_read(ssl, buf, len);

	//vnclog.Print(LL_SOCKINFO, VNCLOG("%s> %d\n"), __FUNCTION__, read_);

	return read_;
}



void TLSInternal::FreeSSLContext()
{
	if (ctx)
	{
		SSL_CTX_free(ctx);
	}	
}