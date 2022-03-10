#include "TLSInternal.h"

TLSInternal::TLSInternal()
	: ctx(NULL)
	, ssl(NULL)
	, client_cert(NULL)
	, meth(NULL)

{
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
}


TLSInternal::~TLSInternal()
{
}

VBool TLSInternal::Close()
{
	SSL_free(ssl);
	
	return VTrue;
}
