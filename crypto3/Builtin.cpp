#include "Builtin.hpp"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <random>

using namespace std;

const unsigned char *const key = (unsigned char *)"super secret builtin key";

void randomBits(unsigned char key[], size_t len)
{
	random_device dev;
	seed_seq seq({dev(), dev(), dev(), dev()});
	mt19937 mt;
	mt.seed(seq);
	len /= sizeof(unsigned);
	for(size_t i = 0; i < len; ++i)
		((unsigned *)key)[i] = mt();
}

void handleErrors()
{
	ERR_print_errors_fp(stderr);
	abort();
}

void builtinEncrypt(const unsigned char *message, int messageSize, FILE *config)
{
  unsigned char *out = new unsigned char[messageSize + 16], iv[16];
	int outl;

	EVP_CIPHER_CTX *ctx;
	
	randomBits(iv, 16);
	if(fwrite(iv, 16, 1, config) != 1)
	{
		fputs("write error\n", stderr);
		exit(1);
	}
	
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	if(1 != EVP_EncryptUpdate(ctx, out, &outl, message, messageSize))
		handleErrors();
	fwrite(out, 1, outl, config);

	if(1 != EVP_EncryptFinal_ex(ctx, out, &outl)) handleErrors();
	fwrite(out, 1, outl, config);

	EVP_CIPHER_CTX_free(ctx);
	
	EVP_cleanup();
	ERR_free_strings();
	
	delete[] out;
}

string builtinDecrypt(FILE *config)
{
  string result;
	unsigned char in[4096], out[4112], iv[16];
	int inl, outl;

	EVP_CIPHER_CTX *ctx;
	
	if(fread(iv, 16, 1, config) != 1)
	{
		fputs("read error\n", stderr);
		exit(1);
	}

	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	do
	{
		inl = (int)fread(in, 1, 4096, config);
		if(1 != EVP_DecryptUpdate(ctx, out, &outl, in, inl))
			handleErrors();
		result.append((const char *)out, outl);
	}
	while(inl == 4096);

	if(1 != EVP_DecryptFinal_ex(ctx, out, &outl)) handleErrors();
	result.append((const char *)out, outl);

	EVP_CIPHER_CTX_free(ctx);
	
	EVP_cleanup();
	ERR_free_strings();
  
  return result;
}
