// Copyright (c) 2015 Mateusz Pyzik, all rights reserved.
#include "Keystore.hpp"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/conf.h>
#include <algorithm>
#include <random>
#include <cstring>

using namespace std;

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

void userKeyFromPassword(const string &password, unsigned char userKey[32], unsigned char userIv[16])
{
	seed_seq seq(password.begin(), password.end());
	mt19937 mt;
	mt.seed(seq);
	for(size_t i = 0; i < 8; ++i)
		((unsigned *)userKey)[i] = mt();
	for(size_t i = 0; i < 4; ++i)
		((unsigned *)userIv)[i] = mt();
}

void handleErrors()
{
	ERR_print_errors_fp(stderr);
	abort();
}

int encryptKey(unsigned char *in, int inl, unsigned char *key,
			   unsigned char *iv, unsigned char *out, const EVP_CIPHER *cipher, int enc)
{
	EVP_CIPHER_CTX *ctx;
	int len, outl;

	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	if(1 != EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc))
		handleErrors();

	if(1 != EVP_CipherUpdate(ctx, out, &len, in, inl))
		handleErrors();
	outl = len;

	if(1 != EVP_CipherFinal_ex(ctx, out + len, &len)) handleErrors();
	outl += len;

	EVP_CIPHER_CTX_free(ctx);

	return outl;
}

void Keystore::cipher(FILE *ifp, FILE *ofp, int enc)
{
	unsigned char in[4096], out[4112], iv[16];
	int inl, outl, ivl = 16;

	const EVP_CIPHER *cipher;

	if(algo_ == "aes")
	{
		if(mode_ == "cbc")
			cipher = EVP_aes_256_cbc();
		else if(mode_ == "ctr")
			cipher = EVP_aes_256_ctr();
		else if(mode_ == "gcm")
		{
			cipher = EVP_aes_256_gcm();
			ivl = 12;
		}
		else
		{
			fputs("unsupported mode of operation\n", stderr);
			exit(1);
		}
	}
	else
	{
		fputs("unsupported cipher\n", stderr);
		exit(1);
	}

	EVP_CIPHER_CTX *ctx;

	if(enc == 1)
	{
		randomBits(iv, ivl);
		if(fwrite(iv, ivl, 1, ofp) != 1)
		{
			fputs("write error\n", stderr);
			exit(1);
		}
	}
	else if(fread(iv, ivl, 1, ifp) != 1)
	{
		fputs("read error\n", stderr);
		exit(1);
	}

	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	if(1 != EVP_CipherInit_ex(ctx, cipher, NULL, key_, iv, enc))
		handleErrors();

	do
	{
		inl = (int)fread(in, 1, 4096, ifp);
		if(1 != EVP_CipherUpdate(ctx, out, &outl, in, inl))
			handleErrors();
		fwrite(out, 1, outl, ofp);
	}
	while(inl == 4096);

	if(1 != EVP_CipherFinal_ex(ctx, out, &outl) && mode_ != "gcm") handleErrors();
	fwrite(out, 1, outl, ofp);

	EVP_CIPHER_CTX_free(ctx);
}

Keystore::Keystore(const char *path, const char *algo): path_(path), algo_(algo)
{
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
}

void Keystore::setMode(const char *mode)
{
	mode_ = mode;
}

void Keystore::createKey(const char *keyIdentifier, string password)
{
	unsigned char hash[32];
	Row row;
	int line = 0;
	FILE *file = fopen(path_.c_str(), "r+b");
	if(file == NULL)
	{
		fputs("keystore could not be opened\n", stderr);
		exit(1);
	}
	unsigned char userKey[32], userIv[16];
	SHA256((const unsigned char *)keyIdentifier, strlen(keyIdentifier), hash);
	while(fread(&row, sizeof row, 1, file) == 1)
	{
		if(equal(begin(hash), end(hash), row.hash))
		{
			fseek(file, -(long)(sizeof row), SEEK_CUR);
			break;
		}
		++line;
	}
	randomBits(key_, 32);
	userKeyFromPassword(password += to_string(line), userKey, userIv);
	memcpy(row.hash, hash, 32);
	SHA256((const unsigned char *)password.c_str(), password.size(), row.pass);
	encryptKey(key_, 32, userKey, userIv, row.key, EVP_aes_256_cbc(), 1);
	fwrite(&row, sizeof row, 1, file);
	fclose(file);
}

void Keystore::loadKey(const char *keyIdentifier, string password)
{
	unsigned char hash[32];
	Row row;
	int line = 0;
	FILE *file = fopen(path_.c_str(), "rb"); SHA256((const unsigned char *)keyIdentifier, strlen(keyIdentifier), hash);
	if(file == NULL)
	{
		fputs("keystore could not be opened\n", stderr);
		exit(1);
	}
	while(fread(&row, sizeof row, 1, file) == 1)
	{
		if(equal(begin(hash), end(hash), row.hash))
		{
			unsigned char userKey[32], userIv[16];
			userKeyFromPassword(password += to_string(line), userKey, userIv);
			SHA256((const unsigned char *)password.c_str(), password.size(), hash);
			if(equal(begin(hash), end(hash), row.pass))
			{
				encryptKey(row.key, 48, userKey, userIv, key_, EVP_aes_256_cbc(), 0);
				fclose(file);
				return;
			}
			fputs("wrong password\n", stderr);
			exit(1);
		}
		++line;
	}
	fputs("no such key in keystore\n", stderr);
	exit(1);
}

Keystore::~Keystore()
{
	EVP_cleanup();
	ERR_free_strings();
}