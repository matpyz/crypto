// Copyright (c) 2015 Mateusz Pyzik, all rights reserved.
#pragma once

#include <cstdio>
#include <string>

class Keystore
{
public:
	Keystore(const char *path, const char *algo);

	void setMode(const char *mode);

	void createKey(const char *keyIdentifier, std::string password);

	void loadKey(const char *keyIdentifier, std::string password);

	void cipher(std::FILE *ifp, std::FILE *ofp, int enc);

	~Keystore();

private:
	struct Row
	{
		unsigned char hash[32];
		unsigned char pass[32];
		unsigned char key[48];
	};

	std::string path_, algo_, mode_;
	unsigned char key_[48];
};