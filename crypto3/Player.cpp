#include <sstream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <openssl/sha.h>
#include "Builtin.hpp"
#include "Echo.hpp"

using namespace std;

void install(string keystore, string identifier, string password, string pin, FILE *config)
{
	unsigned char hash[32];
	SHA256((unsigned char *)pin.c_str(), (int)pin.size(), hash);
	fwrite(hash, 32, 1, config);
	string message = keystore + '\n' + identifier + '\n' + password + '\n';
	builtinEncrypt((const unsigned char *)message.c_str(), (int)message.size(), config);
	fclose(config);
}

void play(string pin, FILE *config, string file)
{
	unsigned char hashOld[32], hashNew[32];
	fread(hashOld, 32, 1, config);
	SHA256((unsigned char *)pin.c_str(), (int)pin.size(), hashNew);
	string message = builtinDecrypt(config);
	fclose(config);
	istringstream stream(message);
	string keystore, identifier, password;
	getline(stream, keystore);
	getline(stream, identifier);
	getline(stream, password);
	string args = keystore + ' ' + identifier + ' ' + file;
	string command = "echo -n " + password + " | ./cipher dec aes ctr " + args + " - | mplayer -";
	system(command.c_str());
}

int main(int argc, const char *argv[])
{
	FILE *config;
	string pin;
	if(argc == 2) // play
	{
		config = fopen("config.bin", "rb");
		string file = argv[1];
		setEcho(false);
		getline(cin, pin);
		setEcho(true);
		play(pin, config, file);
	}
	else if(argc == 3) // install
	{
		config = fopen("config.bin", "wb");
		string keystore = argv[1];
		string identifier = argv[2];
		string password;
		setEcho(false);
		getline(cin, password);
		getline(cin, pin);
		setEcho(true);
		install(keystore, identifier, password, pin, config);
	}
	return 0;
}