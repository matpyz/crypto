#pragma once
#include <string>

void builtinEncrypt(const unsigned char *message, int messageSize, FILE *config);
std::string builtinDecrypt(FILE *config);