#ifndef UTILS_H
#define UTILS_H

#include <logging.h>

#include <crypt.h>
#include <cstring>
#include <iostream>
#include <shadow.h>

const size_t MAX_EVENTS = 256;
const size_t BUFFER_SIZE = 4096;

int verifyInfo(const std::string &username, const std::string &password);

#endif