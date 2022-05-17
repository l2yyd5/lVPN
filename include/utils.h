#ifndef UTILS_H
#define UTILS_H

#include <logging.h>

#include <cassert>
#include <crypt.h>
#include <cstring>
#include <errno.h>
#include <iostream>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <shadow.h>
#include <sys/socket.h>
#include <unistd.h>

const size_t MAX_EVENTS = 256;
const size_t BUFFER_SIZE = 2048;

int verifyInfo(const std::string &username, const std::string &password);

class tlsTool {
public:
  explicit tlsTool(int fd, SSL *ssl = nullptr);
  ~tlsTool();

  int getFd() { return _fd; }

  int readSSL(char *buf);
  int writeSSL(const char *buf, size_t len);

  bool isConnected() { return _sslConnected; }
  bool isVerified() { return _loginVerified; }

  void setState(int n) {
    switch (n) {
    case 0:
      _sslConnected = _loginVerified = false;
      break;
    case 1:
      _sslConnected = true;
      _loginVerified = false;
      break;
    case 2:
      _sslConnected = _loginVerified = true;
      break;
    default:
      _sslConnected = _loginVerified = false;
    }
  }

private:
  int _fd;
  SSL *_ssl;
  bool _sslConnected;
  bool _loginVerified;
};

#endif