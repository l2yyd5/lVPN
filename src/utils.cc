#include <utils.h>

int verifyInfo(const std::string &username, const std::string &password) {
  spwd *pw;
  std::string epassword = "";
  pw = ::getspnam(username.c_str());
  if (pw == nullptr) {
    return -1;
  }
  epassword = ::crypt(password.c_str(), pw->sp_pwdp);
  if (epassword != pw->sp_pwdp) {
    return -1;
  }
  return 1;
}

tlsTool::tlsTool(int fd, SSL *ssl)
    : _fd(fd), _ssl(ssl), _sslConnected(false), _loginVerified(false) {}

tlsTool::~tlsTool() {
  if (_ssl != nullptr) {
    SSL_shutdown(_ssl);
    SSL_free(_ssl);
  }
  close(_fd);
}

int tlsTool::readSSL(char *buf) {
  int ret = SSL_read(_ssl, buf, BUFFER_SIZE);

  if (ret == 0) {
    LOG_INFO << "Socket fd: " << _fd << ". Ssl link error!\n";
  } else if (ret < 0) {
    LOG_INFO << "Socket fd: " << _fd << ". Ssl read error!\n";
    LOG_INFO << "Socket fd: " << _fd << ". " << strerror(errno) << "\n";
  }

  return ret;
}

int tlsTool::writeSSL(const char *buf, size_t len) {
  int ret = SSL_write(_ssl, buf, len);

  if (ret == -1) {
    LOG_INFO << "Socket fd: " << _fd << "tls write error!\n";
  }

  return ret;
}