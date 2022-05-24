#ifndef LVPN_H
#define LVPN_H

#include <Epoll.h>
#include <config.h>
#include <utils.h>

#include <arpa/inet.h>
#include <cassert>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <memory>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <set>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>

using json = nlohmann::json;

class lVPNsrv : public LNET::noncopyable {
public:
  enum errorCode {
    INFORMATION_ERROR = 1,
    AUTHENTICATION_FAILED,
    LOGIN_SUCCEEDED,
  };

public:
  using EpollPtr = std::unique_ptr<Epoll[]>;
  using IPMap = std::unordered_map<int, string>;
  using LoginMap = std::unordered_map<int, bool>;
  using SSLMap = std::unordered_map<int, SSL *>;
  using TunMap = std::unordered_map<string, int>;

  explicit lVPNsrv(lConfig::serverConfig scfg, LNET::AsyncLogging *log);
  ~lVPNsrv();

  void run();

  friend int createTunDevice();

private:
  void _acceptConnection(int);
  void _closeConnection(int);
  void _handleSSLRead(int);
  void _handleTunRead(int);

  void _tunThreadFunc();
  void _SSLThreadFunc();

  int _listenFd;
  int _tunFd;
  char _tAddr[5];

  std::set<in_addr_t> _tunIdSet;
  lConfig::serverConfig _scfg;
  EpollPtr _epoll;
  IPMap _ipMap;
  IPMap _tunIPMap;
  LoginMap _loginMap;
  SSLMap _SSLMap;
  TunMap _tunMap;
  std::thread _thread[2];
  LNET::AsyncLogging *_asynclog;
};

#endif