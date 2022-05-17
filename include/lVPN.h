#ifndef LVPN_H
#define LVPN_H

#include <Epoll.h>
#include <config.h>
#include <utils.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <memory>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <set>
#include <sys/ioctl.h>
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
  using EpollPtr = std::unique_ptr<Epoll>;
  using listenPtr = std::unique_ptr<tlsTool>;
  using fdMap = std::unordered_map<string, tlsTool *>;
  using IPMap = std::unordered_map<int, string>;

  explicit lVPNsrv(lConfig::serverConfig scfg, LNET::AsyncLogging *log);
  ~lVPNsrv();

  void run();

  friend int createTunDevice();

private:
  void _acceptConnection();
  void _closeConnection(tlsTool *tool);
  void _handleSSLRead(tlsTool *tool);
  void _handleTunRead();

  int _listenFd;
  int _tunFd;
  char _tAddr[5];

  std::set<in_addr_t> _tunIdSet;
  lConfig::serverConfig _scfg;
  listenPtr _listenTCP;
  listenPtr _listenTun;
  EpollPtr _epoll;
  fdMap _fdMap;
  IPMap _ipMap;
  IPMap _tunIPMap;
  LNET::AsyncLogging *_asynclog;
};

#endif