#ifndef LVPN_H
#define LVPN_H

#include <config.h>
#include <logging.h>

#include <arpa/inet.h>
#include <cassert>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <iostream>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <memory>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

using json = nlohmann::json;

const size_t MAX_EVENTS = 16;
const size_t BUFFER_SIZE = 2048;

class lVPNclient : public LNET::noncopyable {
public:
  using EventList = std::vector<epoll_event>;
  explicit lVPNclient(lConfig::clientConfig ccfg, LNET::AsyncLogging *log);
  ~lVPNclient();

  void run();

private:
  void handleSSLRead();
  void handleTunRead();
  int handleEvents(int numEvents);

  int _epollFd;
  int _socketFd;
  int _tunFd;

  EventList _events;
  lConfig::clientConfig _ccfg;
  SSL *_ssl;
  string _tunIP;
  LNET::AsyncLogging *_asynclog;
};

#endif