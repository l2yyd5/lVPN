#include <lVPN.h>

const SSL_METHOD *g_meth;
SSL_CTX *g_sslCtx;

int createTunDevice(const lConfig::serverConfig &scfg) {
  int tunfd;
  struct ifreq ifr;
  int ret;

  ::memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

  tunfd = ::open("/dev/net/tun", O_RDWR);
  if (tunfd == -1) {
    LOG_INFO << "Open TUN failed! (" << errno << ": " << ::strerror(errno)
             << "\n";
    return -1;
  }

  ret = ::ioctl(tunfd, TUNSETIFF, &ifr);
  if (ret == -1) {
    LOG_INFO << "Setup TUN interface by ioctl failed! (" << errno << ": "
             << ::strerror(errno) << "\n";
    return -1;
  }
  LOG_INFO << "Create a tun device :" << ifr.ifr_name << "\n";

  string tunName = string(ifr.ifr_name);
  string cmd = "";
  cmd += "sudo ifconfig " + tunName;
  cmd += " " + scfg.tunAddr + "/" + scfg.tunMask + " up";
  system(cmd.c_str());
  LOG_INFO << cmd << "\n";

  return tunfd;
}

int tlsInit(const lConfig::serverConfig &scfg) {
  SSL_load_error_strings();
  int r = SSL_library_init();
  if (!r) {
    LOG_INFO << "SSL_library_init failed\n";
  }
  SSLeay_add_ssl_algorithms();

  g_meth = TLS_server_method();
  g_sslCtx = SSL_CTX_new(g_meth);
  SSL_CTX_set_verify(g_sslCtx, SSL_VERIFY_NONE, NULL);
  SSL_CTX_load_verify_locations(g_sslCtx, scfg.tls_config.caCert.c_str(), NULL);

  if (SSL_CTX_use_certificate_file(g_sslCtx, scfg.tls_config.serverCert.c_str(),
                                   SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    return 3;
  }
  if (SSL_CTX_use_PrivateKey_file(g_sslCtx, scfg.tls_config.serverKey.c_str(),
                                  SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    return 4;
  }
  if (!SSL_CTX_check_private_key(g_sslCtx)) {
    LOG_INFO << "Private key does not match the certificate public key\n";
    return 5;
  }

  return 0;
}

int setupTCPServer(const lConfig::serverConfig &scfg) {
  sockaddr_in sa_server;
  int listen_sock;
  in_addr_t sAddr = 0;
  ::inet_pton(AF_INET, scfg.listenAddr.c_str(), &sAddr);

  listen_sock = ::socket(PF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
  if (listen_sock < 0) {
    LOG_INFO << "Server: socket error!\n";
    exit(0);
  }
  ::memset(&sa_server, '\0', sizeof(sa_server));
  sa_server.sin_family = AF_INET;
  sa_server.sin_addr.s_addr = sAddr;
  sa_server.sin_port = htons(scfg.listenPort);
  int err =
      ::bind(listen_sock, (struct sockaddr *)&sa_server, sizeof(sa_server));

  if (err < 0) {
    LOG_INFO << "Server: bind error!\n";
    exit(0);
  }
  err = ::listen(listen_sock, 5);
  if (err < 0) {
    LOG_INFO << "Server: listen error!\n";
    exit(0);
  }
  return listen_sock;
}

lVPNsrv::lVPNsrv(lConfig::serverConfig scfg, LNET::AsyncLogging *log)
    : _scfg(scfg), _tunFd(createTunDevice(scfg)),
      _listenFd(setupTCPServer(scfg)), _asynclog(log),
      _listenTCP(new tlsTool(_listenFd)), _listenTun(new tlsTool(_tunFd)),
      _epoll(new Epoll) {
  assert(_listenFd >= 0);
  assert(_tunFd >= 0);

  in_addr_t tmp;
  ::inet_pton(AF_INET, scfg.tunAddr.c_str(), &_tAddr);
  memcpy(&tmp, _tAddr, 4);
  for (int i = 2; i <= 250; i++) {
    _tunIdSet.insert((i << 24) + tmp);
  }
  tlsInit(_scfg);
}

lVPNsrv::~lVPNsrv() {
  ::close(_listenFd);
  SSL_CTX_free(g_sslCtx);
  _asynclog->stop();
}

void lVPNsrv::_acceptConnection() {
  sockaddr_in clientAddr{};
  socklen_t len = sizeof(clientAddr);
  int acceptFd;
  while ((acceptFd =
              ::accept(_listenFd, (struct sockaddr *)&clientAddr, &len)) < 0 &&
         errno == EINTR)
    ;

  if (acceptFd == -1) {
    LOG_INFO << "Accept error!\n";
  } else {
    SSL *tmpSSL = SSL_new(g_sslCtx);
    SSL_set_fd(tmpSSL, acceptFd);
    int err = SSL_accept(tmpSSL);
    if (err <= 0) {
      LOG_INFO << "Can't complete SSL connection " << SSL_get_error(tmpSSL, err)
               << "\n";
      ERR_print_errors_fp(stderr);
    } else {
      tlsTool *tool = new tlsTool(acceptFd, tmpSSL);

      char clientIP[INET_ADDRSTRLEN];
      ::inet_ntop(AF_INET, &clientAddr.sin_addr.s_addr, clientIP,
                  sizeof(clientIP));
      _ipMap[acceptFd] = clientIP;
      ::fcntl(acceptFd, F_SETFL, fcntl(acceptFd, F_GETFL, 0) | O_NONBLOCK);
      _epoll->add(acceptFd, tool, EPOLLIN);
      tool->setState(1);
      LOG_INFO << "Accept from " << clientIP << ". Complete SSL connection\n";
    }
  }
}

void lVPNsrv::_closeConnection(tlsTool *tool) {
  int fd = tool->getFd();
  _epoll->del(fd, tool, 0);

  auto it = _tunIPMap.find(fd);
  if (it != _tunIPMap.end()) {
    string clientIP = _tunIPMap[fd];
    in_addr_t tmp;
    ::inet_pton(AF_INET, clientIP.c_str(), &tmp);
    _tunIPMap.erase(fd);
    _fdMap.erase(clientIP);
    _tunIdSet.insert(tmp);
  }
  it = _ipMap.find(fd);
  if (it != _ipMap.end()) {
    _ipMap.erase(fd);
  }

  delete tool;
  tool = nullptr;
}

void lVPNsrv::_handleSSLRead(tlsTool *tool) {
  int fd = tool->getFd();
  char buffer[BUFFER_SIZE];
  int len = tool->readSSL(buffer);
  if (len == 0 || (len < 0) && (errno != EAGAIN)) {
    LOG_INFO << "close socket fd: " << fd << "\n";
    _closeConnection(tool);
    return;
  }
  if (!tool->isVerified()) {
    if (len <= 20) {
      string errorMessage =
          "Authentication information from " + _ipMap[fd] + " error.\n";
      LOG_INFO << errorMessage;
      char retErr = static_cast<char>(errorCode::INFORMATION_ERROR);
      tool->writeSSL(&retErr, 1);
      return;
    }
    try {
      auto info = json::parse(buffer, buffer + len);
      string username = info["username"];
      string password = info["password"];
      int ret = verifyInfo(username, password);
      if (ret == -1) {
        LOG_INFO << "Wrong user name or password. " << _ipMap[fd] << "\n";
        char retErr = static_cast<char>(errorCode::AUTHENTICATION_FAILED);
        tool->writeSSL(&retErr, 1);
      } else {
        LOG_INFO << _ipMap[fd] << " succeeded login.\n";
        string retMsg = "";
        retMsg += static_cast<char>(errorCode::LOGIN_SUCCEEDED);
        char tmpIP[INET_ADDRSTRLEN];
        ::inet_ntop(AF_INET, &*_tunIdSet.begin(), tmpIP, sizeof(tmpIP));
        retMsg += tmpIP;
        _tunIPMap[fd] = tmpIP;
        _fdMap[tmpIP] = tool;

        tool->writeSSL(retMsg.c_str(), retMsg.length());
        tool->setState(2);
        _tunIdSet.erase(_tunIdSet.begin());
      }
    } catch (json::parse_error &ex) {
      string errorMessage = "Authentication information from " + _ipMap[fd] +
                            " error. " + ex.what() + "\n";
      LOG_INFO << errorMessage;
      LOG_INFO << buffer << "\n";
      char retErr = static_cast<char>(errorCode::INFORMATION_ERROR);
      tool->writeSSL(&retErr, 1);
    }
  } else {
    LOG_INFO << "Got a packet from the tunnel. Received " << len
             << " bytes data from " << _ipMap[fd] << "\n";
    write(_tunFd, buffer, len);
  }
}

void lVPNsrv::_handleTunRead() {
  char buff[BUFFER_SIZE];
  int len = read(_tunFd, buff, BUFFER_SIZE);
  if (len >= 20) {
    const void *peek = buff;
    const iphdr *_iphdr = static_cast<const iphdr *>(peek);

    char IPstr[INET_ADDRSTRLEN];
    ::inet_ntop(AF_INET, &_iphdr->daddr, IPstr, sizeof(IPstr));
    auto it = _fdMap.find(IPstr);
    if (it != _fdMap.end()) {
      auto tool = it->second;
      if (tool->isVerified()) {
        tool->writeSSL(buff, len);
      }
    }
    LOG_INFO << "Got a packet " << len << " bytes from Tun to " << IPstr
             << "\n";
  }
}

void lVPNsrv::run() {
  _epoll->add(_listenFd, _listenTCP.get(), EPOLLIN);
  _epoll->add(_tunFd, _listenTun.get(), EPOLLIN);

  _epoll->setNewConnection(std::bind(&lVPNsrv::_acceptConnection, this));
  _epoll->setHandleSSLRead(
      std::bind(&lVPNsrv::_handleSSLRead, this, std::placeholders::_1));
  _epoll->setHandleTunRead(std::bind(&lVPNsrv::_handleTunRead, this));
  _epoll->setCloseConnection(
      std::bind(&lVPNsrv::_closeConnection, this, std::placeholders::_1));

  while (1) {
    int eventsnum = _epoll->wait(-1);
    if (eventsnum > 0) {
      _epoll->handleEvents(_listenFd, _tunFd, eventsnum);
    }
  }
}