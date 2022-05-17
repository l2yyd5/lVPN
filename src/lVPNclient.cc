#include <lVPNclient.h>

const SSL_METHOD *g_meth;
SSL_CTX *g_sslCtx;

void verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
  char buf[300];
  X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);

  X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
  LOG_INFO << "Subject = " << buf << ".\n";

  if (preverify_ok == 1) {
    LOG_INFO << "Verification passed.\n";
  } else {
    int err = X509_STORE_CTX_get_error(x509_ctx);
    LOG_INFO << "Verification failed: " << X509_verify_cert_error_string(err)
             << "\n";
  }
}

SSL *setupTLSClient(const lConfig::clientConfig &ccfg) {
  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  SSL *ssl;

  g_meth = TLS_client_method();
  g_sslCtx = SSL_CTX_new(g_meth);

  SSL_CTX_set_verify(g_sslCtx, SSL_VERIFY_NONE, NULL);
  if (SSL_CTX_use_certificate_file(g_sslCtx, ccfg.tls_config.clientCert.c_str(),
                                   SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(-2);
  }
  if (SSL_CTX_use_PrivateKey_file(g_sslCtx, ccfg.tls_config.clientKey.c_str(),
                                  SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(-3);
  }
  if (!SSL_CTX_check_private_key(g_sslCtx)) {
    LOG_INFO << "Private key does not match the certificate public keyn\n";
    exit(-4);
  }
  ssl = SSL_new(g_sslCtx);
  X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
  X509_VERIFY_PARAM_set1_host(vpm, ccfg.serverHostName.c_str(), 0);

  return ssl;
}

int setupTCPClient(const lConfig::clientConfig &ccfg) {
  struct sockaddr_in server_addr;
  int sockfd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  int options = fcntl(sockfd, F_GETFL, 0);
  fcntl(sockfd, F_SETFL, options | O_NONBLOCK);

  ::memset(&server_addr, '\0', sizeof(server_addr));
  ::inet_pton(AF_INET, ccfg.serverAddr.c_str(), &(server_addr.sin_addr.s_addr));
  server_addr.sin_port = htons(ccfg.serverPort);
  server_addr.sin_family = AF_INET;

  int ret =
      ::connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
  if (ret == -1) {
    LOG_INFO << "Connect eerror. " << ::strerror(errno) << "\n";
    return -1;
  }

  return sockfd;
}

string loginVerify(SSL *ssl, const lConfig::clientConfig &ccfg) {
  json j;
  j["username"] = ccfg.username;
  j["password"] = ccfg.password;

  string authMsg = j.dump();
  SSL_write(ssl, authMsg.c_str(), authMsg.length());

  char buffer[BUFFER_SIZE];
  ::bzero(buffer, BUFFER_SIZE);
  int len = ::SSL_read(ssl, buffer, BUFFER_SIZE);
  if (len <= 0) {
    return "\x01";
  }
  printf("%d %s\n", (int)buffer[0], buffer + 1);
  if (buffer[0] == 3) {
    string IPstr(buffer + 1, buffer + len);
    return string(IPstr);
  }
  return string(buffer, 1);
}

int setupTunClient(string addr) {
  int tunfd;
  ifreq ifr;
  int ret;

  ::memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  tunfd = open("/dev/net/tun", O_RDWR);
  if (tunfd == -1) {
    LOG_INFO << "Open TUN failed! (" << errno << ": " << ::strerror(errno)
             << "\n";
    return -1;
  }

  string deviceName = "tun-client";
  strncpy(ifr.ifr_name, deviceName.c_str(), IFNAMSIZ);
  ret = ioctl(tunfd, TUNSETIFF, &ifr);
  if (ret == -1) {
    LOG_INFO << "Setup TUN interface by ioctl failed! (" << errno << ": "
             << ::strerror(errno) << "\n";
    return -1;
  }
  LOG_INFO << "Create a tun device :" << ifr.ifr_name << "\n";

  string cmd = "ifconfig ";
  cmd += deviceName;
  cmd += " ";
  cmd += addr;
  cmd += "/24 up";
  ::system(cmd.c_str());
  LOG_INFO << cmd << "\n";
  cmd = "route add -net 192.168.60.0/24 ";
  cmd += deviceName;
  ::system(cmd.c_str());
  LOG_INFO << cmd << "\n";

  LOG_INFO << "Setup TUN interface success!\n";
  return tunfd;
}

void addEvent(int epollFd, int fd, int state) {
  struct epoll_event ev;
  ev.events = state;
  ev.data.fd = fd;
  if (epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &ev) < 0) {
    LOG_INFO << "Add event failed!\n";
    std::cerr << "Add event failed!\n";
    ::exit(0);
  }
}

lVPNclient::lVPNclient(lConfig::clientConfig ccfg, LNET::AsyncLogging *log)
    : _ccfg(ccfg), _asynclog(log), _ssl(setupTLSClient(ccfg)),
      _socketFd(setupTCPClient(ccfg)), _events(MAX_EVENTS) {
  assert(_ssl != nullptr);
  assert(_socketFd >= 0);
}

lVPNclient::~lVPNclient() {
  ::close(_socketFd);
  SSL_CTX_free(g_sslCtx);
  _asynclog->stop();
}

void lVPNclient::handleSSLRead() {
  char buffer[BUFFER_SIZE];
  ::bzero(buffer, BUFFER_SIZE);
  int len = ::SSL_read(_ssl, buffer, BUFFER_SIZE);
  if (len > 0) {
    LOG_INFO << "Got a packet " << len << " bytes from from the tunnel.\n";
    ::write(_tunFd, buffer, len);
  } else if (len == 0) {
    LOG_INFO << "Socket fd: " << _socketFd << ". ssl link error!\n";
    _asynclog->stop();
    exit(0);
  } else {
    LOG_INFO << "Socket fd: " << _socketFd << "ssl read error!\n";
    LOG_INFO << "Socket fd: " << _socketFd << strerror(errno) << "\n";
    _asynclog->stop();
    exit(0);
  }
}

void lVPNclient::handleTunRead() {
  char buffer[BUFFER_SIZE];
  ::bzero(buffer, BUFFER_SIZE);
  int len = ::read(_tunFd, buffer, BUFFER_SIZE);
  const void *peek = buffer;
  const iphdr *_iphdr = static_cast<const iphdr *>(peek);

  char IPstr[INET_ADDRSTRLEN];
  ::inet_ntop(AF_INET, &_iphdr->daddr, IPstr, sizeof(IPstr));
  LOG_INFO << "Got a packet " << len << " bytes from Tun to " << IPstr << "\n";
  SSL_write(_ssl, buffer, len);
}

int lVPNclient::handleEvents(int numEvents) {
  assert(numEvents > 0);
  int fd;
  for (int i = 0; i < numEvents; i++) {
    fd = _events[i].data.fd;
    if (fd == _tunFd) {
      handleTunRead();
    } else if (fd == _socketFd) {
      handleSSLRead();
    } else if (_events[i].events & EPOLLHUP) {
      std::cerr << "EPOLLHUP, error.\n";
      return -1;
    } else {
      return -1;
    }
  }
  return 1;
}

void lVPNclient::run() {
  SSL_set_fd(_ssl, _socketFd);
  int err = SSL_connect(_ssl);
  if (err <= 0) {
    err = SSL_get_error(_ssl, err);
    LOG_INFO << "Can't complete SSL connect " << ERR_error_string(err, NULL)
             << "\n";
    ERR_print_errors_fp(stderr);
    return;
  }
  LOG_INFO << "SSL connection is successful\n";
  LOG_INFO << "SSL connection using " << SSL_get_cipher(_ssl) << "\n";

  _tunIP = loginVerify(_ssl, _ccfg);

  std::cout << _tunIP << std::endl;
  if (_tunIP.length() <= 8) {
    if (_tunIP[0] == 2) {
      LOG_INFO << "Login failed. Username or password error.\n";
    }
    return;
  }
  _tunFd = setupTunClient(_tunIP);
  assert(_tunFd >= 0);

  _epollFd = ::epoll_create1(0);

  addEvent(_epollFd, _socketFd, EPOLLIN);
  addEvent(_epollFd, _tunFd, EPOLLIN);

  while (1) {
    int numEvents = ::epoll_wait(_epollFd, &*_events.begin(), MAX_EVENTS, -1);
    if (numEvents > 0) {
      if (handleEvents(numEvents) == -1) {
        LOG_INFO << "Connect error!\n";
        break;
      }
    }
  }
}