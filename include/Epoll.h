#ifndef EPOLL_H
#define EPOLL_H

#include <utils.h>

#include <cstdlib>
#include <functional>
#include <sys/epoll.h>
#include <vector>

class Epoll {
public:
  using EventList = std::vector<epoll_event>;
  using newConnectionCallback = std::function<void()>;
  using handleReadCallback = std::function<void(tlsTool *)>;
  using handleTunCallback = std::function<void()>;
  using closeConnectionCallback = std::function<void(tlsTool *)>;

  Epoll(int flag = 0);
  ~Epoll();

  void handleEvents(int listenfd, int tunfd, int eventsnum);

  bool isEpollValid();
  bool create(int flag = 0);
  bool add(int fd, void *data, int event);
  bool modify(int fd, void *data, int event);
  bool del(int fd, void *data, int event);
  int wait(int timeout);
  void destroy();

  void setNewConnection(const newConnectionCallback &cb) { _connectionCB = cb; }
  void setHandleSSLRead(const handleReadCallback &cb) { _sslReadCB = cb; }
  void setHandleTunRead(const handleTunCallback &cb) { _tunReadCB = cb; }
  void setCloseConnection(const closeConnectionCallback &cb) { _closeCB = cb; }

private:
  int epoll_fd_;
  EventList _events;
  newConnectionCallback _connectionCB;
  handleReadCallback _sslReadCB;
  handleTunCallback _tunReadCB;
  closeConnectionCallback _closeCB;
};

#endif