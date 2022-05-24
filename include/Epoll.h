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
  using handleReadCallback = std::function<void(int )>;

  Epoll(int flag = 0);
  ~Epoll();

  void handleEvents(int eventsnum);

  bool isEpollValid();
  bool create(int flag = 0);
  bool add(int fd, int event);
  bool modify(int fd, int event);
  bool del(int fd, int event);
  int wait(int timeout);
  void destroy();

  void setHandleRead(const handleReadCallback &cb) { _ReadCB = cb; }

private:
  int epoll_fd_;
  EventList _events;
  handleReadCallback _ReadCB;
};

#endif