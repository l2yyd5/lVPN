#include <Epoll.h>

Epoll::Epoll(int flag) : epoll_fd_(-1), _events(MAX_EVENTS) { create(flag); }

Epoll::~Epoll() { destroy(); }

bool Epoll::isEpollValid() { return epoll_fd_ >= 0; }

bool Epoll::create(int flag) {
  if (!isEpollValid() && ((epoll_fd_ = ::epoll_create1(flag)) == -1)) {
    LOG_INFO << "Server create epoll fd failed\n";
    return false;
  }
  return true;
}

bool Epoll::add(int fd, int event) {
  if (isEpollValid()) {
    epoll_event ep_event{};
    ep_event.events = event;
    ep_event.data.fd = fd;

    int ret = ::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ep_event) != -1;
    if (!ret)
      LOG_INFO << "Fd: " << fd << ". epoll add failed\n";
    return ret;
  }
  return false;
}

bool Epoll::modify(int fd, int event) {
  if (isEpollValid()) {
    epoll_event ep_event{};
    ep_event.events = event;
    ep_event.data.fd = fd;

    int ret = ::epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ep_event) != -1;
    if (!ret)
      LOG_INFO << "Fd: " << fd << ". epoll modify failed\n";
    return ret;
  }

  return false;
}

bool Epoll::del(int fd, int event) {
  if (isEpollValid()) {
    epoll_event ep_event{};
    ep_event.events = event;
    ep_event.data.fd = fd;

    int ret = ::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, &ep_event) != -1;
    if (!ret)
      LOG_INFO << "Fd: " << fd << ". epoll delete failed\n";
    return ret;
  }

  return false;
}

int Epoll::wait(int timeout) {
  if (isEpollValid()) {
    int numEvents =
        ::epoll_wait(epoll_fd_, &*_events.begin(), MAX_EVENTS, timeout);
    return numEvents;
  }
  return -2;
}

void Epoll::destroy() {
  if (isEpollValid())
    ::close(epoll_fd_);
  epoll_fd_ = -1;
}

void Epoll::handleEvents(int eventsnum) {
  assert(eventsnum > 0);
  for (int i = 0; i < eventsnum; i++) {
    int fd = _events[i].data.fd;
    if (_events[i].events & EPOLLIN) {
      _ReadCB(fd);
    }
  }
  return;
}