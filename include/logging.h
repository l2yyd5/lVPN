#ifndef LNET_LOGGING_H
#define LNET_LOGGING_H

#include <CountDownLatch.h>
#include <noncopyable.h>

#include <array>
#include <atomic>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/format.hpp>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

using boost::format;
using namespace boost::posix_time;
using std::string;

namespace LNET {

const int lLargeBufferSize = 4000 * 1000;
const int lSmallBufferSize = 4096;

template <int SIZE> class lBuffer : noncopyable {
public:
  lBuffer() : _data{}, _cur(_data.begin()) {}
  ~lBuffer() {}

  int size() { return _data.size(); }
  int length() const { return _cur - _data.begin(); }
  int fspace() const { return _data.end() - _cur; }
  const char *data() const { return &_data[0]; }
  char *current() { return &(*_cur); }
  void add(size_t len) { _cur += len; }
  void setZero() {
    _data.fill(0);
    _cur = _data.begin();
  }

  string toString() const { return string(_data.begin()); }

  void append(const char *buf, size_t len) {
    if (static_cast<size_t>(fspace()) > len) {
      strncpy(_cur, buf, len);
      _cur += len;
    }
  }

private:
  std::array<char, SIZE> _data;
  decltype(_data.begin()) _cur;
};

class LogStream : private noncopyable {
public:
  LogStream() {}

  using Buffer = lBuffer<lSmallBufferSize>;

  LogStream &operator<<(bool v) {
    _buffer.append(v ? "1" : "0", 1);
    return *this;
  }

  LogStream &operator<<(short);
  LogStream &operator<<(unsigned short);
  LogStream &operator<<(int);
  LogStream &operator<<(unsigned int);
  LogStream &operator<<(long);
  LogStream &operator<<(unsigned long);
  LogStream &operator<<(long long);
  LogStream &operator<<(unsigned long long);

  LogStream &operator<<(const void *);

  LogStream &operator<<(float v) {
    *this << static_cast<double>(v);
    return *this;
  }
  LogStream &operator<<(double);

  LogStream &operator<<(char v) {
    _buffer.append(&v, 1);
    return *this;
  }

  LogStream &operator<<(const char *str) {
    if (str) {
      _buffer.append(str, strlen(str));
    } else {
      _buffer.append("(null)", 6);
    }
    return *this;
  }

  LogStream &operator<<(const unsigned char *str) {
    return operator<<(reinterpret_cast<const char *>(str));
  }

  LogStream &operator<<(const string &v) {
    _buffer.append(v.c_str(), v.length());
    return *this;
  }

  LogStream &operator<<(const Buffer &v) {
    *this << v.toString();
    return *this;
  }

  void append(const char *data, int len) { _buffer.append(data, len); }
  const Buffer &buffer() const { return _buffer; }

private:
  template <typename T> void formatInteger(T);

  Buffer _buffer;
  static const int MaxNumSize = 48;
};

class Logger : private noncopyable {
public:
  class SourceFile {
  public:
    template <int N>
    SourceFile(const char (&arr)[N]) : _data(arr), _size(N - 1) {
      const char *slash = strrchr(_data, '/');
      if (slash) {
        _data = slash + 1;
      }
      _size = strlen(_data);
    }

    explicit SourceFile(const char *filename) : _data(filename) {
      const char *slash = strrchr(filename, '/');
      if (slash) {
        _data = slash + 1;
      }
      _size = strlen(_data);
    }

    const char *_data;
    int _size;
  };

  Logger(SourceFile file, int line);
  ~Logger();

  LogStream &stream() { return _logStream; }

  typedef void (*OutputFunc)(const char *msg, int len);
  typedef void (*FlushFunc)();
  static void setOutput(OutputFunc);
  static void setFlush(FlushFunc);

private:
  LogStream _logStream;
  int _line;
  SourceFile _filename;
};

#define LOG_INFO LNET::Logger(__FILE__, __LINE__).stream()

class AsyncLogging : private noncopyable {
public:
  AsyncLogging(const string &filename, int flushInterval = 3);
  ~AsyncLogging() {
    if (_running) {
      stop();
    }
  }

  void append(const char *logline, int len);
  void start() {
    _running = true;
    std::thread tmp(&AsyncLogging::threadFunc, this);
    _thread.swap(tmp);
    _latch.await();
  }
  void stop() {
    _running = false;
    _cond.notify_all();
    _thread.join();
  }

private:
  using Buffer = lBuffer<lLargeBufferSize>;
  using BufferVector = std::vector<std::unique_ptr<Buffer>>;
  using BufferPtr = BufferVector::value_type;

  void threadFunc();

  const int _flushInterval;
  std::atomic<bool> _running;
  const string _filename;
  std::thread _thread;
  CountDownLatch _latch;
  std::mutex _mutex;
  std::condition_variable _cond;

  BufferPtr _currentBuffer;
  BufferPtr _nextBuffer;
  BufferVector _buffers;
};
} // namespace LNET

void createLog(LNET::AsyncLogging *&log);

#endif