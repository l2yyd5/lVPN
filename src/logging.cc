#include <logging.h>

#include <algorithm>

namespace LNET {

const char digits[] = "9876543210123456789";
const char digitsHex[] = "0123456789ABCDEF";
const char *zero = digits + 9;
template <typename T> size_t convert(char buf[], T value) {
  T i = value;
  char *p = buf;

  do {
    int lsd = static_cast<int>(i % 10);
    i /= 10;
    *p++ = zero[lsd];
  } while (i != 0);

  if (value < 0) {
    *p++ = '-';
  }
  *p = '\0';
  std::reverse(buf, p);

  return p - buf;
}

size_t convertHex(char buf[], uintptr_t value) {
  uintptr_t i = value;
  char *p = buf;

  do {
    int lsd = static_cast<int>(i % 16);
    i /= 16;
    *p++ = digitsHex[lsd];
  } while (i != 0);

  *p = '\0';
  std::reverse(buf, p);

  return p - buf;
}

template <typename T> void LogStream::formatInteger(T v) {
  if (_buffer.fspace() >= MaxNumSize) {
    size_t len = convert(_buffer.current(), v);
    _buffer.add(len);
  }
}

LogStream &LogStream::operator<<(short v) {
  *this << static_cast<int>(v);
  return *this;
}

LogStream &LogStream::operator<<(unsigned short v) {
  *this << static_cast<unsigned int>(v);
  return *this;
}

LogStream &LogStream::operator<<(int v) {
  formatInteger(v);
  return *this;
}

LogStream &LogStream::operator<<(unsigned int v) {
  formatInteger(v);
  return *this;
}

LogStream &LogStream::operator<<(long v) {
  formatInteger(v);
  return *this;
}

LogStream &LogStream::operator<<(unsigned long v) {
  formatInteger(v);
  return *this;
}

LogStream &LogStream::operator<<(long long v) {
  formatInteger(v);
  return *this;
}

LogStream &LogStream::operator<<(unsigned long long v) {
  formatInteger(v);
  return *this;
}

LogStream &LogStream::operator<<(const void *p) {
  uintptr_t v = reinterpret_cast<uintptr_t>(p);
  if (_buffer.fspace() >= MaxNumSize) {
    char *buf = _buffer.current();
    buf[0] = '0';
    buf[1] = 'x';
    size_t len = convertHex(buf + 2, v);
    _buffer.add(len + 2);
  }
  return *this;
}

LogStream &LogStream::operator<<(double v) {
  if (_buffer.fspace() >= MaxNumSize) {
    int len = snprintf(_buffer.current(), MaxNumSize, "%.12g", v);
    _buffer.add(len);
  }
  return *this;
}

class T {
public:
  T(const char *str, unsigned len) : _str(str), _len(len) {
    assert(strlen(str) == _len);
  }

  const char *_str;
  const unsigned _len;
};

inline LogStream &operator<<(LogStream &s, T v) {
  s.append(v._str, v._len);
  return s;
}

inline LogStream &operator<<(LogStream &s, const Logger::SourceFile &v) {
  s.append(v._data, v._size);
  return s;
}

void defaultOutput(const char *msg, int len) {
  size_t n = fwrite(msg, 1, len, stdout);
  (void)n;
}

void defaultFlush() { fflush(stdout); }

Logger::OutputFunc g_output = defaultOutput;
Logger::FlushFunc g_flush = defaultFlush;

Logger::Logger(SourceFile file, int line) : _filename(file), _line(line) {}
Logger::~Logger() {
  const LogStream::Buffer &buf(stream().buffer());
  g_output(buf.data(), buf.length());
}

void Logger::setOutput(OutputFunc out) { g_output = out; }

void Logger::setFlush(FlushFunc flush) { g_flush = flush; }

AsyncLogging::AsyncLogging(const string &filename, int flushInterval)
    : _flushInterval(flushInterval), _running(false), _filename(filename),
      _latch(1), _currentBuffer(new Buffer), _nextBuffer(new Buffer),
      _buffers() {
  _buffers.reserve(16);
}

void AsyncLogging::append(const char *dataLine, int len) {
  std::unique_lock<std::mutex> lck(_mutex);
  if (_currentBuffer->fspace() > len) {
    _currentBuffer->append(dataLine, len);
  } else {
    _buffers.push_back(std::move(_currentBuffer));
    if (_nextBuffer) {
      _currentBuffer = std::move(_nextBuffer);
    } else {
      _currentBuffer.reset(new Buffer);
    }
    _currentBuffer->append(dataLine, len);
    _cond.notify_all();
  }
}

void AsyncLogging::threadFunc() {
  _latch.countDown();
  std::ofstream output(_filename);
  BufferPtr newBuffer1(new Buffer);
  BufferPtr newBuffer2(new Buffer);
  newBuffer1->setZero();
  newBuffer2->setZero();
  BufferVector toWrite;
  toWrite.reserve(16);
  while (_running) {
    assert(newBuffer1 && newBuffer1->length() == 0);
    assert(newBuffer2 && newBuffer2->length() == 0);
    assert(toWrite.empty());

    {
      std::unique_lock<std::mutex> lck(_mutex);
      if (_buffers.empty()) {
        _cond.wait_for(lck, std::chrono::seconds(_flushInterval));
      }
      _buffers.push_back(std::move(_currentBuffer));
      _currentBuffer = std::move(newBuffer1);
      toWrite.swap(_buffers);
      if (!_nextBuffer) {
        _nextBuffer = std::move(newBuffer2);
      }
    }

    for (const auto &buf : toWrite) {
      string tmp(buf->data());
      output.write(tmp.c_str(), tmp.length());
    }
    if (toWrite.size() > 2) {
      toWrite.resize(2);
    }
    if (!newBuffer1) {
      assert(!toWrite.empty());
      newBuffer1 = std::move(toWrite.back());
      toWrite.pop_back();
      newBuffer1->setZero();
    }
    if (!newBuffer2) {
      assert(!toWrite.empty());
      newBuffer2 = std::move(toWrite.back());
      toWrite.pop_back();
      newBuffer2->setZero();
    }
    toWrite.clear();
    output.flush();
  }
  output.flush();
}

} // namespace LNET

void createLog(LNET::AsyncLogging *&log) {
  ptime nowtime = second_clock::local_time();
  std::string logPath = to_simple_string(nowtime);
  
  logPath[11] = '-';
  logPath = "logs/" + logPath + ".log";
  LNET::AsyncLogging *_log = new LNET::AsyncLogging(logPath);
  log = _log;
}