#include <CountDownLatch.h>

namespace LNET {
CountDownLatch::CountDownLatch(int count) : _count(count) {}

void CountDownLatch::await() {
  std::unique_lock<std::mutex> lck(_lock);
  while (_count > 0) {
    _cv.wait(lck);
  }
}

void CountDownLatch::countDown() {
  std::unique_lock<std::mutex> lck(_lock);
  --_count;
  if (_count == 0) {
    _cv.notify_all();
  }
}

int CountDownLatch::getCount() {
  std::unique_lock<std::mutex> lck(_lock);
  return _count;
}

} // namespace LNET