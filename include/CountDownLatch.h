// Use of this source code is governed by a BSD-style license
// that can be found in the License file.
//
// Author: Shuo Chen (chenshuo at chenshuo dot com)

#ifndef LNET_COUNTDOWNLATCH_H
#define LNET_COUNTDOWNLATCH_H

#include <inttypes.h>
#include <noncopyable.h>
#include <stdint.h>

#include <condition_variable>
#include <mutex>

namespace LNET {

class CountDownLatch : private noncopyable {
public:
  CountDownLatch(int count);

  void await();

  void countDown();

  int getCount();

private:
  std::condition_variable _cv;
  std::mutex _lock;
  uint32_t _count;
};

} // namespace LNET
#endif
