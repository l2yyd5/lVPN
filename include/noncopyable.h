#ifndef LNET_NONCOPYABLE_H
#define LNET_NONCOPYABLE_H

namespace LNET {
class noncopyable {
protected:
  noncopyable() = default;
  ~noncopyable() = default;

private:
  noncopyable(const noncopyable &) = delete;
  void operator=(const noncopyable &) = delete;
};
} // namespace LNET

#endif