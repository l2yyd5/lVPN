#include <utils.h>

int verifyInfo(const std::string &username, const std::string &password) {
  spwd *pw;
  std::string epassword = "";
  pw = ::getspnam(username.c_str());
  if (pw == nullptr) {
    return -1;
  }
  epassword = ::crypt(password.c_str(), pw->sp_pwdp);
  if (epassword != pw->sp_pwdp) {
    return -1;
  }
  return 1;
}