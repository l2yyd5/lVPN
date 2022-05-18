#include <lVPN.h>

#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>

LNET::AsyncLogging *g_asyncLog = nullptr;
void asyncOutput(const char *msg, int len) { g_asyncLog->append(msg, len); }
string confFileName = "serverConf.json";
json sConf;

int main(int argc, char *argv[]) {
  // switch (fork()) {
  // case -1:
  //   printf("fork() failed\n");
  //   exit(0);
  // case 0:
  //   break;
  // default:
  //   exit(0);
  // }

  // if (setsid() == -1) {
  //   printf("setsid() failed\n");
  //   exit(0);
  // }

  // switch (fork()) {
  // case -1:
  //   printf("fork() failed\n");
  //   exit(0);
  // case 0:
  //   break;
  // default:
  //   exit(0);
  // }

  if (argc > 1) {
    confFileName = argv[1];
  }
  std::ifstream confFile(confFileName);
  if (!confFile.is_open()) {
    std::cerr << "File not exits.\n";
    exit(0);
  }
  confFile >> sConf;
  confFile.close();

  lConfig::serverConfig scfg;
  getServerConfig(sConf, scfg);

  createLog(g_asyncLog);
  LNET::Logger::setOutput(asyncOutput);
  g_asyncLog->start();

  lVPNsrv server(scfg, g_asyncLog);
  server.run();

  g_asyncLog->stop();

  return 0;
}