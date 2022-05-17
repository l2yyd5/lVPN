#ifndef CONFIG_H
#define CONFIG_H

#include <nlohmann/json.hpp>

#include <cstring>
#include <iostream>

using json = nlohmann::json;
using std::string;

namespace lConfig {
struct tlsConfig {
  string caCert;
  string clientCert;
  string clientKey;
  string serverCert;
  string serverKey;
};
void from_json(const json &j, tlsConfig &t);
void to_json(json &j, const tlsConfig &t);

struct serverConfig {
  tlsConfig tls_config;
  string tunAddr;
  string tunMask;
  string listenAddr;
  int listenPort;
};
void from_json(const json &j, serverConfig &s);
void to_json(json &j, const serverConfig &s);

struct clientConfig {
  tlsConfig tls_config;
  string serverHostName;
  string serverAddr;
  int serverPort;
  string username;
  string password;
};
void from_json(const json &j, clientConfig &c);
void to_json(json &j, const clientConfig &c);
} // namespace lConfig

void getServerConfig(const json &j, lConfig::serverConfig& scfg);
void getClientConfig(const json &j, lConfig::clientConfig& ccfg);

#endif