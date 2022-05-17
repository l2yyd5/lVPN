#include <config.h>

namespace lConfig {
void from_json(const json &j, tlsConfig &t) {
  j.at("caCert").get_to(t.caCert);
  j.at("clientCert").get_to(t.clientCert);
  j.at("clientKey").get_to(t.clientKey);
  j.at("serverCert").get_to(t.serverCert);
  j.at("serverKey").get_to(t.serverKey);
}
void to_json(json &j, const tlsConfig &t) {
  j = json{{"caCert", t.caCert},
           {"clientCert", t.clientCert},
           {"clientKey", t.clientKey},
           {"serverCert", t.serverCert},
           {"serverKey", t.serverKey}};
}

void from_json(const json &j, serverConfig &s) {
  j.at("tunAddr").get_to(s.tunAddr);
  j.at("tunMask").get_to(s.tunMask);
  j.at("listenAddr").get_to(s.listenAddr);
  j.at("listenPort").get_to(s.listenPort);
}
void to_json(json &j, const serverConfig &s) {
  j = json{{"tunAddr", s.tunAddr},
           {"tunMask", s.tunMask},
           {"listenAddr", s.listenAddr},
           {"listenPort", s.listenPort}};
}

void from_json(const json &j, clientConfig &c) {
  j.at("serverHostName").get_to(c.serverHostName);
  j.at("serverAddr").get_to(c.serverAddr);
  j.at("serverPort").get_to(c.serverPort);
  j.at("username").get_to(c.username);
  j.at("password").get_to(c.password);
}
void to_json(json &j, const clientConfig &c) {
  j = json{{"serverHostName", c.serverHostName},
           {"serverPort", c.serverPort},
           {"username", c.username},
           {"password", c.password}};
}
} // namespace lConfig

using namespace lConfig;

void getServerConfig(const json &j, serverConfig &scfg) {
  try {
    scfg = j["server_config"];
    scfg.tls_config = j["tls_config"];
  } catch (json::parse_error &ex) {
    string errorMessage = "Server config file error. ";
    errorMessage += ex.what();
    std::cerr << errorMessage << std::endl;
    exit(0);
  }
}

void getClientConfig(const json &j, clientConfig &ccfg) {
  try {
    ccfg = j["client_config"];
    ccfg.tls_config = j["tls_config"];
  } catch (json::parse_error &ex) {
    string errorMessage = "Client config file error. ";
    errorMessage += ex.what();
    std::cerr << errorMessage << std::endl;
    exit(0);
  }
}
