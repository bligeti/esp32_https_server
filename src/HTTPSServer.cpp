#include "HTTPSServer.hpp"

namespace httpsserver {

constexpr const char * alpn_protos[] = { "http/1.1", NULL } ;

HTTPSServer::HTTPSServer(SSLCert * cert, const uint16_t port, const uint8_t maxConnections, const in_addr_t bindAddress):
  HTTPServer(port, maxConnections, bindAddress),
  _cert(cert) {
  // Configure runtime data
  _cfg = NULL;

}

HTTPSServer::~HTTPSServer() {
  
}

/**
 * This method starts the server and begins to listen on the port
 */
uint8_t HTTPSServer::setupSocket() {
  if (!isRunning()) {
    _cfg = new esp_tls_cfg_server();
    _cfg->alpn_protos = (const char **)alpn_protos;
    _cfg->cacert_buf = NULL;
    _cfg->cacert_bytes = 0;
    _cfg->servercert_buf = _cert->getCertData();
    _cfg->servercert_bytes = _cert->getCertLength();
    _cfg->serverkey_buf = _cert->getPKData();
    _cfg->serverkey_bytes = _cert->getPKLength();

    esp_err_t ret = esp_tls_cfg_server_session_tickets_init(_cfg);
    if ( ret != ESP_OK ) {
      HTTPS_LOGE("Failed to init session ticket support. error: %s", esp_err_to_name(ret));
    }

    if (HTTPServer::setupSocket()) {
      return 1;
    } else {
      HTTPS_LOGE("HTTPServer::setupSocket failed");
      return 0;
    }
  } else {
    return 1;
  }
}

void HTTPSServer::teardownSocket() {

  HTTPServer::teardownSocket();

  if (_cfg) {
    //esp_tls_cfg_server_session_tickets_free(_cfg);
    free((void *)_cfg->servercert_buf);
    free((void *)_cfg->serverkey_buf);
  }
  delete _cfg;
  _cfg = NULL;


}

int HTTPSServer::createConnection(int idx) {
  HTTPSConnection * newConnection = new HTTPSConnection(this);
  _connections[idx] = newConnection;
  return newConnection->initialize(_socket, _cfg , &_defaultHeaders);
}


} /* namespace httpsserver */
