#pragma once

#include "Particle.h"

// This will load the definition for common Particle variable types
#include "mbedtls/ssl.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/base64.h"

int mbedtls_default_rng( void *data, unsigned char *output, size_t len);

// This is your main class that users will import into their application
class Mbedtls
{
public:
  Mbedtls();
  ~Mbedtls() = default;

  int init(const char *rootCaPem, const size_t rootCaPemSize,
           const char *clientCertPem = NULL, const size_t clientCertPemSize = 0,
           const char *clientKeyPem = NULL, const size_t clientKeyPemSize = 0);
  int connect(uint8_t *ip, uint16_t port);
  int connect(char *domain, uint16_t port);
  int write(unsigned char *buf, size_t len, uint16_t timeout = 2000);
  /**
   * \brief   Read at most 'len' application data bytes
   * 
   */
  int read(unsigned char *buf, size_t len, uint16_t timeout = 2000);
  void close();

  int available();

private:
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cacert, clicert;
  mbedtls_pk_context pkey;
  static int rng_Tls(void *handle, uint8_t *data, const size_t len_);
  static int f_send(void *ctx, const unsigned char *buf, size_t len);
  static int f_recv(void *ctx, unsigned char *buf, size_t len);
  int handshake();
  bool _connected;
  TCPClient client;
};
