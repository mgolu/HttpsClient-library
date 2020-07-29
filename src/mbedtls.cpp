/* mbedtls library by Mariano Goluboff
 */

#include "mbedtls.h"

int mbedtls_default_rng(void *data, unsigned char *output, size_t len)
{
    while (len >= 4)
    {
        *((uint32_t *)output) = HAL_RNG_GetRandomNumber();
        output += 4;
        len -= 4;
    }
    while (len-- > 0)
    {
        *output++ = HAL_RNG_GetRandomNumber();
    }
    return 0;
}

static void mbedtls_debug(void *ctx, int level,
                          const char *file, int line,
                          const char *str)
{
    Log.trace("%s:%04d: %s", file, line, str);
}

Mbedtls::Mbedtls()
{
}

int Mbedtls::init(const char *rootCaPem, const size_t rootCaPemSize,
                  const char *clientCertPem, const size_t clientCertPemSize,
                  const char *clientKeyPem, const size_t clientKeyPemSize)
{
    // https://tls.mbed.org/module-level-design-ssl-tls
    int ret;
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        return ret;
    }
    mbedtls_ssl_conf_rng(&conf, mbedtls_default_rng, nullptr);
    mbedtls_ssl_conf_dbg(&conf, mbedtls_debug, this);
    //mbedtls_debug_set_threshold(3);
    
    mbedtls_x509_crt_init(&cacert);
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        return ret;
    }

    if ((ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)rootCaPem, rootCaPemSize)) != 0)
    {
        Log.info(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        return ret;
    }
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);
    if (clientCertPem != NULL && clientKeyPem != NULL) {
        mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey);
    } 
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_set_bio(&ssl, this, &Mbedtls::f_send, &Mbedtls::f_recv, nullptr);
    _connected = false;
    return 0;
}

int Mbedtls::f_send(void *ctx, const unsigned char *buf, size_t len)
{
    Mbedtls *sock = (Mbedtls *)ctx;

    if (!sock->client.status())
    {
        return -1;
    }

    int ret = sock->client.write(buf, len);
    if (ret == 0)
    {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    sock->client.flush();
    return ret;
}

int Mbedtls::f_recv(void *ctx, unsigned char *buf, size_t len)
{
    Mbedtls *sock = (Mbedtls *)ctx;

    if (!sock->client.status())
    {
        return -1;
    }

    if (sock->client.available() == 0)
    {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    int ret = sock->client.read(buf, len);
    if (ret == 0)
    {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    return ret;
}

void Mbedtls::close()
{
    mbedtls_x509_crt_free(&cacert);
    //mbedtls_x509_crt_free(&clicert);
    //mbedtls_pk_free(&pkey);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ssl_free(&ssl);
    client.stop();
    _connected = false;
};

int Mbedtls::connect(char *domain, uint16_t port)
{
    int ret;
    if (!client.connect(domain, port))
    {
        Log.info("Could not connect to server : %s", domain);
        return -1;
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl, domain)) != 0)
    {
        return ret;
    }
    return handshake();
}

int Mbedtls::connect(uint8_t *ip, uint16_t port)
{
    int ret;
    char buffer[16];
    sprintf(buffer, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

    if (!client.connect(ip, port))
    {
        return -1;
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl, buffer)) != 0)
    {
        return ret;
    }
    return handshake();
}

int Mbedtls::handshake()
{
    int ret = -1;
    do
    {
        while (ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
        {
            ret = mbedtls_ssl_handshake_client_step(&ssl);
            if (ret != 0)
                break;
        }
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    mbedtls_x509_crt_free(&cacert);
    //mbedtls_x509_crt_free(&clicert);
    //mbedtls_pk_free(&pkey);
    if (ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER)
    {
        _connected = true;
        return 0;
    }
    return ret;
}

int Mbedtls::write(unsigned char *buf, size_t len, uint16_t timeout)
{
    if (!_connected) return -1;
    long int _timeout = millis();
    size_t offset = 0;
    int ret;
    do
    {
        ret = mbedtls_ssl_write(&ssl, buf+offset, len-offset);
        if (ret <= 0)
        {
            switch (ret)
            {
            case MBEDTLS_ERR_SSL_WANT_READ:
            case MBEDTLS_ERR_SSL_WANT_WRITE:
            case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
            case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
                delay(100);
                break;
            default:
                close();
            }
        } else {
            offset+=ret;
            _timeout = millis();
        }
    } while ((ret > 0 && offset < len) ||
             ((ret == MBEDTLS_ERR_SSL_WANT_READ ||
               ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
               ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
               ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) &&
              (millis() - _timeout) < timeout));
    return ret;
}

int Mbedtls::read(unsigned char *buf, size_t len, uint16_t timeout)
{
    if (!_connected) return -1;
    long int _timeout = millis();
    size_t offset = 0;
    int ret;
    do
    {
        ret = mbedtls_ssl_read(&ssl, buf+offset, len-offset);
        if (ret <= 0)
        {
            switch (ret)
            {
            case MBEDTLS_ERR_SSL_WANT_READ:
            case MBEDTLS_ERR_SSL_WANT_WRITE:
            case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
            case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
                delay(100);
                break;
            case MBEDTLS_ERR_SSL_CLIENT_RECONNECT: // This can only happen server-side
            default:
                close();
            }
        } else {
            offset+=ret;
            _timeout = millis();
        }
    } while (
            ( ret > 0 && offset < len)  ||
            ((ret == MBEDTLS_ERR_SSL_WANT_READ ||
              ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
              ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
              ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) &&
             (millis() - _timeout) < timeout )
             );
    return (offset > 0) ? offset : ret;
}