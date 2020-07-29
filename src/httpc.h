#ifndef HTTPC_CLIENT_H
#define HTTPC_CLIENT_H

#include "mbedtls.h"

#define HTTPS_ERROR_HEADER_LINE_TOO_LONG -29999
#define HTTPS_ERROR_BAD_HEADER_FORMAT -30000

class HttpsClient;

enum class HTTP_METHOD {POST, GET};
enum class CONTENT_TYPE {APPLICATION_JSON, X_WWW_FORM_URLENCODED};

struct NameValue
{
    const char *name;
    const char *value;
};

class HttpsClient {
public:
    class Header;
    class HttpResponse;
    class HttpRequest;
    HttpsClient();
    ~HttpsClient();

    /**
     * \brief                   Initialize the TLS stack
     * 
     * \param rootCaPem         Required: Certificate Authority certificate, to validate the server's identity
     * \param rootCaPemSize     Required: Size of the rootCaPem certificate
     * \param clientCertPem     Optional: If using a client certificate
     * \param clientCertPemSize Optional: (but required if the client cert is used)
     * \param clientKeyPem      Optional: Private key for client cert (required if client cert is used)
     * \param clientKeyPemSize  Optional: size of the key (required if client cert is used)
     * 
     * \return 0 if success
     */
    int initTls(const char *rootCaPem, const size_t rootCaPemSize,
                const char *clientCertPem = NULL, const size_t clientCertPemSize = 0,
                const char *clientKeyPem = NULL, const size_t clientKeyPemSize = 0);

    int connect(char *url, uint16_t port);
    void disconnect();
    int postJson(char *path, char *body);
    int postUrlEncoded(char *path);

    HttpRequest* req;
    HttpResponse* resp;

private:
    Mbedtls* _tlsClient;
    int _sendHeaders(char *path);
    int _parseResponse();
};

class HttpsClient::Header {
    public:
    const char *name;
    const char *value;

    Header() {
        name = NULL;
        value = NULL;
    };
    Header(const Header& obj) {
        size_t size = strlen(obj.name)+1;
        this->name = new char[size];
        memcpy((void *)this->name,(void *)obj.name,size);
        size = strlen(obj.value)+1;
        this->value = new char[size];
        memcpy((void *)this->value,(void *)obj.value,size);
    };
    Header(Header&& obj) {
        this->name = obj.name;
        this->value = obj.value;
        obj.name = NULL;
        obj.value = NULL;
    };
    ~Header() {
        delete[] name;
        delete[] value;
    }
    int addHeader(char *buf, size_t size);
    void addHeader(const char *name, const char* value);
};

class HttpsClient::HttpResponse
{
    public:
    uint16_t status_code;
    Vector<HttpsClient::Header> headers;
    char* body;
};

class HttpsClient::HttpRequest
{
    public:
    const char* url;
    Vector<HttpsClient::Header> headers;
    Vector<NameValue> form_fields;
    HTTP_METHOD method;
    CONTENT_TYPE content_type;

    void setMethod(HTTP_METHOD method) { this->method = method;};
    void setContentType(CONTENT_TYPE content_type) { this->content_type = content_type;};
    /**
     * \brief           Add a header with Name: Value
     * 
     * \param name      The name of the header
     * \param value     The value of the header
     * 
     * Headers are consumed when a transaction is started (i.e. with postJson or postUrlEncoded), so they need to be added again if doing back to back transactions.
     */
    void addHeader(const char *name, const char *value);
    /**
     * \brief           Add a form field to be used for UrlEncoded post
     * 
     * \param name      The name of the field
     * \param value     The value of the field
     * 
     * Form fields are consumed when a transaction is started (i.e. postUrlEncoded), so they need to be added again if doing back to back transactions.
     */
    void addFormField(const char *name, const char *value);
    /**
     * \brief           Use Basic Authentication for the request
     * 
     * \param userid    Username
     * \param password  Password (use "" for no password)
     * 
     * Authorization is consumed when a transaction is started (i.e. with postJson or postUrlEncoded), so it needs to be added again if doing back to back transactions.
     */
    void withBasicAuthentication(const char *userid, const char *password);
};

#endif