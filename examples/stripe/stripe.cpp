#include "stripe.h"

#define DIGICERT_CERT                                                    \
  "-----BEGIN CERTIFICATE-----\r\n"                                      \
  "MIIEtjCCA56gAwIBAgIQDHmpRLCMEZUgkmFf4msdgzANBgkqhkiG9w0BAQsFADBs\r\n" \
  "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\r\n" \
  "d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j\r\n" \
  "ZSBFViBSb290IENBMB4XDTEzMTAyMjEyMDAwMFoXDTI4MTAyMjEyMDAwMFowdTEL\r\n" \
  "MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3\r\n" \
  "LmRpZ2ljZXJ0LmNvbTE0MDIGA1UEAxMrRGlnaUNlcnQgU0hBMiBFeHRlbmRlZCBW\r\n" \
  "YWxpZGF0aW9uIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\r\n" \
  "ggEBANdTpARR+JmmFkhLZyeqk0nQOe0MsLAAh/FnKIaFjI5j2ryxQDji0/XspQUY\r\n" \
  "uD0+xZkXMuwYjPrxDKZkIYXLBxA0sFKIKx9om9KxjxKws9LniB8f7zh3VFNfgHk/\r\n" \
  "LhqqqB5LKw2rt2O5Nbd9FLxZS99RStKh4gzikIKHaq7q12TWmFXo/a8aUGxUvBHy\r\n" \
  "/Urynbt/DvTVvo4WiRJV2MBxNO723C3sxIclho3YIeSwTQyJ3DkmF93215SF2AQh\r\n" \
  "cJ1vb/9cuhnhRctWVyh+HA1BV6q3uCe7seT6Ku8hI3UarS2bhjWMnHe1c63YlC3k\r\n" \
  "8wyd7sFOYn4XwHGeLN7x+RAoGTMCAwEAAaOCAUkwggFFMBIGA1UdEwEB/wQIMAYB\r\n" \
  "Af8CAQAwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF\r\n" \
  "BQcDAjA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp\r\n" \
  "Z2ljZXJ0LmNvbTBLBgNVHR8ERDBCMECgPqA8hjpodHRwOi8vY3JsNC5kaWdpY2Vy\r\n" \
  "dC5jb20vRGlnaUNlcnRIaWdoQXNzdXJhbmNlRVZSb290Q0EuY3JsMD0GA1UdIAQ2\r\n" \
  "MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5j\r\n" \
  "b20vQ1BTMB0GA1UdDgQWBBQ901Cl1qCt7vNKYApl0yHU+PjWDzAfBgNVHSMEGDAW\r\n" \
  "gBSxPsNpA/i/RwHUmCYaCALvY2QrwzANBgkqhkiG9w0BAQsFAAOCAQEAnbbQkIbh\r\n" \
  "hgLtxaDwNBx0wY12zIYKqPBKikLWP8ipTa18CK3mtlC4ohpNiAexKSHc59rGPCHg\r\n" \
  "4xFJcKx6HQGkyhE6V6t9VypAdP3THYUYUN9XR3WhfVUgLkc3UHKMf4Ib0mKPLQNa\r\n" \
  "2sPIoc4sUqIAY+tzunHISScjl2SFnjgOrWNoPLpSgVh5oywM395t6zHyuqB8bPEs\r\n" \
  "1OG9d4Q3A84ytciagRpKkk47RpqF/oOi+Z6Mo8wNXrM9zwR4jxQUezKcxwCmXMS1\r\n" \
  "oVWNWlZopCJwqjyBcdmdqEU79OX2olHdx3ti6G8MdOu42vi/hw15UJGQmxg7kVkn\r\n" \
  "8TUoE6smftX3eg==\r\n"                                                 \
  "-----END CERTIFICATE-----\r\n"


int Stripe::connect()
{
    const char* CA_cert = DIGICERT_CERT;
    client = new HttpsClient;
    client->initTls(CA_cert, strlen(CA_cert) + 1); // Add 1 as initTls expects total length including null terminator
    return client->connect((char *)"api.stripe.com", 443);
}

int Stripe::get_token(char* token, const char* username, const char* card_number, const char* exp_month,
    const char* exp_year, const char* cvc)
{
    // https://stripe.com/docs/api/tokens/create_card
    int ret_size;
    client->req->withBasicAuthentication("sk_test_4eC39HqLyjWDarjtT1zdp7dc", "");
    client->req->addHeader("Accept", "*/*");
    client->req->addFormField("card[number]", "4242424242424242");
    client->req->addFormField("card[exp_month]", "4");
    client->req->addFormField("card[exp_year]", "2021");
    client->req->addFormField("card[cvc]", "314");
    ret_size = client->postUrlEncoded((char *)"/v1/tokens");
    if (ret_size > 0)
    {
      Log.info("Token received %d bytes", ret_size);
      while (!client->resp->headers.isEmpty())
      {
        HttpsClient::Header header = client->resp->headers.takeFirst();
      }
      JsonParser parser;
      String tok;
      parser.addString(client->resp->body);
      if (parser.parse() && parser.getOuterValueByKey("id",tok)) {
            Log.info("Found token: %s", tok.c_str());
            delete _token;
            _token = new char[strlen(tok)+1];
            memcpy(_token, tok,strlen(tok)+1);
      }
    } 
    return ret_size;
}

void Stripe::disconnect()
{
    client->disconnect();
    delete client;
}

int Stripe::send_charge(char *token, const char *username, const char *amount, const char *currency, const char *description)
{
    // https://stripe.com/docs/api/charges
    int ret_size;
    client->req->withBasicAuthentication(username, "");
    client->req->addHeader("Accept", "*/*");
    client->req->addFormField("amount", amount);
    client->req->addFormField("currency", currency);
    client->req->addFormField("description", description);
    client->req->addFormField("source", token);
    ret_size = client->postUrlEncoded((char *)"/v1/charges");
    if (ret_size > 0)
    {
        Log.info("Charge received %d bytes", ret_size);
        JsonParser parser;
        parser.addString(client->resp->body);
        String url;
        if (parser.parse() && parser.getOuterValueByKey("receipt_url",url))
        {
            Particle.publish("stripe", url, PRIVATE);
        }
    }
    return ret_size;
}

int Stripe::charge(const char* amount, const char* currency, const char* username, const char* card_number, const char* exp_month, 
    const char* exp_year, const char* cvc, const char* description)
{
    int ret;
    if ((ret = connect()) < 0) return ret;
    if ((ret = get_token(_token, username, card_number, exp_month, exp_year, cvc)) < 0)
    {
        disconnect();
        return ret;
    };
    ret = send_charge(_token, username, amount, currency, description);
    disconnect();
    return ret;
}

Stripe::Stripe()
{
    client = NULL;
    _token = NULL;
}
Stripe::~Stripe()
{
    delete client;
    delete _token;
}