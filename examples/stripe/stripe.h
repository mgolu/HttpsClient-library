#include "Particle.h"
#include "httpc.h"
#include "JsonParserGeneratorRK.h"

#define DEFAULT_USERNAME "sk_test_4eC39HqLyjWDarjtT1zdp7dc"

class Stripe {
public:
    Stripe();
    ~Stripe();

    /**
     * \brief               Use the Stripe Charge API to charge a credit card
     * 
     * \param amount        The amount of the charge in the smallest currency unit (i.e. 100 for usd $1.00: https://stripe.com/docs/currencies#zero-decimal)
     * \param currency      Three letter ISO code for currency: https://stripe.com/docs/currencies   If not specified, it uses usd
     * \param username      The secret key for your Stripe account. If not specified, it uses the Stripe test account.
     * \param card_number   Card number to charge. If not specified, it uses the Stripe test VISA card
     * \param exp_month     Card expiration month in MM format. If not specified, it uses the Stripe test VISA card
     * \param exp_year      Card expiration year in YYYY format. If not specified, it uses the Stripe test VISA card
     * \param cvc           Card CVC number. If not specified, it uses the Strip test VISA card.
     * \param description   Charge description for receipt
     * 
     * This function will do a Particle.publish() with the URL of the receipt available on Stripe's system.
     */
    int charge(const char* amount, const char* currency="usd", const char* username=DEFAULT_USERNAME, 
        const char* card_number="4242424242424242", const char* exp_month="4", const char* exp_year="2021", const char* cvc="314",
        const char* description="Test Card Charge");

private:
    HttpsClient* client;
    char* _token;
    int connect();
    void disconnect();
    int get_token(char* token, const char* username, const char* card_number, const char* exp_month,
        const char* exp_year, const char* cvc);
    int send_charge(char *token, const char *username, const char *amount, const char *currency, const char *description);
};
