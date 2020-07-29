#include "Particle.h"
#include "stripe.h"

SYSTEM_THREAD(ENABLED);


Serial1LogHandler logHandler(115200, LOG_LEVEL_TRACE, {{"app", LOG_LEVEL_TRACE}});

#define ONE_DAY_MILLIS (24 * 60 * 60 * 1000)
unsigned long lastSync = millis();

Stripe stripe;

/**
 * Expose a command interface function on the Particle console to test sending
 * charges to the Stripe payment processor.
 */
int cmd(String extra)
{
  const char* provider = "";
  const char* amount = "";
  JSONValue json = JSONValue::parseCopy(extra, extra.length());
  if (!json.isObject()) return -1;

  JSONObjectIterator iter(json);
  while (iter.next())
  {
    if (iter.name() == "processor") provider = (const char *)iter.value().toString();
    if (iter.name() == "amount") amount = iter.value().toString().data();
  }
  if (strcmp(provider,"stripe") == 0 && amount != NULL)
  {
    stripe.charge(amount);
  }
  return 0;
}

void setup()
{
  Serial.begin(9600);
  Serial.print(Time.timeStr());
  Particle.function("Command", &cmd);
}

void loop()
{
  static uint32_t thirty_sec_timer = System.uptime();
  uint32_t curr_time = System.uptime();

  if (curr_time - thirty_sec_timer > 30 && Network.ready())
  {
    thirty_sec_timer = curr_time;
    if (millis() - lastSync > ONE_DAY_MILLIS)
    {
      Particle.syncTime();
      lastSync = millis();
    }
  }
}