#ifndef __WIFI_STATE_MACHINE_H__
#define __WIFI_STATE_MACHINE_H__

#include "espressif/c_types.h"
#include "espressif/esp_wifi.h"

typedef void (* wifi_state_cb_t)();
typedef void (* wifi_disco_cb_t)(uint8_t reason);

void set_on_station_first_connect(wifi_state_cb_t cb);
void set_on_station_connect(wifi_state_cb_t cb);
void set_on_station_disconnect(wifi_disco_cb_t cb);
void set_on_client_connect(wifi_state_cb_t cb);
void set_on_client_disconnect(wifi_state_cb_t cb);

WIFI_MODE init_esp_wifi();
bool start_wifi_station(const char * ssid, const char * pass);
bool stop_wifi_station();
bool start_wifi_ap(const char * ssid, const char * pass);
bool stop_wifi_ap();

bool wifi_station_connected();
bool wifi_ap_enabled();

#endif /* _WIFI_STATE_MACHINE_H_ */