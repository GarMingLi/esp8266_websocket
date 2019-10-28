

#include "espressif/esp_common.h"
#include "espressif/esp_libc.h"
#include "espressif/esp_misc.h"

#include "espressif/esp_softap.h"
#include "espressif/esp_sta.h"

#include "wifi_state_machine.h"

#include "stddef.h"

wifi_state_cb_t on_station_first_connect = NULL;
wifi_state_cb_t on_station_connect = NULL;
wifi_disco_cb_t on_station_disconnect = NULL;

wifi_state_cb_t on_client_connect = NULL;
wifi_state_cb_t on_client_disconnect = NULL;

volatile bool wifi_station_static_ip = false;
volatile bool wifi_station_is_connected = false;

/**
 * @brief  wifi事件处理
 * @note   
 * @param  *event: 
 * @retval 
 */
void ICACHE_FLASH_ATTR wifi_event_handler_cb(System_Event_t *event) {
  static bool station_was_connected = false;
  if (event == NULL) {
    return;
  }

  os_printf("[WiFi] event %u\n", event->event_id);

  switch (event->event_id) {
    case EVENT_STAMODE_DISCONNECTED:
      wifi_station_is_connected = false;
      Event_StaMode_Disconnected_t *ev =
          (Event_StaMode_Disconnected_t *)&event->event_info;
      if (on_station_disconnect) {
        on_station_disconnect(ev->reason);
      }
      break;
    case EVENT_STAMODE_CONNECTED:
      if (wifi_station_static_ip) {
        wifi_station_is_connected = true;
        if (!station_was_connected) {
          station_was_connected = true;
          if (on_station_first_connect) {
            on_station_first_connect();
          }
        }
        if (on_station_connect) {
          on_station_connect();
        }
      }
      break;
    case EVENT_STAMODE_DHCP_TIMEOUT:
      if (wifi_station_is_connected) {
        wifi_station_is_connected = false;
        if (on_station_disconnect) {
          on_station_disconnect(REASON_UNSPECIFIED);
        }
      }
      break;
    case EVENT_STAMODE_GOT_IP:
      wifi_station_is_connected = true;
      if (!station_was_connected) {
        station_was_connected = true;
        if (on_station_first_connect) {
          on_station_first_connect();
        }
      }
      if (on_station_connect) {
        on_station_connect();
      }
      break;

    case EVENT_SOFTAPMODE_STACONNECTED:
      if (on_client_connect) {
        on_client_connect();
      }
      break;
    case EVENT_SOFTAPMODE_STADISCONNECTED:
      if (on_client_disconnect) {
        on_client_disconnect();
      }
      break;
    default:
      break;
  }
}


/**
 * @brief  首次连接路由处理回调
 * @note   
 * @param  cb: 
 * @retval 
 */
void ICACHE_FLASH_ATTR set_on_station_first_connect(wifi_state_cb_t cb) {
  on_station_first_connect = cb;
}

/**
 * @brief  连接路由回调
 * @note   
 * @param  cb: 
 * @retval 
 */
void ICACHE_FLASH_ATTR set_on_station_connect(wifi_state_cb_t cb) {
  on_station_connect = cb;
}

/**
 * @brief  断开路由连接回调
 * @note   
 * @param  cb: 
 * @retval 
 */
void ICACHE_FLASH_ATTR set_on_station_disconnect(wifi_disco_cb_t cb) {
  on_station_disconnect = cb;
}


/**
 * @brief  节点设备接入回调
 * @note   
 * @param  cb: 
 * @retval 
 */
void ICACHE_FLASH_ATTR set_on_client_connect(wifi_state_cb_t cb) {
  on_client_connect = cb;
}

/**
 * @brief  节点设备断开回调
 * @note   
 * @param  cb: 
 * @retval 
 */
void ICACHE_FLASH_ATTR set_on_client_disconnect(wifi_state_cb_t cb) {
  on_client_disconnect = cb;
}

/**
 * @brief  设置wifi模式
 * @note   
 * @param  mode: 
 * @retval 
 */
bool ICACHE_FLASH_ATTR wifi_set_mode(WIFI_MODE mode) {
  if (!mode) {
    bool s = wifi_set_opmode(mode);
    wifi_fpm_open();
    wifi_fpm_set_sleep_type(MODEM_SLEEP_T);
    wifi_fpm_do_sleep(0xFFFFFFFF);
    return s;
  }
  wifi_fpm_close();
  return wifi_set_opmode(mode);
}

/**
 * @brief  初始化wifi
 * @note   
 * @retval 
 */
WIFI_MODE ICACHE_FLASH_ATTR init_esp_wifi() {
  wifi_set_event_handler_cb(wifi_event_handler_cb);
  WIFI_MODE mode = wifi_get_opmode_default();
  wifi_set_mode(mode);
  return mode;
}

/**
 * @brief  开始station， 设备连接路由
 * @note   
 * @param  *ssid: wifi名
 * @param  *pass: 密码
 * @retval 
 */
bool ICACHE_FLASH_ATTR start_wifi_station(const char *ssid, const char *pass) {
  WIFI_MODE mode = wifi_get_opmode();
  if ((mode & STATION_MODE) == 0) {
    mode |= STATION_MODE;
    if (!wifi_set_mode(mode)) {
      os_printf("Failed to enable Station mode!\n");
      return false;
    }
  }
  if (!ssid) {
    os_printf("No SSID Given. Will connect to the station saved in flash\n");
    return true;
  }
  struct station_config config;
  memset(&config, 0, sizeof(struct station_config));
  strcpy((char *)config.ssid, ssid);
  if (pass) {
    strcpy((char *)config.password, pass);
  }
  if (!wifi_station_set_config(&config)) {
    os_printf("Failed to set Station config!\n");
    return false;
  }

  if (!wifi_station_dhcpc_status()) {
    os_printf("DHCP is not started. Starting it...\n");
    if (!wifi_station_dhcpc_start()) {
      os_printf("DHCP start failed!\n");
      return false;
    }
  }
  return wifi_station_connect();
}


/**
 * @brief  停止station模式
 * @note   
 * @retval 
 */
bool ICACHE_FLASH_ATTR stop_wifi_station(void) {
  WIFI_MODE mode = wifi_get_opmode();
  mode &= ~STATION_MODE;
  if (!wifi_set_mode(mode)) {
    os_printf("Failed to disable Station mode!\n");
    return false;
  }
  return true;
}

/**
 * @brief  开始ap模式
 * @note   
 * @param  *ssid: 
 * @param  *pass: 
 * @retval 
 */
bool ICACHE_FLASH_ATTR start_wifi_ap(const char *ssid, const char *pass) {
  WIFI_MODE mode = wifi_get_opmode();
  if ((mode & SOFTAP_MODE) == 0) {
    mode |= SOFTAP_MODE;
    if (!wifi_set_mode(mode)) {
      os_printf("Failed to enable AP mode!\n");
      return false;
    }
  }
  if (!ssid) {
    os_printf("No SSID Given. Will start the AP saved in flash\n");
    return true;
  }
  struct softap_config config;
  bzero(&config, sizeof(struct softap_config));
  sprintf((char *)config.ssid, ssid);
  if (pass) {
    sprintf((char *)config.password, pass);
  }
  config.ssid_len = 0;
  config.beacon_interval = 100;
  config.max_connection = 6;
  return wifi_softap_set_config(&config);
}

/**
 * @brief  停止AP模式
 * @note   
 * @retval 
 */
bool ICACHE_FLASH_ATTR stop_wifi_ap(void) {
  WIFI_MODE mode = wifi_get_opmode();
  mode &= ~SOFTAP_MODE;
  if (!wifi_set_mode(mode)) {
    os_printf("Failed to disable AP mode!\n");
    return false;
  }
  return true;
}

/**
 * @brief  获取wifi连接状态
 * @note   
 * @retval 
 */
bool ICACHE_FLASH_ATTR wifi_station_connected(void) {
  if (!wifi_station_is_connected) {
    return false;
  }
  WIFI_MODE mode = wifi_get_opmode();
  if ((mode & STATION_MODE) == 0) {
    return false;
  }
  STATION_STATUS wifistate = wifi_station_get_connect_status();
  wifi_station_is_connected =
      (wifistate == STATION_GOT_IP ||
       (wifi_station_static_ip && wifistate == STATION_CONNECTING));
  return wifi_station_is_connected;
}

/**
 * @brief  检查是否使能AP模式
 * @note   
 * @retval 
 */
bool ICACHE_FLASH_ATTR wifi_ap_enabled(void) {
  return !!(wifi_get_opmode() & SOFTAP_MODE);
}

