#include "wifi_process.h"
#include "esp_common.h"
#include "user_config.h"
#include "wifi_state_machine.h"

static os_timer_t timer;

bool wifi_connect_flag = false;  // wifi连接路由标识

LOCAL void ICACHE_FLASH_ATTR wait_for_connection_ready(uint8 flag) {
  os_timer_disarm(&timer);
  if (wifi_station_connected()) {
    os_printf("connected\n");
    wifi_connect_flag = true;
    // sntp_setservername(0, "0.cn.pool.ntp.org");
    // sntp_setservername(1, "1.cn.pool.ntp.org");
    // sntp_setservername(2, "2.cn.pool.ntp.org");
    // sntp_init();
    // os_printf("sntp_init\n");
  } else {
    os_printf("reconnect after 2s\n");
    os_timer_setfn(&timer, (os_timer_func_t *)wait_for_connection_ready, NULL);
    os_timer_arm(&timer, 2000, 0);
  }
}

LOCAL void ICACHE_FLASH_ATTR on_wifi_connect() {
  os_timer_disarm(&timer);
  os_timer_setfn(&timer, (os_timer_func_t *)wait_for_connection_ready, NULL);
  os_timer_arm(&timer, 100, 0);
}

LOCAL void ICACHE_FLASH_ATTR on_wifi_disconnect(uint8_t reason) {
  os_printf("disconnect %d\n", reason);
  wifi_connect_flag = false;
}

/**
 * @brief  wifi初始化
 * @note
 * @retval None
 */
void wifi_process_init(void) {
  wifi_connect_flag = false;

  set_on_station_connect(on_wifi_connect);
  set_on_station_disconnect(on_wifi_disconnect);
  init_esp_wifi();
  stop_wifi_ap();
  start_wifi_station(USER_SSID, USER_PASSWORD);
}

/**
 * @brief  获取wifi连接标识
 * @note
 * @retval
 */
bool wifi_check_station_connected(void) { return wifi_connect_flag; }
