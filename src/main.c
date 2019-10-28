#include "espressif/esp_common.h"
#include "freertos/FreeRTOSConfig.h"
#include "freertos/task.h"
#include "gpio.h"
#include "uart.h"
#include "user_config.h"
#include "wifi_process.h"

#include "espressif/c_types.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "openssl/ssl.h"

#include "websocketclient.h"

#define local_host_url "wss://47.111.26.190:5041/websocket"
//#define local_host_url  "wss://echo.websocket.org"

static const char *payload = "Message from ESP8266 ";
char test_mode = 4;

typedef struct s_queuedata_t {
  uint16_t size;
  void *data;
} queuedata_t;

xQueueHandle Queue_Recv_Msg;

//测试数据
char *str =
    "{\"command\": \"CheckIn\",\"serialNumber\": "
    "\"LACMJWJAY6L2KRGL111A\",\"firmwareVersion\": "
    "\"3516EV100_SC2232_DI0001-G_V1.2.0.3\",\"macAddress\": "
    "\"01:02:03:04:05:06\",\"id\":\"1537894560\"}";

/**
 * @brief  websocket 连接回调
 * @note
 * @param  *ws: websocket对象
 * @retval None
 */
void websocket_connnect_cb(ws_info *ws) {
  os_printf("websocket has connected\r\n");
  os_printf("websocket send->%s\r\n", str);
  ws_send(ws, str, strlen(str));
}

void websocket_disconnnect_cb(ws_info *ws) {
  os_printf("websocket has disconnected\r\n");
}

/**
 * @brief  websocket 接收回调
 * @note
 * @param  *ws: websocket对象
 * @param  len: 数据长度
 * @param  *buf: 数据
 * @param  istext: 是否为文本数据
 * @retval None
 */
void websocket_recv_cb(ws_info *ws, int len, char *buf, bool istext) {
  os_printf("websocket_recv_cb->%d\r\n", len);

  if (istext) {
    char *data = (char *)zalloc(len);
    memcpy(data, buf, len);
    queuedata_t msg;
    msg.size = len;
    msg.data = data;
    xQueueSend(Queue_Recv_Msg, (void *)&msg, (portTickType)0);

  } else {
    os_printf("websocket recv data is binary,user can not analyze\r\n");
  }
}

/**
 * @brief  websocket处理任务
 * @note
 * @param  *ignore:
 * @retval None
 */
void task_websocket(void *ignore) {
  os_printf("task_websocket start \r\n");
  ws_info *ws = (ws_info *)zalloc(sizeof(ws_info));
  bool result = 0;
  queuedata_t msg;

  while (!wifi_check_station_connected()) {
    vTaskDelay(100 / portTICK_RATE_MS);
  }

  Queue_Recv_Msg = xQueueCreate(12, sizeof(queuedata_t));

  ws->onConnection = websocket_connnect_cb;
  ws->onDisConn = websocket_disconnnect_cb;
  ws->onReceive = websocket_recv_cb;

  os_printf("start to pingping send data... \r\n");
  ws_connect(ws, local_host_url);

  while (true) {
    result = xQueueReceive(Queue_Recv_Msg, (void *)&msg, 1);
    if (!result) {
      continue;
    }

    if (msg.size == 1) {
      char hearbeat = 0;
      hearbeat = ((char *)msg.data)[0];
      if (hearbeat == 'H') {
        os_printf("B \r\n");
        ws_send(ws, "B", 1);
      }
      os_free(msg.data);
      msg.data = NULL;
      continue;
    }

    // TODO: 解析json
    vTaskDelay(1 / portTICK_RATE_MS);
  }

  vTaskDelete(NULL);
}

/******************************************************************************
 * FunctionName : user_init
 * Description  : entry of user application, init user function here
 * Parameters   : none
 * Returns      : none
 *******************************************************************************/
void user_init(void) {
  os_printf("SDK version:%s %d\n", system_get_sdk_version(),
            system_get_free_heap_size());

  wifi_process_init();

  xTaskCreate(&task_websocket, "task_websocket", 2048, NULL, 1, NULL);
  // user_conn_init();
}

/******************************************************************************
 * FunctionName : user_rf_cal_sector_set
 * Description  : SDK just reversed 4 sectors, used for rf init data and
 *paramters. We add this function to force users to set rf cal sector, since we
 *don't know which sector is free in user's application. sector map for last
 *several sectors : ABCCC A : rf cal B : rf init data C : sdk parameters
 * Parameters   : none
 * Returns      : rf cal sector
 *******************************************************************************/
uint32 user_rf_cal_sector_set(void) {
  flash_size_map size_map = system_get_flash_size_map();
  uint32 rf_cal_sec = 0;
  switch (size_map) {
    case FLASH_SIZE_4M_MAP_256_256:
      rf_cal_sec = 128 - 5;
      break;

    case FLASH_SIZE_8M_MAP_512_512:
      rf_cal_sec = 256 - 5;
      break;

    case FLASH_SIZE_16M_MAP_512_512:
    case FLASH_SIZE_16M_MAP_1024_1024:
      rf_cal_sec = 512 - 5;
      break;

    case FLASH_SIZE_32M_MAP_512_512:
    case FLASH_SIZE_32M_MAP_1024_1024:
      rf_cal_sec = 1024 - 5;
      break;

    default:
      rf_cal_sec = 0;
      break;
  }

  return rf_cal_sec;
}
