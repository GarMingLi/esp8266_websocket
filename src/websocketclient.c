#include "websocketclient.h"

#include <stdarg.h>
#include "string.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/timers.h"
#include "lwip/dns.h"
#include "lwip/err.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"

#include "mbedtls/base64.h"
#include "mbedtls/sha1.h"

#include "freertos/semphr.h"

xTimerHandle heartbeat_timer_handle;
ws_info* ptr_ws = NULL;

xSemaphoreHandle xSemaphore = NULL;

static const header_t DEFAULT_HEADERS[] = {
    {"User-Agent", "SmartSocket"}, {"Sec-WebSocket-Protocol", "chat"}, {0}};

static const header_t* EMPTY_HEADERS =
    DEFAULT_HEADERS + sizeof(DEFAULT_HEADERS) / sizeof(header_t) - 1;

static char recv_buf[RECV_BUF_SIZE];

static void task_websocket_recv(void* param);
static void heartbeat_init(void);

/**
 * @brief 字符串拼接
 * @note
 * @param  dst: 拼接后数据尾地址
 * @param  src: 源数据地址
 * @retval
 */
static char* _strcpy(char* dst, char* src) {
  while (*dst++ = *src++)
    ;
  return dst - 1;
}

/**
 * @brief  计算http头部字段总长度
 * @note
 * @param  headers: 头部字段
 * @retval 头部字段总长度
 */
static int headers_length(const header_t* headers) {
  int length = 0;
  for (; headers->key; headers++)
    length += strlen(headers->key) + strlen(headers->value) + 4;
  return length;
}

/**
 * @brief  格式化头部字段
 * @note
 * @param  buf:
 * @retval
 */
static char* sprintf_headers(char* buf, ...) {
  char* dst = buf;
  va_list args;
  va_start(args, buf);
  for (header_t* header_set = va_arg(args, header_t*); header_set;
       header_set = va_arg(args, header_t*))
    for (header_t* header = header_set; header->key; header++) {
      va_list args2;
      va_start(args2, buf);
      for (header_t* header_set2 = va_arg(args2, header_t*); header_set2;
           header_set2 = va_arg(args2, header_t*))
        for (header_t* header2 = header_set2; header2->key; header2++) {
          if (header == header2) goto ok;
          if (!strcasecmp(header->key, header2->key)) goto skip;
        }
    ok:
      dst = _strcpy(dst, header->key);
      dst = _strcpy(dst, ": ");
      dst = _strcpy(dst, header->value);
      dst = _strcpy(dst, "\r\n");
    skip:;
    }
  dst = _strcpy(dst, "\r\n");
  return dst;
}

/**
 * @brief 哈希编码
 * @note
 * @param  data: 源数据
 * @param  len:源数据长度
 * @retval 哈希编码数据
 */
static char* crypto_sha1(char* data, unsigned int len) {
  mbedtls_sha1_context ctx;

  mbedtls_sha1_init(&ctx);
  mbedtls_sha1_starts(&ctx);
  mbedtls_sha1_update(&ctx, data, len);
  uint8_t* digest = (uint8_t*)zalloc(20);
  mbedtls_sha1_finish(&ctx, digest);
  return (char*)digest;  // Requires free
}

/**
 * @brief  获取key和期望key
 * @note
 * @param  **key: key
 * @param  **expectedKey: 期望key
 * @retval None
 */
static void generate_seckeys(char** key, char** expectedKey) {
  char rndData[16];
  int i;
  int blen = 0;
  for (i = 0; i < 16; i++) {
    rndData[i] = (char)os_random();
  }

  os_printf("key rand-> ");
  for (uint8_t i = 0; i < 16; i++) {
    os_printf("%02x", rndData[i]);
  }
  os_printf("\r\n");

  blen = (16 + 2) / 3 * 4;
  char* out_key = (char*)zalloc(blen + 1);
  int out_key_len = 0;
  mbedtls_base64_encode(out_key, blen + 1, &out_key_len, rndData, 16);
  *key = out_key;

  char keyWithGuid[24 + WS_GUID_LENGTH];
  memcpy(keyWithGuid, *key, 24);
  memcpy(keyWithGuid + 24, WS_GUID, WS_GUID_LENGTH);

  char* keyEncrypted = crypto_sha1(keyWithGuid, 24 + WS_GUID_LENGTH);

  blen = (20 + 2) / 3 * 4;
  char* out_expected = (char*)zalloc(blen + 1);
  int out_expected_len = 0;
  mbedtls_base64_encode(out_expected, blen + 1, &out_expected_len, keyEncrypted,
                        20);
  *expectedKey = out_expected;

  os_free(keyEncrypted);
}

/**
 * @brief  连接超时
 * @note
 * @param  *arg:
 * @retval None
 */
static void ws_connect_timeout(void* arg) {
  os_printf("ws_connect Timeout\n");
  ws_info* ws = (ws_info*)arg;

  if (ws->onFailure) ws->onFailure(ws, eFailed_ConnTimeout);
  // disconnect_callback(arg);
}

/**
 * @brief  开始连接超时
 * @note
 * @param  ws: websocket对象
 * @retval None
 */
static void ws_connect_timeout_start(ws_info* ws) {
  os_timer_disarm(&ws->timeoutTimer);
  os_timer_setfn(&ws->timeoutTimer, (os_timer_func_t*)ws_connect_timeout, ws);
  os_timer_arm(&ws->timeoutTimer, 10 * 1000, false);
}

/**
 * @brief  提取url参数
 * @note
 * @param  ws: websocket对象
 * @param  url: url
 * @retval None
 */
static void ws_extract_param(ws_info* ws, char* url) {
  if (ws == NULL) {
    os_printf("ws_connect ws_info argument is null!");
    return;
  }

  if (url == NULL) {
    os_printf("url is null!");
    return;
  }

  // 提取协议，ws或wss
  bool isSecure =
      strncasecmp(url, PROTOCOL_SECURE, strlen(PROTOCOL_SECURE)) == 0;
  if (isSecure) {
    url += strlen(PROTOCOL_SECURE);
  } else {
    if (strncasecmp(url, PROTOCOL_INSECURE, strlen(PROTOCOL_INSECURE)) != 0) {
      os_printf("Failed to extract protocol from: %s\n", url);
      if (ws->onFailure) ws->onFailure(ws, eFailed_GetProtocol);
      return;
    }
    url += strlen(PROTOCOL_INSECURE);
  }

  //提取路径
  char* path = strchr(url, '/');

  //提取域名，可能包含端口
  char hostname[256];
  if (path) {
    if (path - url >= sizeof(hostname)) {
      os_printf("Hostname too large");
      if (ws->onFailure) ws->onFailure(ws, eFailed_HostTooLarge);
      return;
    }
    memcpy(hostname, url, path - url);
    hostname[path - url] = '\0';
  } else {
    //没有找到路径，只有主机名和端口
    memcpy(hostname, url, strlen(url));
    hostname[strlen(url)] = '\0';
    path = "/";
  }

  //提取端口
  char* portInHostname = strchr(hostname, ':');
  int port;
  if (portInHostname) {
    port = atoi(portInHostname + 1);
    if (port <= 0 || port > PORT_MAX_VALUE) {
      os_printf("Invalid port number\n");
      if (ws->onFailure) ws->onFailure(ws, eFailed_InvalidPort);
      return;
    }

    hostname[strlen(hostname) - strlen(portInHostname)] = '\0';
  } else {
    port = isSecure ? PORT_SECURE : PORT_INSECURE;
  }

  if (strlen(hostname) == 0) {
    os_printf("Failed to extract hostname\n");
    if (ws->onFailure) ws->onFailure(ws, eFailed_InvalidHost);
    return;
  }

  os_printf("secure protocol = %d\n", isSecure);
  os_printf("hostname = %s\n", hostname);
  os_printf("port = %d\n", port);
  os_printf("path = %s\n", path);

  ws->connectionState = eWSState_Extract;
  ws->isSecure = isSecure;
  ws->hostname = strdup(hostname);
  ws->port = port;
  ws->path = strdup(path);
  ws->expectedSecKey = NULL;
  ws->frameBuffer = NULL;
  ws->frameBufferLen = 0;
  ws->payloadBuffer = NULL;
  ws->payloadBufferLen = 0;
  ws->payloadOriginalOpCode = 0;
  ws->heartbeat = 0;
}

/**
 * @brief  socket连接
 * @note
 * @param  ws: websocket对象
 * @retval None
 */
static void socket_connect(ws_info* ws) {
  if (ws == NULL) {
    os_printf("ws_connect ws_info argument is null!");
    return;
  }

  const struct addrinfo hints = {
      .ai_family = AF_INET,
      .ai_socktype = SOCK_STREAM,
  };
  struct addrinfo* res;
  struct in_addr* addr;
  int fd = -1;
  uint8_t getaddr_cnt = 0;
  uint8_t socketinit_cnt = 0;
  uint8_t connect_cnt = 0;

  while (1) {
    char port_str[25] = {0};
    sprintf(port_str, "%d", ws->port);
    ws->connectionState = eWSState_Socket;
    int err = getaddrinfo(ws->hostname, port_str, &hints, &res);
    if (err != 0 || res == NULL) {
      os_printf("DNS lookup failed err=%d res=%p\r\n", err, res);
      getaddr_cnt++;
      if (getaddr_cnt > 10) {
        if (ws->onFailure) ws->onFailure(ws, eFailed_GetIP);
        break;
      }
      vTaskDelay(1000 / portTICK_RATE_MS);
      continue;
    }

    addr = &((struct sockaddr_in*)res->ai_addr)->sin_addr;
    os_printf("DNS lookup succeeded. IP=%s\r\n", inet_ntoa(*addr));

    fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd < 0) {
      os_printf("... Failed to allocate socket.\r\n");
      freeaddrinfo(res);
      socketinit_cnt++;
      if (socketinit_cnt > 10) {
        if (ws->onFailure) ws->onFailure(ws, eFailed_SocketInit);
        break;
      }
      vTaskDelay(1000 / portTICK_RATE_MS);
      continue;
    }
    os_printf("... allocated socket\r\n");

    ws_connect_timeout_start(ws);
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
      os_printf("... socket connect failed errno=%d\r\n", errno);
      close(fd);
      freeaddrinfo(res);
      connect_cnt++;
      if (connect_cnt > 10) {
        if (ws->onFailure) ws->onFailure(ws, eFailed_SocketConn);
        break;
      }
      vTaskDelay(4000 / portTICK_RATE_MS);
      continue;
    } else {
      os_printf("... connected\r\n");
      if (ws->isSecure) {
        ws->connectionState = eWSState_SSL;
      } else {
        ws->connectionState = eWSState_Conn;
      }
      freeaddrinfo(res);
      break;
    }
  }

  ws->socket_fd = fd;
  os_printf("ws->socket_fd->%d\r\n", ws->socket_fd);
}

/**
 * @brief  SSL连接
 * @note
 * @param  ws: websocket对象
 * @retval None
 */
static void openssl_connect(ws_info* ws) {
  if (ws == NULL) {
    os_printf("ws_connect ws_info argument is null!");
    return;
  }

  SSL_CTX* ctx;
  SSL* ssl = NULL;
  int ret = 0;

  os_printf("create SSL context ......");
  ctx = SSL_CTX_new(TLSv1_2_client_method());
  if (!ctx) {
    os_printf("failed\n");
    if (ws->onFailure) ws->onFailure(ws, eFailed_SSL_CTX);
    return;
  }
  os_printf("OK\n");

  os_printf("set SSL context read buffer size ......");
  SSL_CTX_set_default_read_buffer_len(ctx, OPENSSL_FRAGMENT_SIZE);

  os_printf("OK\n");

  os_printf("create SSL ......");
  ssl = SSL_new(ctx);
  if (!ssl) {
    os_printf("failed\n");
    SSL_CTX_free(ctx);
    if (ws->onFailure) ws->onFailure(ws, eFailed_SSL);
    return;
  }
  os_printf("OK\n");

  SSL_set_fd(ssl, ws->socket_fd);

  ws_connect_timeout_start(ws);
  os_printf("SSL connected to %s port %d ......", ws->hostname, ws->port);
  ret = SSL_connect(ssl);
  if (!ret) {
    os_printf("failed, return [-0x%x]\n", -ret);
    SSL_free(ssl);
    if (ws->onFailure) ws->onFailure(ws, eFailed_SSLConn);
    return;
  }
  os_printf("OK\n");
  ws->connectionState = eWSState_Conn;
  ws->ssl = ssl;
}

uint32_t cnt = 0;
/**
 * @brief  websocket发送数据帧
 * @note
 * @param  ws:
 * @param  opCode:
 * @param  *data:
 * @param  len:
 * @retval None
 */
static void ws_sendFrame(ws_info* ws, int opCode, const char* data,
                         unsigned short len) {
  xSemaphoreTake(xSemaphore, 1000);

  cnt++;
  os_printf("send %d time\r\n", cnt);
  if (ws->connectionState == eWSState_Disconn) {
    os_printf("already in closing state\n");
    return;
  } else if (ws->connectionState != eWSState_HandShake) {
    os_printf("can't send message while not in a handshake state\n");
    return;
  }

  char* b = zalloc(10 + len);  // 10 bytes = worst case scenario for framming
  if (b == NULL) {
    os_printf("Out of memory when receiving message, disconnecting...\n");

    if (ws->onFailure) ws->onFailure(ws, eFailed_NotBuff);
    return;
  }

  b[0] = 1 << 7;  // has fin
  b[0] += opCode;
  b[1] = 1 << 7;  // has mask
  int bufOffset;
  if (len < 126) {
    b[1] += len;
    bufOffset = 2;
  } else if (len < 0x10000) {
    b[1] += 126;
    b[2] = len >> 8;
    b[3] = len;
    bufOffset = 4;
  } else {
    b[1] += 127;
    b[2] = len >> 24;
    b[3] = len >> 16;
    b[4] = len >> 8;
    b[5] = len;
    bufOffset = 6;
  }

  // Random mask:
  b[bufOffset] = (char)os_random();
  b[bufOffset + 1] = (char)os_random();
  b[bufOffset + 2] = (char)os_random();
  b[bufOffset + 3] = (char)os_random();
  bufOffset += 4;

  // Copy data to buffer
  if (len > 0) {
    memcpy(b + bufOffset, data, len);
  }

  // Apply mask to encode payload
  int i;
  for (i = 0; i < len; i++) {
    b[bufOffset + i] ^= b[bufOffset - 4 + i % 4];
  }
  bufOffset += len;

  if (ws->isSecure) {
    int ret = SSL_write(ws->ssl, b, bufOffset);
    if (ret <= 0) {
      os_printf("failed, return [-0x%x]\n", -ret);
      if (ws->onFailure) ws->onFailure(ws, eFailed_Send);
      return;
    }
  } else {
    int ret = send(ws->socket_fd, b, bufOffset, 0);
    if (ret <= 0) {
      os_printf("failed, return [-0x%x]\n", -ret);
      if (ws->onFailure) ws->onFailure(ws, eFailed_Send);
      return;
    }
  }

  os_free(b);
  os_printf("send system_get_free_heap_size %d\n", system_get_free_heap_size());

  xSemaphoreGive(xSemaphore);
}

/**
 * @brief  websocket数据接收处理
 * @note
 * @param  ws: websocket对象
 * @param  buf: 接收缓存
 * @param  len: 接收数据长度
 * @retval None
 */
static void ws_recv_process(ws_info* ws, char* buf, int16_t len) {
  char* b = buf;
  //不为空，把新内容追加到之前的数据
  if (ws->frameBuffer != NULL) {
    os_printf("Appending new frameBuffer to old one \n");

    ws->frameBuffer = realloc(ws->frameBuffer, ws->frameBufferLen + len);
    if (ws->frameBuffer == NULL) {
      os_printf("Failed to allocate new framebuffer, disconnecting...\n");
      if (ws->onFailure) ws->onFailure(ws, eFailed_NotBuff);
      return;
    }
    memcpy(ws->frameBuffer + ws->frameBufferLen, b, len);

    ws->frameBufferLen += len;

    len = ws->frameBufferLen;
    b = ws->frameBuffer;
    os_printf("New frameBufferLen: %d\n", len);
  }

  while (b != NULL) {
    int isFin = b[0] & 0x80 ? 1 : 0;
    int opCode = b[0] & 0x0f;
    int hasMask = b[1] & 0x80 ? 1 : 0;
    uint64_t payloadLength = b[1] & 0x7f;
    int bufOffset = 2;
    if (payloadLength == 126) {  // 126,接下来的2个字节表示长度
      payloadLength = (b[2] << 8) + b[3];
      bufOffset = 4;
    } else if (payloadLength == 127) {  // 127,接下来的8个字节表示长度
      payloadLength |= ((uint64_t)(b[2]) << 56);
      payloadLength |= ((uint64_t)(b[3]) << 48);
      payloadLength |= ((uint64_t)(b[4]) << 40);
      payloadLength |= ((uint64_t)(b[5]) << 32);
      payloadLength |= ((uint64_t)(b[6]) << 24);
      payloadLength |= ((uint64_t)(b[7]) << 16);
      payloadLength |= ((uint64_t)(b[8]) << 8);
      payloadLength |= ((uint64_t)(b[9]) << 0);
      bufOffset = 10;
    }

    if (hasMask) {
      int maskOffset = bufOffset;
      bufOffset += 4;

      int i;
      for (i = 0; i < payloadLength; i++) {
        //使用掩码解码载荷数据
        b[bufOffset + i] ^= b[maskOffset + i % 4];
      }
    }

    if (payloadLength > len - bufOffset) {
      os_printf("INCOMPLETE Frame \n");
      if (ws->frameBuffer == NULL) {
        os_printf("Allocing new frameBuffer \n");
        ws->frameBuffer = zalloc(len);
        if (ws->frameBuffer == NULL) {
          os_printf("Failed to allocate framebuffer, disconnecting... \n");

          if (ws->onFailure) ws->onFailure(ws, eFailed_NotBuff);
          return;
        }
        memcpy(ws->frameBuffer, b, len);
        ws->frameBufferLen = len;
      }
      break;  // since the buffer were already concat'ed, wait for the next
              // receive
    }

    if (!isFin) {
      os_printf(
          "PARTIAL frame! Should concat payload and later restore "
          "opcode\n");
      if (ws->payloadBuffer == NULL) {
        os_printf("Allocing new payloadBuffer \n");
        ws->payloadBuffer = zalloc(payloadLength);
        if (ws->payloadBuffer == NULL) {
          os_printf("Failed to allocate payloadBuffer, disconnecting...\n");

          if (ws->onFailure) ws->onFailure(ws, eFailed_NotBuff);
          return;
        }
        memcpy(ws->payloadBuffer, b + bufOffset, payloadLength);
        ws->frameBufferLen = payloadLength;
        ws->payloadOriginalOpCode = opCode;
      } else {
        os_printf("Appending new payloadBuffer to old one \n");
        ws->payloadBuffer =
            realloc(ws->payloadBuffer, ws->payloadBufferLen + payloadLength);
        if (ws->payloadBuffer == NULL) {
          os_printf("Failed to allocate new framebuffer, disconnecting...\n");

          if (ws->onFailure) ws->onFailure(ws, eFailed_NotBuff);
          return;
        }
        memcpy(ws->payloadBuffer + ws->payloadBufferLen, b + bufOffset,
               payloadLength);

        ws->payloadBufferLen += payloadLength;
      }
    } else {
      char* payload;
      if (opCode == WS_OPCODE_CONTINUATION) {
        os_printf("restoring original opcode\n");
        if (ws->payloadBuffer == NULL) {
          os_printf(
              "Got FIN continuation frame but didn't receive any "
              "beforehand, disconnecting...\n");

          if (ws->onFailure) ws->onFailure(ws, eFailed_NotContinue);
          return;
        }
        // concat buffer with payload
        payload = zalloc(ws->payloadBufferLen + payloadLength);

        if (payload == NULL) {
          os_printf("Failed to allocate new framebuffer, disconnecting...\n");

          if (ws->onFailure) ws->onFailure(ws, eFailed_NotBuff);
          return;
        }
        memcpy(payload, ws->payloadBuffer, ws->payloadBufferLen);
        memcpy(payload + ws->payloadBufferLen, b + bufOffset, payloadLength);

        os_free(ws->payloadBuffer);
        ws->payloadBuffer = NULL;

        payloadLength += ws->payloadBufferLen;
        ws->payloadBufferLen = 0;

        opCode = ws->payloadOriginalOpCode;
        ws->payloadOriginalOpCode = 0;
      } else {
        int extensionDataOffset = 0;

        if (opCode == WS_OPCODE_CLOSE && payloadLength > 0) {
          unsigned int reasonCode = b[bufOffset] << 8 + b[bufOffset + 1];
          os_printf("Closing due to: %d\n",
                    reasonCode);  // Must not be shown to client as per spec
          extensionDataOffset += 2;
        }

        payload = zalloc(payloadLength - extensionDataOffset + 1);
        if (payload == NULL) {
          os_printf("Failed to allocate payload, disconnecting...\n");

          if (ws->onFailure) ws->onFailure(ws, eFailed_NotBuff);
          return;
        }

        memcpy(payload, b + bufOffset + extensionDataOffset,
               payloadLength - extensionDataOffset);
        payload[payloadLength - extensionDataOffset] = '\0';
      }

      if (opCode == WS_OPCODE_CLOSE) {
        os_printf("Closing message: %s\n",
                  payload);  // Must not be shown to client as per spec

        ws_sendFrame(ws, WS_OPCODE_CLOSE, (const char*)(b + bufOffset),
                     (unsigned short)payloadLength);
        if (ws->onDisConn) ws->onDisConn(ws);
        ws->connectionState = 4;
      } else if (opCode == WS_OPCODE_PING) {
        os_printf("pong...\r\n");
        ws_sendFrame(ws, WS_OPCODE_PONG, (const char*)(b + bufOffset),
                     (unsigned short)payloadLength);
      } else if (opCode == WS_OPCODE_PONG) {
        os_printf("--->pong...\r\n");
        // ping alarm was already reset...
      } else {
        //负载数据
        os_printf("get data ------->%s\r\n", payload);
        bool is_text = false;
        if (opCode == WS_OPCODE_TEXT) {
          is_text = true;
        }
        if (ws->onReceive) ws->onReceive(ws, payloadLength, payload, is_text);
      }
      os_free(payload);
    }

    bufOffset += payloadLength;
    if (bufOffset == len) {  // (bufOffset > len) won't happen here because
                             // it's being checked earlier
      b = NULL;
      if (ws->frameBuffer !=
          NULL) {  // the last frame inside buffer was processed
        os_free(ws->frameBuffer);
        ws->frameBuffer = NULL;
        ws->frameBufferLen = 0;
      }
    } else {
      len -= bufOffset;
      b += bufOffset;  // move b to next frame
      if (ws->frameBuffer != NULL) {
        os_printf("Reallocing frameBuffer to remove consumed frame\n");

        ws->frameBuffer = realloc(ws->frameBuffer, ws->frameBufferLen + len);
        if (ws->frameBuffer == NULL) {
          os_printf("Failed to allocate new frame buffer, disconnecting...\n");

          if (ws->onFailure) ws->onFailure(ws, eFailed_NotBuff);
          return;
        }
        memcpy(ws->frameBuffer + ws->frameBufferLen, b, len);

        ws->frameBufferLen += len;
        b = ws->frameBuffer;
      }
    }
  }
}

/**
 * @brief  websocket 握手接收处理
 * @note
 * @param  *ws: websocket接收对象
 * @param  *buf: 接收数据缓存
 * @param  len: 接收数据缓存长度
 * @retval None
 */
static void ws_handshake_recv_process(ws_info* ws, char* buf, int16_t len) {
  os_printf("ws_handshake_recv_process %d ->%s\n", len, buf);

  //检查服务器是否有切换协议
  if (strstr(buf, WS_HTTP_SWITCH_PROTOCOL_HEADER) == NULL) {
    os_printf("Server is not switching protocols\n");
    if (ws->onFailure) ws->onFailure(ws, eFailed_ErrorProtocol);
    return;
  }

  // 检查服务器密钥是否有效
  if (strstr(buf, ws->expectedSecKey) == NULL) {
    os_printf("Server has invalid response\n");
    if (ws->onFailure) ws->onFailure(ws, eFailed_InvalidKey);
    return;
  }

  os_printf("Server response is valid, it's now a websocket!\n");
  ws->connectionState = eWSState_HandShake;

  if (ws->onConnection) ws->onConnection(ws);

  char* data = strstr(buf, "\r\n\r\n");
  unsigned short dataLength = len - (data - buf) - 4;

  os_printf("dataLength = %d\n", len - (data - buf) - 4);

  // 握手包中包含了帧数据
  if (data != NULL && dataLength > 0) {
    ws_recv_process(ws, data + 4, dataLength);
  }
}

/**
 * @brief  websocket握手
 * @note
 * @param  ws: websocket对象
 * @retval None
 */
static void ws_handshake(ws_info* ws) {
  char* key;

  generate_seckeys(&key, &ws->expectedSecKey);
  os_printf("base64 key data->%s\r\n", key);
  os_printf("expected key data->%s\r\n", ws->expectedSecKey);

  header_t headers[] = {
      {"Upgrade", "websocket"},
      {"Connection", "Upgrade"},
      {"Sec-WebSocket-Key", key},
      {"Sec-WebSocket-Version", "13"},
      {0},
  };

  const header_t* extraHeaders = EMPTY_HEADERS;

  char buf[WS_INIT_REQUEST_LENGTH + strlen(ws->path) + strlen(ws->hostname) +
           headers_length(DEFAULT_HEADERS) + headers_length(headers) +
           headers_length(extraHeaders) + 2 + 1];

  os_printf("buf size is %d\r\n", sizeof(buf));
  int len = sprintf(buf, WS_INIT_REQUEST, ws->path, ws->hostname, ws->port);

  char* dst =
      sprintf_headers(buf + len, headers, extraHeaders, DEFAULT_HEADERS, 0);
  len = dst - buf;
  os_free(key);

  os_printf("request:\n %s", buf);
  int ret;
  if (ws->isSecure) {
    ret = SSL_write(ws->ssl, buf, len);
    if (ret <= 0) {
      os_printf("failed, return [-0x%x]\n", -ret);
      if (ws->onFailure) ws->onFailure(ws, eFailed_Send);
      return;
    }
    os_printf("send wss OK\n\n");

    do {
      ret = SSL_read(ws->ssl, recv_buf, RECV_BUF_SIZE - 1);
      if (ret < 0) {
        if (ws->onFailure) ws->onFailure(ws, eFailed_Recv);
        return;
      }
      if (ret > 0) {
        break;
      }
      vTaskDelay(200 / portTICK_RATE_MS);
      os_printf("wss recv_buf->%s\r\n", recv_buf);
    } while (1);
    os_printf("read %d bytes data from %s ......\n", ret, ws->hostname);
  } else {
    ret = send(ws->socket_fd, buf, len, 0);
    if (ret <= 0) {
      os_printf("failed, return [-0x%x]\n", -ret);
      if (ws->onFailure) ws->onFailure(ws, eFailed_Send);
      return;
    }
    os_printf("send ws OK\n\n");

    do {
      ret = recv(ws->socket_fd, recv_buf, RECV_BUF_SIZE - 1, 0);
      if (ret < 0) {
        if (ws->onFailure) ws->onFailure(ws, eFailed_Recv);
        return;
      }
      if (ret > 0) {
        break;
      }
      vTaskDelay(200 / portTICK_RATE_MS);
      os_printf("ws recv_buf-> %s\r\n", recv_buf);
    } while (1);
    os_printf("read %d bytes data from %s ......\n", ret, ws->hostname);
  }
  ws_handshake_recv_process(ws, recv_buf, ret);
}

/**
 * @brief  websocket 连接
 * @note
 * @param  ws:
 * @param  url:
 * @retval None
 */
void ws_connect(ws_info* ws, char* url) {
  if (ws == NULL) {
    os_printf("ws_connect ws_info argument is null!");
    return;
  }

  ws->connectionState = eWSState_Init;

  xSemaphore = xSemaphoreCreateMutex();

  //提取参数
  ws_extract_param(ws, url);
  if (ws->connectionState < eWSState_Extract) {
    os_printf(">>>ws_connect failed! connectionState is %d\r\n",
              ws->connectionState);
    return;
  }

  // socket连接
  socket_connect(ws);
  if (ws->connectionState < eWSState_SSL) {
    os_printf(">>>ws_connect failed! connectionState is %d\r\n",
              ws->connectionState);
    return;
  }

  // ssl连接
  if (ws->isSecure) {
    openssl_connect(ws);
  }

  if (ws->connectionState < eWSState_Conn) {
    os_printf(">>>ws_connect failed! connectionState is %d\r\n",
              ws->connectionState);
    return;
  }

  os_timer_disarm(&ws->timeoutTimer);
  ws_handshake(ws);

  if (ws->connectionState < eWSState_HandShake) {
    os_printf(">>>ws_connect failed! connectionState is %d\r\n",
              ws->connectionState);
    return;
  }

  ptr_ws = ws;
  xTaskCreate(&task_websocket_recv, "task_websocket_recv", 2048, ws, 1, NULL);
  heartbeat_init();
}

/**
 * @brief  发送数据
 * @note
 * @param  *ws: websocket对象
 * @param  *message: 文本数据
 * @param  length: 数据长度
 * @retval None
 */
void ws_send(ws_info* ws, const char* message, unsigned short length) {
  os_printf("ws_send\n");
  ws_sendFrame(ws, WS_OPCODE_TEXT, message, length);
}

/**
 * @brief  websocket接收处理任务
 * @note
 * @param  param:
 * @retval None
 */
static void task_websocket_recv(void* param) {
  os_printf("task_websocket_recv start \r\n");
  ws_info* ws = (ws_info*)param;

  int len = 0;

  while (1) {
    if (ws->isSecure) {
      len = SSL_read(ws->ssl, recv_buf, RECV_BUF_SIZE - 1);
    } else {
      len = recv(ws->socket_fd, recv_buf, RECV_BUF_SIZE - 1, 0);
    }
    if (len > 0) {
      os_printf("recv system_get_free_heap_size---> %d\n",
                system_get_free_heap_size());
      ws->heartbeat = 0;
      ws_recv_process(ws, recv_buf, len);
    } else if (len < 0) {
      os_printf(">>>recv failed \r\n");
      if (ws->onFailure) ws->onFailure(ws, eFailed_DisConn);
      break;
    }
    vTaskDelay(1 / portTICK_RATE_MS);
  }
  os_printf("task_websocket_recv was deleted\r\n");
  xTimerStop(heartbeat_timer_handle, 0);
  xTimerDelete(heartbeat_timer_handle, 0);
  vTaskDelete(NULL);
}

/**
 * @brief  心跳回调
 * @note
 * @param  xtimer:
 * @retval None
 */
static void heartbeat_callback(xTimerHandle xtimer) {
  os_printf("heartbeat_callback\r\n");
  if (ptr_ws->heartbeat == 2) {
    // several pings were sent but no pongs nor messages
    os_printf("heartbeat timeout\r\n");
    if (ptr_ws->onFailure) ptr_ws->onFailure(ptr_ws, eFailed_DisConn);
    return;
  }
  ws_sendFrame(ptr_ws, WS_OPCODE_PING, NULL, 0);
  ptr_ws->heartbeat += 1;
}

/**
 * @brief  心跳初始化
 * @note
 * @retval None
 */
static void heartbeat_init(void) {
  os_printf("heartbeat_init\r\n");
  heartbeat_timer_handle = xTimerCreate(NULL, 30 * 1000 / portTICK_RATE_MS,
                                        pdTRUE, NULL, heartbeat_callback);
  if (xTimerStart(heartbeat_timer_handle, 0) != pdPASS) {
    os_printf("timer start fail\r\n");
  }
}