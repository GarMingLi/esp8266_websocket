#ifndef __WEBSOCKET_CLIENT_H__
#define __WEBSOCKET_CLIENT_H__

#include "espressif/esp_common.h"
#include "openssl/ssl.h"

#define PROTOCOL_SECURE "wss://"
#define PROTOCOL_INSECURE "ws://"

#define WS_INIT_REQUEST_LENGTH 30
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_GUID_LENGTH 36

#define WS_INIT_REQUEST \
  "GET %s HTTP/1.1\r\n" \
  "Host: %s:%d\r\n"

#define WS_HTTP_SWITCH_PROTOCOL_HEADER "HTTP/1.1 101"
#define WS_HTTP_SEC_WEBSOCKET_ACCEPT "Sec-WebSocket-Accept:"

#define PORT_SECURE 443
#define PORT_INSECURE 80
#define PORT_MAX_VALUE 65535

#define OPENSSL_FRAGMENT_SIZE 4096

#define RECV_BUF_SIZE 2048

// websocket数据帧操作码
#define WS_OPCODE_CONTINUATION 0x0  //持续帧
#define WS_OPCODE_TEXT 0x1          //文本帧
#define WS_OPCODE_BINARY 0x2        //二进制帧
#define WS_OPCODE_CLOSE 0x8         //连接关闭包
#define WS_OPCODE_PING 0x9          //心跳ping包
#define WS_OPCODE_PONG 0xA          //心跳pong包

struct ws_info;

typedef void (*ws_onConnectionCallback)(struct ws_info *wsInfo);
typedef void (*ws_onDisConnCallback)(struct ws_info *wsInfo);
typedef void (*ws_onReceiveCallback)(struct ws_info *wsInfo, int len,
                                     char *message, bool istext);
typedef void (*ws_onFailureCallback)(struct ws_info *wsInfo, int errorCode);

typedef struct {
  char *key;
  char *value;
} header_t;

typedef struct ws_info {
  int connectionState;

  bool isSecure;
  char *hostname;
  int port;
  char *path;
  char *expectedSecKey;

  int socket_fd;
  SSL *ssl;
  void *reservedData;

  char *frameBuffer;
  int frameBufferLen;

  char *payloadBuffer;
  int payloadBufferLen;
  int payloadOriginalOpCode;

  os_timer_t timeoutTimer;
  int heartbeat;

  ws_onConnectionCallback onConnection;
  ws_onReceiveCallback onReceive;
  ws_onFailureCallback onFailure;
  ws_onDisConnCallback onDisConn;
} ws_info;

//错误代码
enum {
  eFailed_GetProtocol = -1,     //提取ws wss协议失败
  eFailed_HostTooLarge = -2,    //提取主机名失败,主机名太大
  eFailed_InvalidPort = -3,     //提取端口失败，端口无效
  eFailed_InvalidHost = -4,     //提取主机名失败，不存在主机名
  eFailed_GetIP = -5,           //获取IP失败
  eFailed_SocketInit = -6,      //创建socket失败
  eFailed_SocketConn = -7,      // socket连接失败
  eFailed_SSL_CTX = -8,         // sll context创建失败
  eFailed_SSL = -9,             // sll 创建失败
  eFailed_SSLConn = -10,        // sll 连接失败
  eFailed_ConnTimeout = -11,    //连接超时
  eFailed_ErrorProtocol = -12,  //错误协议
  eFailed_InvalidKey = -13,     //无效密钥
  eFailed_Send = -14,           //发送失败
  eFailed_Recv = -15,           //接收失败
  eFailed_DisConn = -16,        //连接断开
  eFailed_NotBuff = -17,        //缓存不足
  eFailed_NotContinue = -18,    //无持续数据
};

//连接状态
enum {
  eWSState_Init = 0,   // Websocket初始化状态
  eWSState_Extract,    // websocket提取参数状态
  eWSState_Socket,     // websocket socket连接状态
  eWSState_SSL,        // websocket SSL连接状态
  eWSState_Conn,       // websocket连接完成状态
  eWSState_HandShake,  // websocket握手完成状态
  eWSState_Disconn,    // websocket断开连接状态
};

void ws_connect(ws_info *ws, char *url);
void ws_send(ws_info *ws, const char *message, unsigned short length);

#endif  // !__WEBSOCKET_CLIENT_H__
