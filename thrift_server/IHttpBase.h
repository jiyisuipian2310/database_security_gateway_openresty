#ifndef __IHTTPBASE_H__
#define __IHTTPBASE_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <string>

using namespace std;

#ifdef __cplusplus
extern "C" {
#endif

// 错误类型常量
typedef enum {
    ERROR_TYPE_NONE = 0,            // 无错误
    ERROR_TYPE_CONNECTION_FAILED,   // 连接失败
    ERROR_TYPE_TIMEOUT,             // 超时
    ERROR_TYPE_TLS,                 // TLS错误
    ERROR_TYPE_DNS,                 // DNS解析错误
    ERROR_TYPE_READ_RESPONSE,       // 读取响应失败
    ERROR_TYPE_OTHER                // 其他错误
} ErrorType;

typedef void (*HttpCallback)(const char* response, int status, int error_type, void* user_data);

// 导出函数, 异步发送http请求
void SendHttpRequestAsync(const char* url, const char* method, const char* headers, 
                         const char* body, HttpCallback callback, void* user_data);


// 导出函数, 同步发送http请求
void SendHttpRequestSync(const char* url, const char* method, const char* headers, 
                         const char* body, HttpCallback callback, void* user_data);

#ifdef __cplusplus
}
#endif

void http_callback(const char* response, int status, int error_type, void* user_data);

class IHttpBase {
public:
    IHttpBase(bool bAsyncCall);
    ~IHttpBase();

	void send_http_message(string strUrl, string strMethod, string strHeaders, const string& strBody);

    virtual void process_http_message(const char* response, int status, int error_type);

	//bSuccess true, response is response data; bSuccess false, response is error message 
	virtual void process_http_response(bool bSuccess, const char* response, int status) = 0;

protected:
	bool m_bAsyncCall;
};

#endif //__IHTTPBASE_H__
