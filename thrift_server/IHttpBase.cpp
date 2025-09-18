#include "IHttpBase.h"

void http_callback(const char* response, int status, int error_type, void* user_data)
{
    if(user_data == NULL) { return; }
    IHttpBase* pIHttpBase = (IHttpBase*)user_data;
	pIHttpBase->process_http_message(response, status, error_type);
}

IHttpBase::IHttpBase(bool bAsyncCall) {
	m_bAsyncCall = bAsyncCall;
}

IHttpBase::~IHttpBase() {
}

void IHttpBase::send_http_message(string strUrl, string strMethod, string strHeaders, const string& strBody) {
    if(m_bAsyncCall)
        SendHttpRequestAsync(strUrl.data(), strMethod.data(), strHeaders.data(), strBody.data(), http_callback, (void*)this);
    else
        SendHttpRequestSync(strUrl.data(), strMethod.data(), strHeaders.data(), strBody.data(), http_callback, (void*)this);
}

void IHttpBase::process_http_message(const char* response, int status, int error_type) {
	if(!response) return;
	
	switch (error_type) {
        case ERROR_TYPE_NONE:
            if(status == 200) {
				process_http_response(true, response, status);
            } else {
				process_http_response(false, response, status);
			}

            break;
        case ERROR_TYPE_DNS:               //DNS解析错误
        case ERROR_TYPE_TLS:               //TLS/SSL错误
        case ERROR_TYPE_TIMEOUT:           //请求超时
        case ERROR_TYPE_CONNECTION_FAILED: //连接http服务失败
        case ERROR_TYPE_READ_RESPONSE:     //读取响应失败
			process_http_response(false, response, status);
            break;
        default:
			process_http_response(false, response, status);
            break;
    }
}
