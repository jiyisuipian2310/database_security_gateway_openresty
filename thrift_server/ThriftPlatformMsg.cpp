#include "ThriftPlatformMsg.h"
#include "IHttpBase.h"
#include "opcode.h"
#include "ConfigInit.h"
#include "IHttpBase.h"

extern std::string getCurrentTime();

ThriftPlatformMsg::ThriftPlatformMsg() {
}

ThriftPlatformMsg::~ThriftPlatformMsg() {
}

class HttpClient: public IHttpBase {
public:
    HttpClient(bool bAsyncCall = false):IHttpBase(bAsyncCall) {}
    ~HttpClient() {}

	virtual void process_http_response(bool bSuccess, const char* response, int status) {
		if(m_bAsyncCall) {
			if(!bSuccess) {
				cout << "Async call failed, status: " << status << ", response: " << response << endl;
			}
		}
		else {
			if(!bSuccess) {
				cout << "Sync call failed, status: " << status << ", response: " << response << endl;
			}
		}
        fflush(stdout);
	}
};

void ThriftPlatformMsg::SendMessage(const ReqInfo& msg)
{
    string currtime = getCurrentTime();
    HttpClient client(false);
    CConfig* pConfig = CConfig::instance();
    std::string requestUrlBase = "http://127.0.0.1:";
    switch (msg.iCode) {
    case CommandCode::REQUEST_ACCOUNT_UNLOCK: {
        if(pConfig->m_strPgsqlHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strPgsqlHttpListenPort).append("/unlock_account");
            printf("%s, send http message(account_unlock) to pgsql_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
        if(pConfig->m_strMysqlHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strMysqlHttpListenPort).append("/unlock_account");
            printf("%s, send http message(account_unlock) to mysql_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
        if(pConfig->m_strOracleHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strOracleHttpListenPort).append("/unlock_account");
            printf("%s, send http message(account_unlock) to oracle_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
    }
    break;
    case CommandCode::REQUEST_CFG_ADD_VP: {
        if(pConfig->m_strPgsqlHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strPgsqlHttpListenPort).append("/add_db_control_policy");
            printf("%s, send http message(add_db_control_policy) to pgsql_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
        if(pConfig->m_strMysqlHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strMysqlHttpListenPort).append("/add_db_control_policy");
            printf("%s, send http message(add_db_control_policy) to mysql_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
        if(pConfig->m_strOracleHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strOracleHttpListenPort).append("/add_db_control_policy");
            printf("%s, send http message(add_db_control_policy) to oracle_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
    }
    break;
    case CommandCode::REQUEST_CFG_DELETE_VP: {
        if(pConfig->m_strPgsqlHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strPgsqlHttpListenPort).append("/delete_db_control_policy");
            printf("%s, send http message(delete_db_control_policy) to pgsql_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
        if(pConfig->m_strMysqlHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strMysqlHttpListenPort).append("/delete_db_control_policy");
            printf("%s, send http message(delete_db_control_policy) to mysql_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
        if(pConfig->m_strOracleHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strOracleHttpListenPort).append("/delete_db_control_policy");
            printf("%s, send http message(delete_db_control_policy) to oracle_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
    }
    break;
    case CommandCode::REQUEST_CFG_ALTER_VP: {
        if(pConfig->m_strPgsqlHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strPgsqlHttpListenPort).append("/update_db_control_policy");
            printf("%s, send http message(update_db_control_policy) to pgsql_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
        if(pConfig->m_strMysqlHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strMysqlHttpListenPort).append("/update_db_control_policy");
            printf("%s, send http message(update_db_control_policy) to mysql_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
        if(pConfig->m_strOracleHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strOracleHttpListenPort).append("/update_db_control_policy");
            printf("%s, send http message(update_db_control_policy) to oracle_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
    }
    break;
    default:
        break;
    }

    fflush(stdout);
}

void ThriftPlatformMsg::SendAndRecMessage(ResultInfo& _return, const ReqInfo& msg)
{
    string currtime = getCurrentTime();
    HttpClient client(false);
    CConfig* pConfig = CConfig::instance();
    std::string requestUrlBase = "http://127.0.0.1:";
    switch (msg.iCode) {
    case CommandCode::REQUEST_ACCOUNT_UNLOCK: {
        if(pConfig->m_strPgsqlHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strPgsqlHttpListenPort).append("/unlock_account");
            printf("%s, send http message(unlock_account) to pgsql_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
        if(pConfig->m_strMysqlHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strMysqlHttpListenPort).append("/unlock_account");
            printf("%s, send http message(unlock_account) to mysql_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
        if(pConfig->m_strOracleHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strOracleHttpListenPort).append("/unlock_account");
            printf("%s, send http message(unlock_account) to oracle_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }

        _return.iCode = 0;
        _return.strValue = "OK";
    }
    break;
    case CommandCode::REQUEST_CFG_ADD_VP: {
        if(pConfig->m_strPgsqlHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strPgsqlHttpListenPort).append("/add_db_control_policy");
            printf("%s, send http message(add_db_control_policy) to pgsql_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
        if(pConfig->m_strMysqlHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strMysqlHttpListenPort).append("/add_db_control_policy");
            printf("%s, send http message(add_db_control_policy) to mysql_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
        if(pConfig->m_strOracleHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strOracleHttpListenPort).append("/add_db_control_policy");
            printf("%s, send http message(add_db_control_policy) to oracle_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }

        _return.iCode = 0;
        _return.strValue = "OK";
    }
    break;
    case CommandCode::REQUEST_CFG_DELETE_VP: {
        if(pConfig->m_strPgsqlHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strPgsqlHttpListenPort).append("/delete_db_control_policy");
            printf("%s, send http message(delete_db_control_policy) to pgsql_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
        if(pConfig->m_strMysqlHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strMysqlHttpListenPort).append("/delete_db_control_policy");
            printf("%s, send http message(delete_db_control_policy) to mysql_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
        if(pConfig->m_strOracleHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strOracleHttpListenPort).append("/delete_db_control_policy");
            printf("%s, send http message(delete_db_control_policy) to oracle_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }

        _return.iCode = 0;
        _return.strValue = "OK";
    }
    break;
    case CommandCode::REQUEST_CFG_ALTER_VP: {
        if(pConfig->m_strPgsqlHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strPgsqlHttpListenPort).append("/update_db_control_policy");
            printf("%s, send http message(update_db_control_policy) to pgsql_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
        if(pConfig->m_strMysqlHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strMysqlHttpListenPort).append("/update_db_control_policy");
            printf("%s, send http message(update_db_control_policy) to mysql_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }
        if(pConfig->m_strOracleHttpListenPort != "") {
            string url = requestUrlBase;
            url.append(pConfig->m_strOracleHttpListenPort).append("/update_db_control_policy");
            printf("%s, send http message(update_db_control_policy) to oracle_proxy, url: %s, jsondata: %s\n", currtime.data(), url.data(), msg.strValue.data());
            client.send_http_message(url, string(""), string(""), msg.strValue);
        }

        _return.iCode = 0;
        _return.strValue = "OK";
    }
    break;
    default:
        _return.iCode = -100;
        _return.strValue = "ERROR";
        break;
    }

    fflush(stdout);
}

void ThriftPlatformMsg::SendPacket(const BaseSKB& msg) {
}

void ThriftPlatformMsg::SendAndRecPacket(ResultInfo& _return, const BaseSKB& msg) {

}



