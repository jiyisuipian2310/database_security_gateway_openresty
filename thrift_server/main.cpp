#include <iostream>
#include "ThriftPlatformMsg.h"
#include "ThriftServer.h"
#include "ConfigInit.h"

const int client_num = 10;
CConfig* g_pConfig = NULL;

std::string getCurrentTime() {
    time_t now = time(nullptr);
    struct tm timeinfo;
    localtime_r(&now, &timeinfo); // 线程安全版本
    
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
    return std::string(buffer);
}

int main(int argc, char* argv[])
{
	CConfig* pConfig = CConfig::instance();
    if(!pConfig->init("../conf/thriftServerConfig.ini")) {
        return -1;
    }

	string currtime = getCurrentTime();

	printf("==================== start run thriftServer ====================\n");
	printf("%s, local listen port: %s\n", currtime.data(), pConfig->m_strLocalListenPort.data());
	printf("%s, pgsql http listen port: %s\n", currtime.data(), pConfig->m_strPgsqlHttpListenPort.data());
	printf("%s, mysql http listen port: %s\n", currtime.data(), pConfig->m_strMysqlHttpListenPort.data());
	printf("%s, oracle http listen port: %s\n", currtime.data(), pConfig->m_strOracleHttpListenPort.data());
	fflush(stdout);
	ThriftServer thSer(new ThriftPlatformMsg(), atoi(pConfig->m_strLocalListenPort.data()), client_num);
	thSer.Start();

	while(1) {
		sleep(1);
	}
	return 0;
}
