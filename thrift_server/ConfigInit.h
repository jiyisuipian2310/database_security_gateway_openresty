#ifndef __CONFIG_INIT_H__
#define __CONFIG_INIT_H__

#include <string>
#include <iostream>
#include <stdint.h>
using namespace std;

class CConfig {
public:
	static CConfig* instance();
	bool init( const char * conf );

public:
    string m_strLocalListenPort;
    string m_strPgsqlHttpListenPort;
    string m_strMysqlHttpListenPort;
    string m_strOracleHttpListenPort;
};

#endif // __CONFIG_INIT_H__