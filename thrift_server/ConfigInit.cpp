#include "ConfigInit.h"
#include "FileReader.h"
#include <cstdarg>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <errno.h>

CConfig* CConfig::instance() {
    static CConfig _instance;
    return &_instance;
}

bool CConfig::init( const char * conf )
{
    char errmsg[256] = {0};
    CFileReader iniFileReader;
    if(!iniFileReader.ReadFile(conf)) {
        sprintf(errmsg, "Error: open config file %s failed, reason: %s", conf, strerror(errno));
        cout << errmsg << endl;
        return false;
    }

    m_strLocalListenPort = iniFileReader.Get_Profile_Str("MAIN","LOCAL_LISTEN_PORT", "1200");
    m_strPgsqlHttpListenPort = iniFileReader.Get_Profile_Str("MAIN","PGSQL_HTTP_LISTEN_PORT", "");
    if(m_strPgsqlHttpListenPort == "-1") m_strPgsqlHttpListenPort = "";

    m_strMysqlHttpListenPort = iniFileReader.Get_Profile_Str("MAIN","MYSQL_HTTP_LISTEN_PORT", "");
    if(m_strMysqlHttpListenPort == "-1") m_strMysqlHttpListenPort = "";

    m_strOracleHttpListenPort = iniFileReader.Get_Profile_Str("MAIN","ORACLE_HTTP_LISTEN_PORT", "");
    if(m_strOracleHttpListenPort == "-1") m_strOracleHttpListenPort = "";

    return true;
}