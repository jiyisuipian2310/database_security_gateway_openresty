#include "FileReader.h"
#include <sys/file.h>
#include <algorithm>

static int TrimRight(char * RawString)
{
    if (RawString==NULL)
        return 0;

    int len;
    int rawlen;

    rawlen = strlen(RawString);
    for (len = rawlen-1; len>=0; len--)
    {
        if (RawString[len]==' '||RawString[len]=='\t'||
                RawString[len]=='\r'||RawString[len]=='\n')
            continue;
        else
            break;
    }

    RawString[len+1] = 0;
    return strlen(RawString);
}

static int TrimLeft(char * RawString)
{
    if (RawString == NULL)
        return 0;
    int len = 0;
    int rawlen = strlen(RawString);
    char *szTmp = RawString;
    for (len = 0; len < rawlen; len++)
    {
        if (RawString[len] == ' ' || RawString[len] == '\t' ||
                RawString[len] == '\r' || RawString[len] == '\n')
            continue;
        else
            break;
    }
    for (; len < rawlen; len++)
    {
        *szTmp++ = RawString[len];
    }
    *szTmp = '\0';
    return strlen(RawString);
}

static int TrimSpace(std::string &str)
{
    int nSize = str.size();
    char *pTemp = new char[nSize+1];
    if (pTemp!=NULL)
    {
        memset(pTemp, 0x00, nSize+1);
        strncpy(pTemp, str.c_str(), nSize);

		TrimRight(pTemp);
		TrimLeft(pTemp);
		
        str = pTemp;
        delete [] pTemp;
        pTemp = NULL;
    }
	return 0;
}

struct StAnalyzeIni
{
	string strSect;
	strMap *pMap;
	
	StAnalyzeIni(strMap & strmap):pMap(&strmap){}

	void operator()( const string & strini)
	{
		string strTemp = strini;
		TrimSpace(strTemp);
		int ipos = strTemp.find('#');
		if(ipos==0)
		{
			return;
		}

		int first =strini.find('[');
		int last = strini.rfind(']');

		if( first != string::npos && last != string::npos && first != last+1)
		{
			if(strini.find('=') == string::npos) {
				strSect = strini.substr(first+1,last-first-1);
			    return;
			}
		}

		if(strSect.empty())
		    return ;

		if((first=strini.find('='))== string::npos)
		    return ;

		string strtmp1= strini.substr(0,first);
		string strtmp2=strini.substr(first+1, string::npos);
		first= strtmp1.find_first_not_of(" \t");
		last = strtmp1.find_last_not_of(" \t");

		if(first == string::npos || last == string::npos)
		    return ;

		string strkey = strtmp1.substr(first, last-first+1);

		first = strtmp2.find_first_not_of(" \t");

		if(((last = strtmp2.find("\t#", first )) != -1) ||
		((last = strtmp2.find(" #", first )) != -1) ||
		((last = strtmp2.find("\t\\", first )) != -1)||
		((last = strtmp2.find(" \\", first )) != -1))
		{
			strtmp2 = strtmp2.substr(0, last-first);
		}

		last = strtmp2.find_last_not_of(" \t");

		if(first == string::npos || last == string::npos)
			return ;

		string strValue = strtmp2.substr(first, last-first+1);
		string strMapKey = strSect + MIDDLE_STRING;
		strMapKey += strkey;

		(*pMap)[strMapKey]=strValue;
		
		return ;
	}
};

CFileReader::CFileReader() {
}

CFileReader::~CFileReader() {
}

bool CFileReader::ReadFile(const char* pinipath)
{
	m_strFilePath = pinipath;
	m_IniVec.clear();
	ifstream fin(pinipath);
	if(!fin.is_open()) return false;

	//加上文件锁
	FILE *fp = NULL;
    if ((fp = fopen(m_strFilePath.c_str(), "r+")) == NULL) {
		cout<<"file "<< m_strFilePath <<" open error !"<<endl;
		return false;
	}

    flock(fp->_fileno, LOCK_EX); //文件加锁

	while(!fin.eof()) {
		string inbuf;
		getline(fin, inbuf,'\n');
		if(inbuf.empty()) continue;
		m_IniVec.push_back(inbuf);
	}

    fclose(fp); //关闭文件
    flock(fp->_fileno, LOCK_UN); //释放文件锁

	fin.close();
	
	if(m_IniVec.empty()) return true;

	for_each(m_IniVec.begin(), m_IniVec.end(), StAnalyzeIni(m_IniMap));
	return true;  
}

string CFileReader::Get_Profile_Str(string psect, string pkey, string sKeyValueDef)
{
    string mapkey = psect;
    mapkey.append(MIDDLE_STRING).append(pkey);
	
	strMapIt it = m_IniMap.find(mapkey);
	if(it == m_IniMap.end() || "" == it->second) {
		return sKeyValueDef;
	}

    string strValue = it->second;
    TrimSpace(strValue);

    return strValue;
}

int CFileReader::Get_Profile_Int(string psect, string pkey, int iKeyValueDef)
{
    string strValue = Get_Profile_Str(psect, pkey, "");
    if("" == strValue) {
        return iKeyValueDef;
    }

    return atoi(strValue.c_str());
}

bool CFileReader::Get_Profile_Bool(string& psect, string& pkey, bool* bValue, bool bKeyValueDef)
{
    string strValue = Get_Profile_Str(psect, pkey, "");
    if("" == strValue) {
        return bKeyValueDef;
    }
	
	std::transform(strValue.begin(), strValue.end(), strValue.begin(), ::tolower);
	if ("on" == strValue || "true" == strValue || "1" == strValue) {
		return true;
	}

	if ("off" == strValue || "false" == strValue || "0" == strValue) 
	{
		return false;
	}

    return bKeyValueDef;
}
