#ifndef __FILE_READER_H__
#define __FILE_READER_H__

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <functional>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

using namespace std;

typedef map<string, string, less<string> > strMap;
typedef strMap::iterator strMapIt;

#define MIDDLE_STRING			"_____***_____"
#define GET_STR_ERROR			"ROOT_KEY_ERR"

class CFileReader {
public:
    CFileReader();
    ~CFileReader();
    bool ReadFile(const char* pinipath);

    string Get_Profile_Str(string psect, string pkey,string sKeyValueDef="");
    int Get_Profile_Int(string psect, string pkey,int iKeyValueDef=0);
    bool Get_Profile_Bool(string& psect, string& pkey, bool* bValue, bool bKeyValueDef = true);

private:
    string m_strFilePath;
    vector<string> m_IniVec;
    strMap m_IniMap;
};

#endif // __FILE_READER_H__