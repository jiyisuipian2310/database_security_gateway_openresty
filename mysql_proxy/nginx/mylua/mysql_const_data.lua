local _M = {}

_M.MYSQL_OK_MARKER = 0
_M.MYSQL_EOF_MARKER = 254  -- 0xfe
_M.MYSQL_ERR_MARKER = 255  -- 0xff

_M.SESSION_STATE_CLIENT_LOGIN_REQUEST = 1
_M.SESSION_STATE_CLIENT_QUERY = 2
_M.SESSION_STATE_CLIENT_LAST = 999

_M.SESSION_STATE_SERVER_GREET = 1
_M.SESSION_STATE_SERVER_LOGIN_RESPONSE = 2
_M.SESSION_STATE_SERVER_LOGIN_FAILED = 3
_M.SESSION_STATE_SERVER_QUERY_RESPONSE = 4
_M.SESSION_STATE_SERVER_LAST = 999

_M.MYSQL_OK_PACKAGE_LESS_LEN = 7   -- >=7
_M.MYSQL_EOF_PACKAGE_MAX_LEN = 9   -- <=9
_M.MYSQL_ERR_PACKAGE_LESS_LEN = 9  -- >=9

_M.MYSQL_HAND_SHAKE_LESS_LEN = 34

_M.SqlMatchRule = {
    NotRegularExpression={
        "SET NAMES utf8mb4",
        "BEGIN",
        "ROLLBACK",
        "COMMIT",
        "SET search_path TO",
        "CREATE TABLE"
    },

    RegularExpression={
        "SHOW .* (STATUS|FROM|TABLE).*",
        "SELECT .* FROM help_topic` LIMIT 0,1000",
        "SHOW VARIABLES .* FROM information_schema.*",
        "SELECT .* FROM information_schema.*",
        "SELECT .* FROM INFORMATION_SCHEMA.* TABLE_NAME ASC"
    },
}

-- 错误提示信息：Get Master Account Failed !
_M.get_main_account_failed_msg = 
"\x24\x00\x00\x01" ..
"\xff\xcb\x04\x23" ..
"\x34\x32\x53\x30\x32" ..
"\x47\x65\x74\x20\x4d\x61\x73\x74\x65\x72" ..
"\x20\x41\x63\x63\x6f\x75\x6e\x74\x20\x46" ..
"\x61\x69\x6c\x65\x64\x20\x21"

-- 错误提示信息：Reached maximum number of login failures!
_M.reach_max_login_failures_msg = 
"\x33\x00\x00\x01" ..
"\xff\xcb\x04\x23\x34\x32\x53\x30\x32" ..
"\x52\x65\x61\x63\x68\x65\x64\x20\x6D\x61" ..
"\x78\x69\x6D\x75\x6D\x20\x6E\x75\x6D\x62" ..
"\x65\x72\x20\x6F\x66\x20\x6C\x6F\x67\x69" ..
"\x6E\x20\x66\x61\x69\x6C\x75\x72\x65\x73" ..
"\x20\x21"

-- 错误提示信息：Reached Maximum connection limit !
_M.reach_max_connection_limit_msg = 
"\x2b\x00\x00\x01" ..
"\xff\xcb\x04\x23\x34\x32\x53\x30\x32" ..
"\x52\x65\x61\x63\x68\x65\x64\x20\x4D\x61" ..
"\x78\x69\x6D\x75\x6D\x20\x63\x6F\x6E\x6E" ..
"\x65\x63\x74\x69\x6F\x6E\x20\x6C\x69\x6D" ..
"\x69\x74\x20\x21"

-- 错误提示信息：Unauthorized access
_M.unauthorized_access_msg = 
"\x1c\x00\x00\x01" ..
"\xff\xcb\x04\x23" ..
"\x34\x32\x53\x30\x32" ..
"\x55\x6e\x61\x75\x74\x68\x6f\x72\x69\x7a" ..
"\x65\x64\x20\x61\x63\x63\x65\x73\x73"

-- 错误提示信息：不允许操作！
_M.table_reject_operation_msg = 
"\x1b\x00\x00\x01" ..
"\xff\xcb\x04\x23" ..
"\x34\x32\x53\x30\x32" ..
"\xe4\xb8\x8d\xe5\x85\x81\xe8\xae\xb8\xe6\x93\x8d\xe4\xbd\x9c\xef\xbc\x81"

_M.audit_field_order = {
    "sourceIp",
    "sourcePort",
    "targetIp",
    "targetPort",
    "eventCreateTime",
    "targetServiceName",
    "command",
    "tableName",
    "dbType",
    "auditSqlText",
    "netcardIp",
    "dataLength",
    "data",
    "hostUsername",
    "loginUsername"
}

return _M