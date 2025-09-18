local _M = {}

_M.PGSQL_CLIENT_CMD_QUERY = 0x51   --'Q'
_M.PGSQL_CLIENT_CMD_PASSWORD = 0x70  --'p'

_M.PGSQL_SERVER_CMD_CMDCOMPLETE = 0x43  --'C'
_M.PGSQL_SERVER_CMD_ERRRESPONSE = 0x45  --'E'
_M.PGSQL_SERVER_CMD_AUTH = 0x52  --'R'
_M.PGSQL_SERVER_CMD_READYFORQUERY = 0x5a  --'Z'
_M.PGSQL_SERVER_CMD_ROWDESC = 0x54  --'T'
_M.PGSQL_SERVER_CMD_DATAROW = 0x44  --'D'

_M.QUERY_DBNAME_SQL = "SELECT d.oid, d.datname AS databasename, d.datacl, d.datistemplate, d.datallowconn, pg_get_userbyid(d.datdba) AS databaseowner, d.datcollate, d.datctype, shobj_description(d.oid, 'pg_database') AS description, d.datconnlimit, t.spcname, d.encoding, pg_encoding_to_char(d.encoding) AS encodingname FROM pg_database d LEFT JOIN pg_tablespace t ON d.dattablespace = t.oid"

_M.SqlMatchRule = {
    NotRegularExpression={
        "set client_encoding to 'UNICODE'",
        "SHOW datestyle",
        "SHOW search_path",
        "BEGIN",
        "ROLLBACK",
        "COMMIT",
        "SET search_path TO",
        "CREATE TABLE"
    },

    RegularExpression={
        "SELECT oid, nspname AS schemaname, nspacl, pg_get_userbyid\\(nspowner\\) .*",
        "SELECT E.extname AS name, E.extversion AS version, .* ORDER BY name, available_version",
        "SELECT .* FROM pg_.*",
        "SELECT .* FROM information_schema.routines .*",
        "SELECT .* FROM information_schema.columns .*",
        "SELECT .* FROM .* ORDER BY c.relname",
        "SELECT .* FROM .* WHERE .* AND .* LIMIT 1$"
    },
}

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
