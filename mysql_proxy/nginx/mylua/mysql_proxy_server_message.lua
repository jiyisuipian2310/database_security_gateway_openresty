local ngx = ngx
local string = string
local table = table

local cjson = require "cjson.safe"
local utils = require "utils"
local loger = require "mysql_proxy_timer_logs"
local mysql_const_data = require "mysql_const_data"
local auditlogs = require "mysql_audit_logs"

local _M = {}

local function record_mysql_audit_log(client_sock)
    local meta = utils.get_metadata(client_sock)
    if meta.querySql == nil or meta.querySql == "" then
        return
    end

    local json_table = {
        sourceIp = ngx.var.remote_addr,
        sourcePort = ngx.var.remote_port,
        targetIp = meta.targetIp,
        targetPort = meta.targetPort,
        eventCreateTime = ngx.localtime(),
        targetServiceName = (meta.database ~= nil) and string.lower(meta.database) or "nil",
        command = string.match(meta.querySql, "(%S+)"),
        tableName = "",
        dbType = "mysql",
        auditSqlText = meta.querySql,
        netcardIp = globalCfg.localAddressIp,
        dataLength = (meta.rownum ~= nil) and meta.rownum or 0,
        data = meta.downdata ~= nil and meta.downdata or "",
        hostUsername = meta.user,
        loginUsername = meta.masterAccount or meta.user,
    }

    local json_parts = {}
    for _, key in ipairs(mysql_const_data.audit_field_order) do
        local value = json_table[key]
        -- 特殊处理：确保字符串类型的值被正确转义
        if type(value) == "string" then
            table.insert(json_parts, string.format('"%s":"%s"', key, value:gsub('"', '\\"')))
        else
            table.insert(json_parts, string.format('"%s":%s', key, cjson.encode(value)))
        end
    end

    local json_str = "{" .. table.concat(json_parts, ",") .. "}"
    auditlogs.save_mysql_audit_log(json_str)
    meta.querySql = nil
    meta.rownum = nil
    meta.downdata = nil
    meta.downdatacount = nil
end

local function parse_mysql_greeting_message(client_sock, backend_sock, backenddata)
    local offset = 1
    local meta = utils.get_metadata(client_sock)
    local pktlen = utils.unpack_little_endian(backenddata, offset, 3)
    if pktlen < mysql_const_data.MYSQL_HAND_SHAKE_LESS_LEN then return end

    offset = offset + 3 + 1 + 1 -- 跳过3字节表示的长度 1字节表示的包序号 1字节表示的服务器标记
    local key_end = backenddata:find("\0", offset, true)
    if key_end == nil then  return end

    local version = backenddata:sub(offset, key_end-1)
    offset = key_end + 1
    offset = offset + 4 -- 跳过4字节表示的ThreadID

    key_end = backenddata:find("\0", offset, true)
    if key_end == nil then return end
    
    offset = key_end + 1 -- 跳过第一个salt结尾的\0
    offset = offset + 2 + 1 -- 跳过2字节表示的服务器能力 和 1字节表示的服务器字符集
    offset = offset + 2 + 2 -- 跳过2字节表示的服务器状态 和 2字节表示的服务器能力
    offset = offset + 1 -- 跳过1字节表示的授权插件的长度
    offset = offset + 10 
    
    local key_end = backenddata:find("\0", offset, true)
    if key_end == nil then return end

    offset = key_end + 1 -- 跳过第二个salt结尾的\0

    local key_end = backenddata:find("\0", offset, true)
    if key_end == nil then return end

    local auth_plugin_name = backenddata:sub(offset, key_end-1)

    loger.add_info_log("parse_mysql_greeting_message, pktlen: %d, version: %s, auth_plugin_name: %s, routeInfo: %s", pktlen, version, auth_plugin_name, meta.routeInfo)
    utils.attach_metadata(backend_sock, {version = version, auth_plugin_name = auth_plugin_name})  
end

-- 记录登录失败次数
local function process_login_failed_message(client_sock, backend_sock)
    local meta = utils.get_metadata(client_sock)

    utils.attach_metadata(backend_sock, {server_session_status = mysql_const_data.SESSION_STATE_SERVER_LOGIN_FAILED})

    local loginFailedCount, err = utils.get_login_failed_count(meta.loginUuid)
    if loginFailedCount == nil then
        loger.add_error_log("process_login_failed_message, get_login_failed_count failed: %s", err)
        return
    end

    local lock, _ = utils.Lock(meta.loginUuid, "process_login_failed_message")
    if lock == nil then return end

    loginFailedCount = tonumber(loginFailedCount) + 1
    err = utils.set_login_failed_count(meta.loginUuid, loginFailedCount)
    if err ~= nil then
        loger.add_error_log("process_login_failed_message, set_login_failed_count failed: %s", err)
    end

    lock:unlock()
end

local function process_login_success_message(client_sock, backend_sock)
    local meta = utils.get_metadata(client_sock)

    utils.attach_metadata(client_sock, {client_session_status = mysql_const_data.SESSION_STATE_CLIENT_QUERY})
    utils.attach_metadata(backend_sock, {server_session_status = mysql_const_data.SESSION_STATE_SERVER_QUERY_RESPONSE})

    local lock, _ = utils.Lock(meta.loginUuid, "process_login_success_message")
    if lock == nil then return end

    local err = utils.set_login_failed_count(meta.loginUuid, 0)
    if err ~= nil then
        loger.add_error_log("process_login_success_message, set_login_failed_count failed: %s", err)
    end

    lock:unlock()
end

local function parse_mysql_login_response_message(client_sock, backend_sock, backenddata)
    local offset = 1
    local meta = utils.get_metadata(client_sock)
    local pktlen = utils.unpack_little_endian(backenddata, offset, 3)
    if pktlen == 2 then
        offset = offset + 3 + 1 -- 跳过3字节表示的长度 1字节表示的包序号
        local b1, b2 = backenddata:byte(offset, offset + 1)
        if b1 == 0x01 and b2 == 0x03 then --登录成功
            loger.add_info_log("parse_mysql_login_response_message, login success(0x01, 0x03), pktlen: %d, %s", pktlen, meta.prompt)
            process_login_success_message(client_sock, backend_sock)
        elseif b1 == 0x01 and b2 == 0x04 then --登录失败
            loger.add_error_log("parse_mysql_login_response_message, login failed(0x01, 0x04), pktlen: %d, %s", pktlen, meta.prompt)            
            process_login_failed_message(client_sock, backend_sock)
        end
        return
    end

    if pktlen >= mysql_const_data.MYSQL_OK_PACKAGE_LESS_LEN then
        offset = offset + 3 + 1 -- 跳过3字节表示的长度 1字节表示的包序号
        local b1 = backenddata:byte(offset)
        if b1 == 0x00 then -- mysql ok package
            loger.add_info_log("parse_mysql_login_response_message, login success(0x00), pktlen: %d, %s", pktlen, meta.prompt)
            process_login_success_message(client_sock, backend_sock)
        elseif b1 == 0xfe then -- mysql eof package
            loger.add_error_log("parse_mysql_login_response_message, login failed(0xfe), pktlen: %d, %s", pktlen, meta.prompt)
            process_login_failed_message(client_sock, backend_sock)
        elseif b1 == 0xff then -- mysql err package
            loger.add_error_log("parse_mysql_login_response_message, login failed(0xff), pktlen: %d, %s", pktlen, meta.prompt)
            process_login_failed_message(client_sock, backend_sock)
        end
        return
    end

    utils.attach_metadata(backend_sock, {server_session_status = mysql_const_data.SESSION_STATE_SERVER_LAST})
end

local function parse_mysql_login_failed_message(client_sock, backend_sock, backenddata)
    local offset = 1
    local meta = utils.get_metadata(client_sock)
    offset = offset + 3 + 1 -- 跳过3字节表示的长度 1字节表示的包序号
    local b1 = backenddata:byte(offset)
    if b1 == 0xff then  -- ResponseCode: ERR Packet
        offset = offset + 1 + 2 + 1 + 5
        local login_failed_resaon = backenddata:sub(offset)
        loger.add_error_log("parse_mysql_login_failed_message, login failed, reason: %s, %s", login_failed_resaon, meta.prompt)
    end
end

local function read_mysql_field_length(offset, backenddata)
    -- Refer: https://dev.mysql.com/doc/internals/en/integer.html
    local field_length = backenddata:byte(offset)
    offset = offset + 1
    if field_length < 0xfb then
        return offset, field_length
    end
    
    if field_length == 0xfc then
        field_length = utils.unpack_little_endian(backenddata, offset, 2)
        offset = offset + 2
        return offset, field_length
    end
    
    if field_length == 0xfd then
        field_length = utils.unpack_little_endian(backenddata, offset, 3)
        offset = offset + 3
        return offset, field_length
    end

    return offset, -1
end

-- return true: record audit log, return false: no record audit log
local function parse_mysql_downstream_data(client_sock, backenddata)
    local meta = utils.get_metadata(client_sock)
    if meta.querySql == nil or meta.querySql == "" then
        return false
    end

    -- extraction last 7 bytes of sql and compare with "LIMIT 0"
    local last_seven = string.sub(meta.querySql, -7)
    if last_seven == "LIMIT 0" then
        return false
    end

    -- local data = utils.print_binary(backenddata)
    -- loger.add_warn_log("parse_mysql_downstream_data, data: %s", data)

    local offset = 1
    local total_data_length = #backenddata
    local mysql_protocol_total_length = utils.unpack_little_endian(backenddata, offset, 3)

    local column_name_count = backenddata:byte(offset + 4) -- 3 bytes length and 1 bytes pkt serial Number
    if column_name_count == mysql_const_data.MYSQL_ERR_MARKER then
        offset = offset + 4 + mysql_protocol_total_length + 2
        local errmsg = backenddata:sub(offset)
        loger.add_warn_log("parse_mysql_downstream_data, sqlFailed reason: %s, %s", errmsg, meta.prompt)
        return true
    end

    loger.add_warn_log("begin parse_mysql_downstream_data, column_name_count: %d", column_name_count)

    if column_name_count == mysql_const_data.MYSQL_OK_MARKER then
        return true
    end

    local all_columns_name = ""

    -- offsetbak save next mysql protocol pkt position
    offset = offset + 4 + mysql_protocol_total_length
    local offsetbak = offset

    local current_column_index = 0
    while offsetbak < total_data_length do
        offset = offsetbak
        mysql_protocol_total_length = utils.unpack_little_endian(backenddata, offset, 3)
        -- loger.add_warn_log("begin parse_mysql_downstream_data, mysql_protocol_total_length: %d", mysql_protocol_total_length)

        offsetbak = offset + 4 + mysql_protocol_total_length

        -- skip 3 bytes length and 1 bytes pkt serial Number
        offset = offset + 4

        local field_length = backenddata:byte(offset)
        if field_length == mysql_const_data.MYSQL_EOF_MARKER then
            loger.add_warn_log("parse_mysql_downstream_data, column name parse end, stop while")
            break
        end

        -- skip Catalog(def)
        local catalog_name = backenddata:sub(offset + 1, offset + 1 + field_length - 1)
        -- loger.add_warn_log("Catalog field length: %d, catalog_name: %s(length: %d)", field_length, catalog_name, #catalog_name)
        offset = offset + 1 + field_length

        -- skip database
        field_length = backenddata:byte(offset)
        local database_name = backenddata:sub(offset+1, offset+1 + field_length - 1)
        -- loger.add_warn_log("database field length: %d, database_name: %s(length: %d)", field_length, database_name, #database_name)
        offset = offset + 1 + field_length
        
        -- skip table
        field_length = backenddata:byte(offset)
        local table_name = backenddata:sub(offset+1, offset + 1 + field_length - 1)
        -- loger.add_warn_log("table field length: %d, table_name: %s(length: %d)", field_length, table_name, #table_name)
        offset = offset + 1 + field_length

        -- skip origin table
        field_length = backenddata:byte(offset)
        local origin_table_name = backenddata:sub(offset+1, offset + 1 + field_length - 1)
        -- loger.add_warn_log("origin table field length: %d, origin_table_name: %s(length: %d)", field_length, origin_table_name, #origin_table_name)
        offset = offset + 1 + field_length

        -- get column name
        field_length = backenddata:byte(offset)
        offset = offset + 1
        local column_name = backenddata:sub(offset, offset + field_length - 1)
        current_column_index = current_column_index + 1
        -- loger.add_info_log("column name field index: %d, column_name: %s (length: %d)", current_column_index, column_name, #column_name)
        if current_column_index == column_name_count then
            all_columns_name = all_columns_name .. column_name
        else
            all_columns_name = all_columns_name .. column_name .. "<|>"
        end
    end

    loger.add_info_log("column_name: %s", all_columns_name)

    local continue_while = true
    while offsetbak < total_data_length do
        offset = offsetbak
        mysql_protocol_total_length = utils.unpack_little_endian(backenddata, offset, 3)
        -- loger.add_warn_log("begin parse_mysql_downstream_data, mysql_protocol_total_length: %d", mysql_protocol_total_length)

        offsetbak = offset + 4 + mysql_protocol_total_length
        if offsetbak > total_data_length then
            break
        end

        -- skip 3 bytes length and 1 bytes pkt serial Number
        offset = offset + 4

        local field_length = backenddata:byte(offset)
        if field_length == mysql_const_data.MYSQL_EOF_MARKER then
            loger.add_warn_log("parse_mysql_downstream_data, column value parse end, stop while")
            break
        end

        local single_down_data = ""
        for i = 1, column_name_count do
            offset, field_length = read_mysql_field_length(offset, backenddata)
            if field_length == -1 then
                continue_while = false
                loger.add_error_log("parse_mysql_downstream_data, column value parse error, stop while")
                break
            end

            if continue_while == false then
                break
            end

            if field_length == 0 then
                -- loger.add_info_log("column name field index: %d, column_value: NULL (length: 0)", i)
                if single_down_data == "" then
                    single_down_data =  "<^>NULL"
                else
                    single_down_data = single_down_data .. "<|>NULL"
                end
            else
                local column_value = backenddata:sub(offset, offset + field_length - 1)
                -- loger.add_info_log("column name field index: %d, column_value: %s (length: %d)", i, column_value, #column_value)
                offset = offset + field_length

                if single_down_data == "" then
                    single_down_data =  "<^>" .. column_value
                else
                    single_down_data = single_down_data .. "<|>" .. column_value
                end
            end
        end

        loger.add_info_log("single_down_data: %s", single_down_data)
    end

    utils.attach_metadata(client_sock, { downdata = all_columns_name })
    -- loger.add_info_log("all_columns_name: %s", meta.downdata)
    return true
end

local function forward_data_to_client(backend_sock, client_sock)
    while true do
        local backenddata, err = backend_sock:receiveany(81920)  -- 非阻塞读取
        if not backenddata then
            local meta = utils.get_metadata(client_sock)
            if err == "closed" then
                loger.add_warn_log("server close connection, routeInfo: %s", meta.routeInfo)
            else
                loger.add_warn_log("server close connection, receive error: %s, routeInfo: %s", err, meta.routeInfo)
            end
            break
        end

        local server_session_status = utils.get_metadata(backend_sock).server_session_status
        if server_session_status == mysql_const_data.SESSION_STATE_SERVER_GREET then
            parse_mysql_greeting_message(client_sock, backend_sock, backenddata)
        elseif server_session_status == mysql_const_data.SESSION_STATE_SERVER_LOGIN_RESPONSE then
            parse_mysql_login_response_message(client_sock, backend_sock, backenddata)
        elseif server_session_status == mysql_const_data.SESSION_STATE_SERVER_LOGIN_FAILED then
            parse_mysql_login_failed_message(client_sock, backend_sock, backenddata)
        elseif server_session_status == mysql_const_data.SESSION_STATE_SERVER_QUERY_RESPONSE then
            local is_record_audit_log = parse_mysql_downstream_data(client_sock, backenddata)
            if is_record_audit_log == true then
                record_mysql_audit_log(client_sock)
            end
        end

        local bytes, err = client_sock:send(backenddata)  -- 转发数据
        if not bytes then
            loger.add_error_log("forward_data_to_client, backend -> client, send error: %s", err)
            break
        end
    end
end

_M.forward_data_to_client = forward_data_to_client

return _M