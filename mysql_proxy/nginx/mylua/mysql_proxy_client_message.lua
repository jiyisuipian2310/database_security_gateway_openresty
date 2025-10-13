local ngx = ngx
local string = string
local table = table

local cjson = require "cjson.safe"
local loger = require "mysql_proxy_timer_logs"
local utils = require "utils"
local mysql_const_data = require "mysql_const_data"

local _M = {}

local function match_system_sql(sql)
    for ruleType, rules in pairs(mysql_const_data.SqlMatchRule) do
        if ruleType == "NotRegularExpression" then
            for _, rule in ipairs(rules) do
                if string.find(sql, rule) then
                    return true, "Match NotRegularExpression"
                end
            end
        else
            for _, rule in ipairs(rules) do
                if ngx.re.match(sql, rule, "jo") then
                    return true, "Match RegularExpression"
                end
            end
        end
    end
    return false, nil
end

local function send_sqlmask_message(client_sock, originSql)
    local meta = utils.get_metadata(client_sock)
    local requestDataTable = {
        targetIp = meta.targetIp,
        targetPort = meta.targetPort,
        vpPort = meta.vpPort,
        targetType = globalCfg.mysql.targetType,
        sourceIp = ngx.var.remote_addr,
        dbName = meta.database,
        account = meta.masterAccount or meta.user,
        outcardIp = globalCfg.localAddressIp,
        originSql = originSql
    }

    local requestData = cjson.encode(requestDataTable)
    loger.add_info_log("sql_mask_request: %s, routeInfo: %s, sqlMaskUrl: %s", requestData, meta.routeInfo, globalCfg.sqlMaskUrl)
    return utils.send_http_request(globalCfg.sqlMaskUrl, requestData)
end

local function send_lock_account_message(client_sock, MaxLoginFailedLimit)
    local meta = utils.get_metadata(client_sock)
    local requestDataTable = {
        sourceIp = ngx.var.remote_addr,
        targetIp = meta.targetIp,
        targetPort = meta.targetPort,
        targetType = globalCfg.mysql.targetType,
        account = meta.user,
        outcardIp = globalCfg.localAddressIp,
        loginFailNum = MaxLoginFailedLimit,
        vpPort = meta.vpPort,
    }

    local requestData = cjson.encode(requestDataTable)
    loger.add_warn_log("lock_account_request: %s, %s", requestData, meta.routeinfo)
    return utils.send_http_request(globalCfg.accountLockUrl, requestData)
end

-- 返回值：true表示已转发数据到客户端，false表示未转发数据到客户端
local function parse_mysql_login_message(client_sock, backend_sock, clientdata)
    local offset = 1
    local meta = utils.get_metadata(client_sock)
    local dbuniqueID = meta.dbuniqueID

    local pktlen = utils.unpack_little_endian(clientdata, offset, 3)
    if pktlen < 64 then return false end

    local red, err = utils.get_redis("parse_mysql_login_message")
    if red == nil then
        loger.add_error_log("parse_mysql_login_message, dbuniqueID: %s, Connect redis failed, err: %s", dbuniqueID, err)
        return 0, nil
    end
    
    offset = offset + 3 + 1 -- 跳过3字节表示的长度 1字节表示的包序号
    offset = offset + 2 + 2 -- 跳过2字节表示的客户端的能力 和 跳过2字节表示的客户端的扩展能力
    offset = offset + 4 -- 跳过4字节表示的MaxPacketSize
    offset = offset + 1 -- 跳过1字节表示的字符编码
    offset = offset + 23 -- 跳过23字节的填充位

    local login_user_zero_pos = clientdata:find("\0", offset, true)
    if login_user_zero_pos == nil then
        local binarydata = utils.print_binary(clientdata)
        loger.add_warn_log("routeInfo: %s, clientdata: %s", meta.routeInfo, binarydata)
        return false
    end

    local separator = "__"
    
    local original_login_user = clientdata:sub(offset, login_user_zero_pos-1)
    local key_end = original_login_user:find(separator, 1, true)
    if key_end == nil then
        if true then
            client_sock:send(mysql_const_data.get_main_account_failed_msg)
            loger.add_warn_log("parse_mysql_login_message, No separators found, parse masterAccount failed by %s, %s", separator, meta.routeInfo)
            return true
        else
            local prompt = string.format("user: %s, masterAccount: nil, routeInfo: %s", original_login_user, meta.routeInfo)
            loger.add_info_log("parse_mysql_login_message, No separators found, %s", prompt)
            utils.attach_metadata(client_sock, {user = original_login_user, prompt = prompt})
            utils.attach_metadata(backend_sock, {server_session_status = mysql_const_data.SESSION_STATE_SERVER_LOGIN_RESPONSE})
        end
        return false
    end

    local masterAccount = original_login_user:sub(key_end+2)
    if #masterAccount == 0 then
        client_sock:send(mysql_const_data.get_main_account_failed_msg)
        loger.add_warn_log("parse_mysql_login_message, Separators found, masterAccount is empty, %s", meta.routeInfo)
        return false
    end

    local real_login_user = original_login_user:sub(1, key_end-1)
    utils.attach_metadata(client_sock, {user = real_login_user, masterAccount = masterAccount})

    local loginUuid = "mysql#" .. dbuniqueID.."#".. real_login_user
    utils.attach_metadata(client_sock, { loginUuid = loginUuid })

    local dbUniqueIDExist, _ = red:exists(dbuniqueID)
    loger.add_info_log("parse_mysql_login_message, dbuniqueID: %s, loginUuid: %s, dbUniqueIDExist: %s", dbuniqueID, loginUuid, dbUniqueIDExist)

    local exists, _ = red:exists(loginUuid)
    if exists == 0 then
        local res, err = red:hmset(loginUuid,
        "CurrentLoginFailedCount", 0,
        "AddTime", ngx.localtime())

        if not res then
            loger.add_error_log("parse_mysql_login_message, Failed to set data: %s, loginUuid: %s", err, loginUuid)
        else
            loger.add_info_log("parse_mysql_login_message, Successed to set loginUuid: %s to redis ", loginUuid)
        end
    elseif exists == 1 then
        -- 判断当前用户是否达到最大登录失败次数
        if dbUniqueIDExist == 1 then
            local MaxLoginFailedLimit = red:hget(dbuniqueID, "MaxLoginFailedLimit")
            local loginFailedCount, _ = red:hget(loginUuid, "CurrentLoginFailedCount")
            loger.add_info_log("parse_mysql_login_message, dbuniqueID: %s, loginFailedCount: %s, MaxLoginFailedLimit: %s", dbuniqueID, loginFailedCount, MaxLoginFailedLimit)

            if MaxLoginFailedLimit ~= nil and MaxLoginFailedLimit ~= "" and tonumber(loginFailedCount) >= tonumber(MaxLoginFailedLimit) then
                loger.add_error_log("parse_mysql_login_message, loginFailedCount(%d) > MaxLoginFailedLimit(%d), loginUuid: %s", loginFailedCount, MaxLoginFailedLimit, loginUuid)
                red:set_keepalive(30000, 200)
                client_sock:send(mysql_const_data.reach_max_login_failures_msg)
                send_lock_account_message(client_sock, MaxLoginFailedLimit)
                return true, nil
            end
        end
    end

    -- 判断数据库是否达到了最大连接数
    if dbUniqueIDExist == 1 then
        local currentConnCount = utils.get_counter(dbuniqueID)
        local connLimit, _ = red:hget(dbuniqueID, "MaxConnectLimit")
        if connLimit ~= nil and connLimit ~= "" and currentConnCount > tonumber(connLimit) then
            loger.add_error_log("parse_mysql_login_message, currentConnCount(%d) > connLimit(%s)", currentConnCount, connLimit)
            red:set_keepalive(30000, 200)
            client_sock:send(mysql_const_data.reach_max_connection_limit_msg)
            return true, nil
        end
    end

    red:set_keepalive(30000, 200)

    local new_length = utils.int_to_3bytes(pktlen - #masterAccount - 2, false)
    local newclientdata = new_length .. clientdata:sub(4, offset + #real_login_user - 1) .. clientdata:sub(login_user_zero_pos)
    local sendbytes, err = backend_sock:send(newclientdata)  -- 转发数据
    if not sendbytes then
        loger.add_error_log("parse_mysql_login_message, forward_data_to_server, send error: %s", err)
        return false
    end

    local prompt = string.format("user: %s, masterAccount: %s, routeInfo: %s", real_login_user, masterAccount, meta.routeInfo)
    loger.add_info_log("parse_mysql_login_message, Separators found, %s", prompt)
    utils.attach_metadata(backend_sock, {server_session_status = mysql_const_data.SESSION_STATE_SERVER_LOGIN_RESPONSE})
    utils.attach_metadata(client_sock, {prompt = prompt, user = real_login_user, masterAccount = masterAccount})

    return true
end

-- 返回值：true表示已转发数据到客户端，false表示未转发数据到客户端
local function parse_mysql_init_db_message(client_sock, clientdata)
    local meta = utils.get_metadata(client_sock)
    local pktlen = utils.unpack_little_endian(clientdata, 1, 3)
    meta.database = clientdata:sub(6)
    loger.add_info_log("parse_mysql_init_db_message, pktlen: %d, user: %s, masterAccount: %s, database: %s, %s", pktlen, meta.user, meta.masterAccount, meta.database, meta.prompt)
    return false
end

-- 返回值：true表示已转发数据到客户端，false表示未转发数据到客户端
local function parse_mysql_com_query_message(client_sock, backend_sock, clientdata)
    local meta = utils.get_metadata(client_sock)
    local sql = clientdata:sub(6)
    local isSysSql, reason = match_system_sql(sql) -- 系统sql判断，如果判断为系统sql，则不脱敏，不审计
    if isSysSql == true then
        loger.add_debug_log("parse_mysql_com_query_message, SystemSql: %s, Reason: %s\n", sql, reason)
        meta.querySql = nil
        return false
    end

    utils.attach_metadata(client_sock, { querySql = sql })
    loger.add_info_log("parse_mysql_com_query_message, %s, QuerySql: %s", meta.prompt, sql)

    -- 开始执行脱敏操作
    local result, err = send_sqlmask_message(client_sock, sql);
    if result == nil then
        loger.add_error_log("send_sqlmask_message failed, %s, reason: %s", meta.prompt, err)
        return false
    end

    loger.add_info_log("send_sqlmask_message success, %s, SqlMask result: %s", meta.prompt, result)

    local respTable = cjson.decode(result)
    local status = tonumber(respTable.successStatus)
    if status == 0 then  -- 脱敏成功
        local pktlen = utils.unpack_little_endian(clientdata, 1, 3)
        local newSql = respTable.newSql
        local new_pktlen = utils.int_to_3bytes(pktlen + #newSql-#sql, false)
        local new_clientdata = new_pktlen .. clientdata:sub(4, 5) .. newSql
        loger.add_info_log("%s, newSql: %s", meta.prompt, newSql)
        backend_sock:send(new_clientdata)  -- 转发修改过的sql到后端数据库
        return true
    elseif status == 1 or status == 2 then -- 1:脱敏失败， 2:不脱敏 原样转发到后端数据库
        return false
    elseif status == 3 then -- 3:阻断当前操作，不转发到后端数据库
        client_sock:send(mysql_const_data.table_reject_operation_msg)
        loger.add_warn_log("send_sqlmask_message success, status is 3, refuse access, %s", meta.prompt)
        return true
    end

    return false
end

-- 返回值：true表示已转发数据到客户端，false表示未转发数据到客户端
local function parse_mysql_query_message(client_sock, backend_sock, clientdata)
    local command = clientdata:byte(5, 5)
    if command == 0x02 then  -- COM_INIT_DB
        return parse_mysql_init_db_message(client_sock, clientdata)
    elseif command == 0x03 then -- COM_QUERY
        return parse_mysql_com_query_message(client_sock, backend_sock,clientdata)
    end

    return false
end

local function forward_data_to_server(client_sock, backend_sock)
    local sendbytes = 0
    while true do
        local clientdata, err = client_sock:receiveany(81920)  -- 非阻塞读取
        if not clientdata then
            local meta = utils.get_metadata(client_sock)
            if err == "closed" then
                loger.add_warn_log("client close connection, routeInfo: %s", meta.routeInfo)
            else
                loger.add_warn_log("client close connection, receive error: %s, routeInfo: %s", err, meta.routeInfo)
            end
            break
        end

        local client_session_status = utils.get_metadata(client_sock).client_session_status
        if client_session_status == mysql_const_data.SESSION_STATE_CLIENT_LOGIN_REQUEST then
            local is_send = parse_mysql_login_message(client_sock, backend_sock, clientdata)
            if is_send then
                goto continue
            end
        elseif client_session_status == mysql_const_data.SESSION_STATE_CLIENT_QUERY then
            local is_send = parse_mysql_query_message(client_sock, backend_sock, clientdata)
            if is_send then
                goto continue
            end
        end
		
        sendbytes, err = backend_sock:send(clientdata)  -- 转发数据
        if not sendbytes then
            loger.add_error_log("forward_data_to_server, send error: %s", err)
            break
        end

        ::continue::
    end
end

_M.forward_data_to_server = forward_data_to_server

return _M