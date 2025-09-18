local ngx = ngx
local string = string
local table = table

local cjson = require "cjson"
local utils = require "utils"
local pgsql_const_data = require "pgsql_const_data"
local loger = require "pgsql_proxy_timer_logs"

local _M = {}

local function match_system_sql(sql)
    for ruleType, rules in pairs(pgsql_const_data.SqlMatchRule) do
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

local function send_sql_mask_message(client_sock, originSql)
    local meta = utils.get_metadata(client_sock)
    local requestDataTable = {
        targetIp = meta.targetIp,
        targetPort = meta.targetPort,
        vpPort = meta.vpPort,
        targetType = globalCfg.pgsql.targetType,
        sourceIp = ngx.var.remote_addr,
        dbName = meta.database,
        account = meta.masterAccount or meta.user,
        outcardIp = globalCfg.localAddressIp,
        originSql = originSql
    }

    local requestData = cjson.encode(requestDataTable)
    loger.add_info_log("sql_mask_request: %s, routeinfo: %s, sqlMaskUrl: %s", requestData, meta.routeinfo, globalCfg.sqlMaskUrl)
    return utils.send_http_request(globalCfg.sqlMaskUrl, requestData)
end

local function send_lock_account_message(client_sock, MaxLoginFailedLimit)
    local meta = utils.get_metadata(client_sock)
    local requestDataTable = {
        sourceIp = ngx.var.remote_addr,
        targetIp = meta.targetIp,
        targetPort = meta.targetPort,
        targetType = globalCfg.pgsql.targetType,
        account = meta.user,
        outcardIp = globalCfg.localAddressIp,
        loginFailNum = MaxLoginFailedLimit,
        vpPort = meta.vpPort,
    }

    local requestData = cjson.encode(requestDataTable)
    loger.add_warn_log("lock_account_request: %s, %s", requestData, meta.routeinfo)
    return utils.send_http_request(globalCfg.accountLockUrl, requestData)
end

local function parse_login_data(client_sock, clientdata)
    local offset = 9
    local username, dbname
    
    while offset <= #clientdata do

        -- clientdata:find 说明： 
        --    "\0": 搜索 NULL 字符（二进制安全的零字节）
        --    offset表示查找的起始位置，字符串索引从 1 开始
        --    true表示禁用正则匹配
        --    返回值：如果找到，返回 NULL 字符的位置；否则返回 nil
        local key_end = clientdata:find("\0", offset, true)
        if not key_end then break end
        
        local key = clientdata:sub(offset, key_end-1)
        offset = key_end + 1
        
        local value_end = clientdata:find("\0", offset, true)
        if not value_end then break end
        
        local value = clientdata:sub(offset, value_end-1)
        offset = value_end + 1
        
        if key == "user" then
            username = value
        elseif key == "database" then
            dbname = value
        end
    end
    
    utils.attach_metadata(client_sock, { user = username, database = dbname})
    return "ok"
end

--[[
return value: 
    nil 解析出错，未转发到后端，由后续流程转发; 
    0 不处理，未转发到后端，由后续流程转发; 
    1 已处理，未转发到后端, 后续流程不转发; 
--]]
local function parse_startup_message(client_sock, clientdata, backend_sock)
    if #clientdata == 8 then 
        return 0, nil 
    end

    local meta = utils.get_metadata(client_sock)
    local dbuniqueID = meta.dbuniqueID

    local red, err = utils.get_redis("parse_startup_message")
    if red == nil then
        loger.add_error_log("parse_startup_message, dbuniqueID: %s, Connect redis failed, err: %s", dbuniqueID, err)
        return 0, nil
    end

    local length = utils.unpack_big_endian(clientdata, 1, 4)
    -- local version = utils.unpack_big_endian(clientdata, 5, 4)
    -- loger.add_debug_log("length: %d, version: %d", length, version)

    parse_login_data(client_sock, clientdata)

    local separator = "__"
    local startpos, stoppos = meta.database:find(separator, 0, true) -- 从位置0开始查找__, true表示禁用正则匹配
    if startpos == nil or stoppos == nil then
        red:select(15)
        local get_main_account_failed_msg = red:get("pgsql_get_main_account_failed_msg")
        client_sock:send(get_main_account_failed_msg)
        loger.add_warn_log("parse_startup_message, parse masterAccount failed, by %s, %s",separator, meta.routeinfo)
        return 1, nil
    end

    local masterAccount = meta.database:sub(startpos+2)
    if masterAccount == nil or masterAccount == "" then
        red:select(15)
        local get_main_account_failed_msg = red:get("pgsql_get_main_account_failed_msg")
        client_sock:send(get_main_account_failed_msg)
        loger.add_warn_log("parse_startup_message, parse masterAccount failed, masterAccount is nil or empty, %s", meta.routeinfo)
        return 1, nil
    end

    utils.attach_metadata(client_sock, { masterAccount = masterAccount })
    meta.database = meta.database:sub(0, startpos-1)

    -- 记录当前登录用户的唯一标识到 Redis
    local loginUuid = "pgsql#" .. dbuniqueID.."#".. meta.user
    utils.attach_metadata(client_sock, { loginUuid = loginUuid })

    loger.add_info_log("parse_startup_message, user: %s, database: %s, masterAccount: %s, dbuniqueID: %s, loginUuid: %s, routeinfo: %s", 
        meta.user, meta.database, meta.masterAccount, dbuniqueID, loginUuid, meta.routeinfo)

    local dbUniqueIDExist, _ = red:exists(dbuniqueID)
    loger.add_info_log("parse_startup_message, dbuniqueID: %s, loginUuid: %s, dbUniqueIDExist: %s", dbuniqueID, loginUuid, dbUniqueIDExist)

    local exists, _ = red:exists(loginUuid)
    if exists == 0 then
        local res, err = red:hmset(loginUuid,
        "CurrentLoginFailedCount", 0,
        "AddTime", ngx.localtime())

        if not res then
            loger.add_error_log("parse_startup_message, Failed to set data: %s, loginUuid: %s", err, loginUuid)
        else
            loger.add_info_log("parse_startup_message, Successed to set loginUuid: %s to redis ", loginUuid)
        end
    elseif exists == 1 then
        -- 判断当前用户是否达到最大登录失败次数
        if dbUniqueIDExist == 1 then
            local MaxLoginFailedLimit = red:hget(dbuniqueID, "MaxLoginFailedLimit")
            local loginFailedCount, _ = red:hget(loginUuid, "CurrentLoginFailedCount")
            loger.add_info_log("parse_startup_message, dbuniqueID: %s, loginFailedCount: %s, MaxLoginFailedLimit: %s", dbuniqueID, loginFailedCount, MaxLoginFailedLimit)
            if tonumber(loginFailedCount) >= tonumber(MaxLoginFailedLimit) then
                loger.add_error_log("parse_startup_message, loginFailedCount(%d) > MaxLoginFailedLimit(%d), loginUuid: %s", loginFailedCount, MaxLoginFailedLimit, loginUuid)

                red:select(15)
                local reach_max_login_failures_msg = red:get("pgsql_reach_max_login_failures_msg")
                client_sock:send(reach_max_login_failures_msg)
                red:set_keepalive(30000, 200)
                send_lock_account_message(client_sock, MaxLoginFailedLimit)
                return 1, nil
            end
        end
    end

    -- 判断数据库是否达到了最大连接数
    if dbUniqueIDExist == 1 then
        local currentConnCount = utils.get_counter(dbuniqueID)
        local connLimit, _ = red:hget(dbuniqueID, "MaxConnectLimit")
        if currentConnCount > tonumber(connLimit) then
            loger.add_error_log("parse_startup_message, currentConnCount(%d) > connLimit(%s)", currentConnCount, connLimit)

            red:select(15)
            local reach_max_connection_limit_msg = red:get("pgsql_reach_max_connection_limit_msg")
            client_sock:send(reach_max_connection_limit_msg)
            red:set_keepalive(30000, 200)
            return 1, nil
        end
    end

    -- 将连接放回连接池
    red:set_keepalive(30000, 200)

    local delete_data = separator .. masterAccount
    local new_length = utils.int_to_4bytes(length - #delete_data, true)
    startpos, stoppos = clientdata:find(delete_data, 1, true)
    clientdata = new_length .. clientdata:sub(5, startpos-1) .. clientdata:sub(stoppos+1, -1)
    backend_sock:send(clientdata)
    return 1, nil
end

-- return value: 
--    nil 解析出错，未转发到后端，由后续流程转发; 
--    0 不处理，未转发到后端，由后续流程转发; 
--    1 已处理，已转发到后端
local function parse_query_message(client_sock, clientdata, backend_sock)
    local length = utils.unpack_big_endian(clientdata, 2, 4)
    -- loger.add_debug_log(", length: ", length)
    if (length + 1) ~= #clientdata then 
        return nil, "invalid query message"
    end

    local meta = utils.get_metadata(client_sock)
    local opSql = clientdata:sub(6, length)
    if opSql == pgsql_const_data.QUERY_DBNAME_SQL then
        local newsql = "SELECT d.oid, d.datname||'__" .. meta.masterAccount .. "' AS databasename, d.datacl, d.datistemplate, d.datallowconn, pg_get_userbyid(d.datdba) AS databaseowner, d.datcollate, d.datctype, shobj_description(d.oid, 'pg_database') AS description, d.datconnlimit, t.spcname, d.encoding, pg_encoding_to_char(d.encoding) AS encodingname FROM pg_database d LEFT JOIN pg_tablespace t ON d.dattablespace = t.oid"

        local new_length = utils.int_to_4bytes(#newsql+5, true)
        clientdata = clientdata:sub(1, 1) .. new_length .. newsql .. '\x00'
        backend_sock:send(clientdata)

        utils.set_login_failed_count(meta.loginUuid, 0)
        return 1, nil
    end

    -- \b 匹配单词边界（避免误匹配，如 SELECTION 不会触发 SELECT）
    -- "i" 表示不区分大小写
    local isMatch = ngx.re.match(opSql, [[\bINSERT\b]], "i")
    if isMatch then return 0, nil end

    isMatch = ngx.re.match(opSql, [[\bUPDATE\b]], "i")
    if isMatch then return 0, nil end

    isMatch = ngx.re.match(opSql, [[\bDROP\b]], "i")
    if isMatch then return 0, nil end

    -- 系统sql判断，如果判断为系统sql，则不脱敏，不审计
    local isSysSql, reason = match_system_sql(opSql)
    if isSysSql == true then
        loger.add_debug_log("parse_query_message, SystemSql: %s, Reason: %s, %s\n", opSql, reason,meta.routeinfo)
        meta.querySql = nil
        return 0, nil
    end

    loger.add_info_log("parse_query_message, user: %s, database: %s, masterAccount: %s, QuerySql: %s, %s", 
        meta.user, meta.database, meta.masterAccount, opSql, meta.routeinfo)

    utils.attach_metadata(client_sock, { querySql = opSql })

    -- 开始执行脱敏操作
    local result, err = send_sql_mask_message(client_sock, opSql);
    if result == nil then 
        loger.add_error_log("parse_query_message, send_sql_mask_message failed(pass), reason: %s", err)
        return 0, nil
    end

    loger.add_info_log("parse_query_message, user: %s, database: %s, masterAccount: %s, SqlMask result: %s", 
        meta.user, meta.database, meta.masterAccount, result)

    local respTable = cjson.decode(result)
    local status = tonumber(respTable.successStatus)
    if status == 0 then  -- 脱敏成功
        local newSql = respTable.newSql
        loger.add_info_log("parse_query_message, newSql: %s", newSql)
        local new_length = utils.int_to_4bytes(#newSql+5, true)
        clientdata = clientdata:sub(1, 1) .. new_length .. newSql .. '\x00'
        backend_sock:send(clientdata)
        return 1, nil
    elseif status == 1 or status == 2 then -- 1:脱敏失败， 2:不脱敏 原样转发到后端数据库
        return 0, nil
    elseif status == 3 then -- 3:阻断当前操作，不转发到后端数据库
        local red, _ = utils.get_redis("parse_query_message", 15)
        if red ~= nil then
            local reject_operation_msg = red:get("pgsql_reject_operation_msg")
            local ready_for_query_msg = red:get("pgsql_ready_for_query_msg")
            client_sock:send(reject_operation_msg)
            client_sock:send(ready_for_query_msg)
            return 1, nil
        else
            return 0, nil  -- 其他的未知状态码原样转发到后端数据库
        end
    else
        return 0, nil  -- 其他的未知状态码原样转发到后端数据库
    end
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
		
		-- local binarydata = utils.print_binary(clientdata)
        -- loger.add_debug_log("forward_data_to_server, receive data: %s", binarydata)
        local msgtype = clientdata:byte(1)
        utils.attach_metadata(client_sock, { clientMsgType = msgtype} )
        if #clientdata >= 8 then
            if msgtype == 0 then
                local result, err = parse_startup_message(client_sock, clientdata, backend_sock)
                if result == nil then
                    loger.add_error_log("forward_data_to_server, parse startup message error: %s", err)
                    break
                elseif result == 1 then
                    goto continue
                end
            elseif msgtype == pgsql_const_data.PGSQL_CLIENT_CMD_QUERY then
                local result, err = parse_query_message(client_sock, clientdata, backend_sock)
                if result == nil then
                    loger.add_error_log("forward_data_to_server, parse query message error: %s", err)
                    break
                elseif result == 1 then
                    goto continue
                end
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