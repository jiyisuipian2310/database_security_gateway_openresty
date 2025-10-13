local ngx = ngx
local string = string
local table = table

local cjson = require "cjson.safe"
local utils = require "utils"
local pgsql_const_data = require "pgsql_const_data"
local loger = require "pgsql_proxy_timer_logs"
local auditlogs = require "pgsql_audit_logs"

local _M = {}

local function record_pgsql_audit_log(meta)
    if meta.querySql == nil or meta.querySql == "" then
        return
    end

    local json_table = {
        sourceIp = ngx.var.remote_addr,
        sourcePort = ngx.var.remote_port,
        targetIp = meta.targetIp,
        targetPort = meta.targetPort,
        eventCreateTime = ngx.localtime(),
        targetServiceName = (meta.schema ~= nil) and meta.schema or "",
        command = string.match(meta.querySql, "(%S+)"),
        tableName = "",
        dbType = "pgsql",
        auditSqlText = meta.querySql,
        netcardIp = globalCfg.localAddressIp,
        dataLength = (meta.rownum ~= nil) and meta.rownum or 0,
        data = meta.downdata ~= nil and meta.downdata or "",
        hostUsername = meta.user,
        loginUsername = meta.masterAccount or meta.user,
    }

    local json_parts = {}
    for _, key in ipairs(pgsql_const_data.audit_field_order) do
        local value = json_table[key]
        -- 特殊处理：确保字符串类型的值被正确转义
        if type(value) == "string" then
            table.insert(json_parts, string.format('"%s":"%s"', key, value:gsub('"', '\\"')))
        else
            table.insert(json_parts, string.format('"%s":%s', key, cjson.encode(value)))
        end
    end

    local json_str = "{" .. table.concat(json_parts, ",") .. "}"
    auditlogs.save_pgsql_audit_log(json_str)
    meta.querySql = nil
    meta.rownum = nil
    meta.downdata = nil
    meta.downdatacount = nil
end

local function deal_login_fail_message(client_sock, backenddata)
    local offset = 1
    local meta = utils.get_metadata(client_sock)
    local msgtype = backenddata:byte(1)
    if msgtype == pgsql_const_data.PGSQL_SERVER_CMD_AUTH then
        local length = utils.unpack_big_endian(backenddata, 2, 4)
        offset = offset + length
        msgtype = backenddata:byte(offset+1)
    end

    if msgtype ~= pgsql_const_data.PGSQL_SERVER_CMD_ERRRESPONSE then
        return  -- 不是登录失败消息
    end

    -- 分析出登录失败的原因
    -- backenddata:find 说明： 
    --    "\0": 搜索 NULL 字符（二进制安全的零字节）
    --    offset表示查找的起始位置，字符串索引从 1 开始
    --    true表示禁用正则匹配
    --    返回值：如果找到，返回 NULL 字符的位置；否则返回 nil
    offset = offset + 5 -- 跳过前 5 个字节(1字节的消息类型 4字节的消息长度)
    local total_data_len = #backenddata
    while offset < total_data_len do
        local zero_pos = backenddata:find("\0", offset, true)
        if zero_pos == nil then break end
        local flag = backenddata:sub(offset, offset)
        if flag == "M" then
            loger.add_warn_log("deal_login_fail_message,Login Failed, Account: %s, Reason: %s, Route: %s, loginDatabase: %s, loginUser: %s",
                 meta.masterAccount, backenddata:sub(offset+1, zero_pos), meta.routeinfo, meta.database, meta.user)
            break
        else
            offset = zero_pos + 1
        end
    end

    -- 记录登录失败次数
    local loginFailedCount, err = utils.get_login_failed_count(meta.loginUuid)
    if loginFailedCount == nil then
        loger.add_error_log("deal_login_fail_message, get_login_failed_count failed: %s", err)
        return
    end
    
    local lock, _ = utils.Lock(meta.loginUuid, "deal_login_fail_message")
    if lock == nil then return end

    loginFailedCount = tonumber(loginFailedCount) + 1
    err = utils.set_login_failed_count(meta.loginUuid, loginFailedCount)
    if err ~= nil then
        loger.add_error_log("deal_login_fail_message, set_login_failed_count failed: %s", err)
    end

    lock:unlock()
    
    loger.add_error_log("deal_login_fail_message, loginUuid: %s login failed, loginFailedCount: %d", meta.loginUuid, loginFailedCount)
end

-- 返回值 true: 需要记录审计日志  false: 不需要记录审计日志
local function parse_downstream_data(meta, backenddata)
    local offset = 1
    local length = 0

    if meta.querySql == nil or meta.querySql == "" then
        return false
    end

    local total_data_len = #backenddata
    -- loger.add_info_log("parse_downstream_data, querySql: %s, total_data_len: %d", meta.querySql, total_data_len)

    -- local hexdata = utils.print_binary(backenddata)
    -- loger.add_info_log("backenddata hexdata: %s", hexdata)

    while offset <= total_data_len do
        local tag = backenddata:byte(offset)
        if tag == 0 then
            offset = offset + 1
            goto continue
        end

        offset = offset + 1
        if tag == pgsql_const_data.PGSQL_SERVER_CMD_ROWDESC then
            -- 处理消息头'T' 0x54
            length = utils.unpack_big_endian(backenddata, offset, 4)

            local offsettmp = offset + 4
            local field_count = utils.unpack_big_endian(backenddata, offsettmp, 2)
            -- loger.add_info_log("tag:'T'(0x54) length: %d, field_count: %d", length, field_count)

            local column_name = ""
            offsettmp = offsettmp + 2
            for i = 1, field_count do
                local zero_pos = backenddata:find("\0", offsettmp, true)
                if zero_pos == nil then break end
                column_name = column_name .. backenddata:sub(offsettmp, zero_pos-1) .. "<|>"
                offsettmp = zero_pos + 1
                offsettmp = offsettmp + 18
            end

            meta.downdata = string.sub(column_name, 1, -4)
            loger.add_debug_log("tag:'T'(0x54), %s", meta.downdata)
        elseif tag == pgsql_const_data.PGSQL_SERVER_CMD_DATAROW then
            length = utils.unpack_big_endian(backenddata, offset, 4)

            -- 走到这里说明当前 'D' 类型的包是完整的，可以解析数据
            local offsettmp = offset + 4
            local field_count = utils.unpack_big_endian(backenddata, offsettmp, 2)
            local column_value = ""
            offsettmp = offsettmp + 2
            for i = 1, field_count do
                local column_length = utils.unpack_big_endian(backenddata, offsettmp, 4)
                offsettmp = offsettmp + 4
                column_value = column_value .. backenddata:sub(offsettmp, offsettmp+column_length-1) .. "<|>"
                offsettmp = offsettmp + column_length
            end

            column_value = string.sub(column_value, 1, -4)
            
            if meta.downdatacount==nil then meta.downdatacount = 0 end
            if meta.downdatacount < 20 then
                meta.downdatacount = meta.downdatacount + 1
                meta.downdata = meta.downdata .. "<^>" .. column_value
                loger.add_debug_log("tag:'D'(0x44), %s", column_value)
            else
                meta.rownum = 20
                return true  -- 达到记录审计日志的条件
            end
        elseif tag == pgsql_const_data.PGSQL_SERVER_CMD_CMDCOMPLETE then
            -- 处理消息头'C' 0x43
            length = utils.unpack_big_endian(backenddata, offset, 4)
            
            local offsettmp = offset + 4
            local substr = backenddata:sub(offsettmp, offsettmp+length-4-1)
            local matches = ngx.re.match(substr, [[(\d+)\D*$]], "jo")
            meta.rownum = matches and tonumber(matches[1]) or nil
            loger.add_debug_log("tag:'C'(0x43), substr: %s, type: %s, rownum: %s", substr, type(substr), meta.rownum)
        elseif tag == pgsql_const_data.PGSQL_SERVER_CMD_READYFORQUERY then
            -- 处理消息头'Z' 0x5a
            --length = utils.unpack_big_endian(backenddata, offset, 4)
            --loger.add_info_log("tag:'Z'(0x5a) length: %d", length)
            return true
        else
            -- length = utils.unpack_big_endian(backenddata, offset, 4)
            -- loger.add_info_log("other tag(0x%x) length: %d", tag, length)
        end

        offset = offset + length

        ::continue::
    end

    return false
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

        local meta = utils.get_metadata(client_sock)
        if meta.clientMsgType == pgsql_const_data.PGSQL_CLIENT_CMD_PASSWORD then
            deal_login_fail_message(client_sock, backenddata)
        elseif meta.clientMsgType == pgsql_const_data.PGSQL_CLIENT_CMD_QUERY then
            local is_record_audit_log = parse_downstream_data(meta, backenddata)
            if is_record_audit_log == true then
                record_pgsql_audit_log(meta)
            end
        else
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