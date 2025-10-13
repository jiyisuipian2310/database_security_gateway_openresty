local ngx = ngx
local string = string
local cjson = require "cjson.safe"
local redis = require "resty.redis"
local utils = require "utils"
local loger = require "mysql_proxy_timer_logs"

local _M = {}

local function deal_unlock_account_msg(json_table)
    local red = utils.get_redis("deal_unlock_account_msg")
    if red == nil then return nil end

    if json_table.targetType ~= "13" then
        red:set_keepalive(30000, 200) -- 将连接放回连接池
        return nil
    end

    local loginUuid = "mysql#" .. json_table.targetIp.."#"..json_table.targetPort.."#"..json_table.vpPort.."#"..json_table.account
    local exists, _ = red:exists(loginUuid)
    if exists == 1 then
        local lock, _ = utils.Lock(loginUuid, "deal_unlock_account_msg")
        if lock == nil then
            red:set_keepalive(30000, 200) -- 将连接放回连接池
            return nil
        end
        red:hset(loginUuid, "CurrentLoginFailedCount", 0)
        lock:unlock()

        loger.add_info_log("Unlock Account Success, loginUuid: %s", loginUuid)
    else
        loger.add_warn_log("Unlock Account Failed, loginUuid: %s not exists in redis", loginUuid)
    end

    red:set_keepalive(30000, 200) -- 将连接放回连接池
    return nil
end

local function deal_lock_account_msg(json_table)
    local red = utils.get_redis("deal_lock_account_msg")
    if red == nil then return nil end

    if json_table.targetType ~= "13" then
        red:set_keepalive(30000, 200) -- 将连接放回连接池
        return nil
    end

    local loginUuid = "mysql#" .. json_table.targetIp.."#"..json_table.targetPort.."#"..json_table.vpPort.."#"..json_table.account
    local exists, _ = red:exists(loginUuid)
    if exists == 1 then
        local lock, _ = utils.Lock(loginUuid, "deal_lock_account_msg")
        if lock == nil then
            red:set_keepalive(30000, 200) -- 将连接放回连接池
            return nil
        end
        red:hset(loginUuid, "CurrentLoginFailedCount", 99999)
        lock:unlock()

        loger.add_info_log("Lock Account Success, loginUuid: %s", loginUuid)
    else
        loger.add_warn_log("Lock Account Failed, loginUuid: %s not exists in redis", loginUuid)
    end

    red:set_keepalive(30000, 200) -- 将连接放回连接池
    return nil
end

local function deal_add_db_control_policy_msg(json_table)
    local red = utils.get_redis("deal_add_db_control_policy_msg")
    if red == nil then return nil end

    for key, item in pairs(json_table) do
        if type(item) == "table" then
            local msg = string.format("targetType: %s, vpPort: %s, targetAddr: %s:%s, MaxLoginFailedLimit: %s, MaxConnectLimit: %s",item.targetType, item.vpPort, item.targetIp, item.targetPort, item.loginFailNum, item.maxConnections)

            local dbuniqueID = item.targetIp.."#"..item.targetPort.."#"..item.vpPort
            local res, err = red:hmset(dbuniqueID,
                "TargetDBType", item.targetType,
                "MaxLoginFailedLimit", item.loginFailNum,
                "MaxConnectLimit", item.maxConnections
            )

            if not res then
                loger.add_warn_log("Add configData Failed: %s, reason: ", msg, err)
                goto continue
            else
               loger.add_info_log("Add configData Success: %s", msg)
            end
        end
        ::continue::
    end

    -- 将连接放回连接池
    red:set_keepalive(30000, 200)
    return nil
end

local function deal_delete_db_control_policy_msg(json_table) 
    local red = utils.get_redis("deal_delete_db_control_policy_msg")
    if red == nil then return nil end

    for key, item in pairs(json_table) do
        if type(item) == "table" then
            local msg = string.format("vpPort: %s, targetIp: %s, targetPort: %s", item.vpPort, item.targetIp, item.targetPort)

            local dbuniqueID = item.targetIp.."#"..item.targetPort.."#"..item.vpPort
            local res, err = red:del(dbuniqueID)
            if not res then
                loger.add_warn_log("Delete configData Failed: %s, dbuniqueID: %s, reason: %s", msg, dbuniqueID, err)
                goto continue
            else
               loger.add_info_log("Delete configData Success: %s, dbuniqueID: %s", msg, dbuniqueID)
            end
        end
        ::continue::
    end

    -- 将连接放回连接池
    red:set_keepalive(30000, 200)
    return nil
end

local function deal_update_db_control_policy_msg(json_table)
    local red = utils.get_redis("deal_update_db_control_policy_msg")
    if red == nil then return nil end

    for key, item in pairs(json_table) do
        if type(item) == "table" then
            local msg = string.format("targetType: %s, vpPort: %s, targetAddr: %s:%s, MaxLoginFailedLimit: %s, MaxConnectLimit: %s",item.targetType, item.vpPort, item.targetIp, item.targetPort, item.loginFailNum, item.maxConnections)

            local dbuniqueID = item.targetIp.."#"..item.targetPort.."#"..item.vpPort
            local res, err = red:hmset(dbuniqueID,
                "TargetDBType", item.targetType,
                "MaxLoginFailedLimit", item.loginFailNum,
                "MaxConnectLimit", item.maxConnections
            )

            if not res then
                loger.add_warn_log("Update configData Failed: %s, dbuniqueID: %s, reason: %s", msg, dbuniqueID, err)
                goto continue
            else
               loger.add_info_log("Update configData Success: %s, dbuniqueID: %s", msg, dbuniqueID)
            end
        end
        ::continue::
    end

    -- 将连接放回连接池
    red:set_keepalive(30000, 200)
    return nil
end

local function deal_get_db_current_config_info_msg(sock, json_table)
    local dbuniqueID = json_table.dbuid
    local red, err = utils.get_redis("deal_get_db_current_config_info_msg")
    if red == nil then
        sock:send(string.format("dbuniqueID: %s, Connect redis failed, err: %s", dbuniqueID, err))
        return nil
    end

    local connLimit, _ = red:hget(dbuniqueID, "MaxConnectLimit")
    local loginFailedLimit, _ = red:hget(dbuniqueID, "MaxLoginFailedLimit")
    local responseTable = {
        dbUniqueID = dbuniqueID,
        currentConnectNumber = utils.get_counter(dbuniqueID),
        MaxConnectLimit = connLimit,
        MaxLoginFailedLimit = loginFailedLimit
    }

    red:set_keepalive(30000, 200)

    local responseMsg = cjson.encode(responseTable)
    loger.add_info_log("dbConfigInfo: %s", responseMsg)

	sock:send(responseMsg)
    return nil
end

function _M.parse_opcode_msg(sock, msg)
    ngx.log(ngx.INFO, "Body: ", msg)

    local json_table, err = cjson.decode(msg)
    if json_table.opcode == "unlock_account" then
        return deal_unlock_account_msg(json_table)
    elseif json_table.opcode == "lock_account" then
        return deal_lock_account_msg(json_table)
    elseif json_table.opcode == "add_db_control_policy" then
       return deal_add_db_control_policy_msg(json_table)
    elseif json_table.opcode == "delete_db_control_policy" then
        return deal_delete_db_control_policy_msg(json_table)
    elseif json_table.opcode == "update_db_control_policy" then
        return deal_update_db_control_policy_msg(json_table)
    elseif json_table.opcode == "get_db_current_config_info" then
        return deal_get_db_current_config_info_msg(sock, json_table)
    else
        loger.add_error_log("The opcode is not supported, opcode: : %s", json_table.opcode)
        return nil
    end
end

return _M