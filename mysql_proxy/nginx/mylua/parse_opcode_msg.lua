local ngx = ngx
local string = string
local cjson = require "cjson.safe"
local redis = require "resty.redis"
local utils = require "utils"

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

        ngx.log(ngx.INFO, "Unlock Account Success, loginUuid: ", loginUuid)
    else
        ngx.log(ngx.WARN, "Unlock Account Failed, loginUuid: ", loginUuid, " not exists in redis")
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

        ngx.log(ngx.INFO, "Lock Account Success, loginUuid: ", loginUuid)
    else
        ngx.log(ngx.WARN, "Lock Account Failed, loginUuid: ", loginUuid, " not exists in redis")
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
                ngx.log(ngx.ERR, "Failed to set data: ", err, ", configData:", msg)
                goto continue
            else
               ngx.log(ngx.INFO, "Successed Add configData [", msg, "]")
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
            -- local msg = string.format("vpPort: %s, targetIp: %s, targetPort: %s", item.vpPort, item.targetIp, item.targetPort)

            local dbuniqueID = item.targetIp.."#"..item.targetPort.."#"..item.vpPort
            local res, err = red:del(dbuniqueID)
            if not res then
                ngx.log(ngx.ERR, "Failed to Delete Item: ", err, ", dbuniqueID:", dbuniqueID)
                goto continue
            else
               ngx.log(ngx.INFO, "Delete Item Success , dbuniqueID:", dbuniqueID)
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
                ngx.log(ngx.ERR, "Failed to set data: ", err, ", configData:", msg)
                goto continue
            else
               ngx.log(ngx.INFO, "Successed Update configData [", msg, "]")
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
    ngx.log(ngx.INFO, "dbConfigInfo: ", responseMsg)

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
        ngx.log(ngx.INFO, "the opcode is not supported, opcode: ", json_table.opcode)
        return nil
    end
end

return _M