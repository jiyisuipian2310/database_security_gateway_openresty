local ngx = ngx
local utils = require "utils"
local cjson = require "cjson.safe"
local auditlogs = require "pgsql_audit_logs"
local applogs = require "pgsql_proxy_timer_logs"

local _M = {}

--定时器函数
local get_db_address_info = function (premature, arg)
	if premature then
		return
	end

    local requestTable = { targetType = globalCfg.pgsql.targetType, proxyIp = globalCfg.localAddressIp}
    local requestData = cjson.encode(requestTable)

    applogs.add_info_log("init_worker requestUrl: %s,  requestData: %s",  globalCfg.getdbAddressUrl, requestData)
    local json_str, err = utils.send_http_request(globalCfg.getdbAddressUrl, requestData)
    if json_str == nil then
        applogs.add_error_log("get pgsql address failed, err: %s",  err.Error())
        return
    end

    applogs.add_info_log("get pgsql address, json_str:  %s", json_str)
    local json_table, err = cjson.decode(json_str)
    if not json_table then
        applogs.add_error_log("parse pgsql address failed: ",  err.Error())
        return
    end

    local red = utils.get_redis("get_db_address_info", 14)
    if red == nil then return end
    
    for key, item in pairs(json_table) do
        if type(item) == "table" then
            local info = string.format("targetType[%s], vpPort[%s], targetAddr[%s:%d]", item.targetType, item.vpPort, item.targetIp, item.targetPort)
            applogs.add_info_log("dbitem: %s", info)
            local item_targetType = ""
            if(type(item.targetType) == "number") then
                item_targetType = tostring(item.targetType)
            else
                item_targetType = item.targetType
            end

            if item_targetType ~= globalCfg.pgsql.targetType then
                local errmsg = string.format("targetType not match pgsql targetType(%d), skip, item: %s", globalCfg.pgsql.targetType, info)
                applogs.add_warn_log(errmsg)
                goto continue
            end
            -- 存入 redis 数据库中
            red:hmset("pgsql_" .. item.vpPort,
                "targetIp", item.targetIp,
                "targetPort", item.targetPort
            )
        end
        ::continue::
    end
    red:set_keepalive(30000, 200) -- 将连接放回连接池
end

function _M.init_worker()
    if ngx.worker.id() == 0 then
        ngx.timer.at(0, get_db_address_info, arg)
        auditlogs.init()
        applogs.init()
    end
end

return _M