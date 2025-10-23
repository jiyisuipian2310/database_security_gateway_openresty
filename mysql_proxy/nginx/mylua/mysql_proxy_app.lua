local ngx = ngx
local spawn = ngx.thread.spawn
local wait = ngx.thread.wait
local string = string

local lrucache = require "resty.lrucache"
local address_cache = lrucache.new(4000)

local mysql_const_data = require "mysql_const_data"

local utils = require "utils"
local loger = require "mysql_proxy_timer_logs"
local client_proxy = require "mysql_proxy_client_message"
local server_proxy = require "mysql_proxy_server_message"

local _M = {}

-- 主处理函数
function _M.run()
    local targetIp, targetPort = nil, nil

    local address_key = string.format("mysql_%d", ngx.var.server_port)
    local addressTable = address_cache:get(address_key)
    if addressTable == nil then
        local red = utils.get_redis("apprun", 14)
        if red == nil then
            loger.add_error_log("address_key(%s) not in redis and get_redis failed", address_key)
            return
        end

        local exists, _ = red:exists(address_key)
        if exists ~= 1 then
            loger.add_error_log("address_key(%s) not in redis and not in lrucache", address_key)
            return
        end

        targetIp = red:hget(address_key, "targetIp")
        targetPort = red:hget(address_key, "targetPort")

        address_cache:set(address_key, {targetIp=targetIp, targetPort=targetPort})

        red:set_keepalive(30000, 200) -- 将连接放回连接池
    else
        targetIp = addressTable.targetIp
        targetPort = addressTable.targetPort
    end

    local client_sock = ngx.req.socket(true)
    local backend_sock, err = ngx.socket.tcp()
    if not backend_sock then
        loger.add_error_log(string.format("Failed to create backend socket: %s", err))
        return
    end

    -- 连接到真实 mysql 服务器
    local ok, err = backend_sock:connect(targetIp, targetPort)
    if not ok then
        local err_msg = string.format("Failed to connect to %s:%s, Reason:%s", targetIp, targetPort, err)
        loger.add_info_log(err_msg)
        return
    end

    local routeInfo = string.format("%s:%s -> 0.0.0.0:%s -> %s:%s", ngx.var.remote_addr, ngx.var.remote_port, ngx.var.server_port, targetIp, targetPort)

    -- 连接数+1
    local dbuniqueID = targetIp.."#"..targetPort.."#"..ngx.var.server_port
    utils.attach_metadata(client_sock, { dbuniqueID = dbuniqueID })
    utils.attach_metadata(client_sock, { sourceIp = ngx.var.remote_addr, sourcePort = ngx.var.remote_port})
    utils.attach_metadata(client_sock, { targetIp = targetIp, targetPort = targetPort, vpPort = ngx.var.server_port })
    utils.attach_metadata(client_sock, { routeInfo = routeInfo}  )

    utils.attach_metadata(client_sock, {client_session_status = mysql_const_data.SESSION_STATE_CLIENT_LOGIN_REQUEST})
    utils.attach_metadata(backend_sock, {server_session_status = mysql_const_data.SESSION_STATE_SERVER_GREET})

    local new_val, _ = utils.increment_counter(dbuniqueID, 1)
    loger.add_info_log("This is new connection, %s, CurrentTotalConnectCount: %d", routeInfo, new_val)

    -- 设置超时
    client_sock:settimeout(3600000)
    backend_sock:settimeout(3600000)
	
	-- 创建两个协程分别处理双向数据流
    local threads = {
        spawn(client_proxy.forward_data_to_server, client_sock, backend_sock),
        spawn(server_proxy.forward_data_to_client, backend_sock, client_sock)
    }

    -- 等待任意一个协程完成
    local ok, err = wait(threads[1], threads[2])
    if not ok then
        loger.add_error_log("proxy error: ", err)
    end

    loger.add_debug_log("proxy done, threads[1] status: %s", coroutine.status(threads[1]))
    loger.add_debug_log("proxy done, threads[2] status: %s", coroutine.status(threads[2]))

    if coroutine.status(threads[1]) ~= "dead" then
        ngx.thread.kill(threads[1])
    end

    if coroutine.status(threads[2]) ~= "dead" then
        ngx.thread.kill(threads[2])
    end

    -- 连接数-1
    local new_val, _ =utils.decrement_counter(dbuniqueID, 1)
    loger.add_info_log("This is close connection, %s, CurrentTotalConnectCount: %d", routeInfo, new_val)

    -- 清理连接
    backend_sock:close()
end

return _M