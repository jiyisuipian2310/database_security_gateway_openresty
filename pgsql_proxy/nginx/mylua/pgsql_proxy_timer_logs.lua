local ngx = ngx

local _M = {}

-- debug, info, warn, error
local log_level = globalCfg.pgsql.log_level
local pgsql_shared_data = ngx.shared.pgsql_proxy_app_logs
local last_date = string.sub(ngx.localtime(), 1, 10):gsub("[-]", "")
local full_log_name = globalCfg.pgsql.app_log_path .."/pgsql_program_" ..last_date.. ".log"
local justStart = true

local function format_message(fmt, ...)
    local count = select('#', ...)
    local args = {...}
    return (fmt:gsub("%%([tsdfxX])", function(spec)
        if count == 0 then return "" end
        local arg = table.remove(args, 1)
        count = count - 1

        if arg == nil then return "nil" end

        if spec == "t" then  -- 布尔值
            return tostring(not not arg)  -- 强制转换为布尔字符串
        elseif spec == "d" then  -- 整数
            return string.format("%d", tonumber(arg) or 0)
        elseif spec == "f" then  -- 浮点数
            return string.format("%.2f", tonumber(arg) or 0)
        elseif spec == "s" then  -- 字符串
            return tostring(arg)
        elseif spec == "x" then  -- 小写16进制
            return string.format("%x", tonumber(arg) or 0)
        elseif spec == "X" then  -- 大写16进制
            return string.format("%X", tonumber(arg) or 0)
        end
    end))
end

local function add_log(level, fmt, ...)
    local applog = string.format("[%s][%s][%s]: %s", ngx.localtime(), level, ngx.worker.pid(),  format_message(fmt,...))
    local success, err, forcible = pgsql_shared_data:lpush("pgsql_app_log_queue", applog)
    if not success then
        ngx.log(ngx.ERR, "Failed to push operateJson: ", err)
        return false, err
    end
	
    return true
end

--log_level: debug > info > warn > error

function _M.add_debug_log(fmt, ...)
    if log_level == "debug" then
        return add_log("Debug", fmt, ...)
    end
end

function _M.add_info_log(fmt, ...)
    if log_level == "debug" or log_level == "info" then
        return add_log("Info ", fmt, ...)
    end
end

function _M.add_warn_log(fmt, ...)
    if log_level == "debug" or log_level == "info" or log_level == "warn" then
        return add_log("Warn ", fmt, ...)
    end
end

function _M.add_error_log(fmt, ...)
    if log_level == "debug" or log_level == "info" or log_level == "warn" or log_level == "error" then
        return add_log("Error", fmt, ...)
    end
end

local function process_pgsql_app_logs(premature)
    if premature then
        return
    end

    local now_date = string.sub(ngx.localtime(), 1, 10):gsub("[-]", "")
    if now_date ~= last_date then
        last_date = now_date
        full_log_name = globalCfg.pgsql.app_log_path .."/pgsql_program_" ..last_date.. ".log"
    end

    -- 以追加模式打开文件
    local file, err = io.open(full_log_name, "a+")
    if not file then
        ngx.log(ngx.ERR, "failed to open file: ", err, ", file: ", full_log_name)
        return
    end

    if justStart == true then
        justStart = false
        local applog = string.format("[%s][Info ][%s]: pgsql_proxy begin running", ngx.localtime(), ngx.worker.pid())
        file:write(applog.."\n")
    end

    local batch_size = 5000
    local processed_count = 0
    
    while processed_count < batch_size do
        local currentlog = pgsql_shared_data:rpop("pgsql_app_log_queue")
        if not currentlog then
            break
        end

        file:write(currentlog.."\n")
        processed_count = processed_count + 1
    end

    if file ~= nil then
        file:close()
    end
    
    local ok, err = ngx.timer.at(1, process_pgsql_app_logs)
    if not ok then
        ngx.log(ngx.ERR, "Failed to create timer: ", err)
    end
end

function _M.init()
    local ok, err = ngx.timer.at(0, process_pgsql_app_logs)
    if not ok then
        ngx.log(ngx.ERR, "Failed to create process_pgsql_app_logs timer: ", err)
        return false, err
    end
    return true
end

return _M