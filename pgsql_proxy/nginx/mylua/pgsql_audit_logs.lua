local ngx = ngx

local _M = {}

local pgsql_audit_log = ngx.shared.pgsql_audit_log
local auditLogPath = globalCfg.auditLogPath

function _M.save_pgsql_audit_log(operateJson)
    local success, err, forcible = pgsql_audit_log:lpush("pgsql_audit_log_queue", operateJson)
    if not success then
        ngx.log(ngx.ERR, "Failed to push operateJson: ", err)
        return false, err
    end
	
    return true
end

local function process_pgsql_audit_logs(premature)
    if premature then
        return
    end

    local batch_size = 5000
    local processed_count = 0
    
    local local_time = ngx.localtime()
    local yyyymmddhhmmss = local_time:gsub("[- :]", "")
    local pgsql_audit_log_file = auditLogPath .."/pgsql_audit_" ..yyyymmddhhmmss.. ".json"

    local list_length = pgsql_audit_log:llen("pgsql_audit_log_queue")
    local file, err = nil, nil
    if list_length > 0 then
        file, err = io.open(pgsql_audit_log_file, "w")
        if not file then
            ngx.log(ngx.ERR, "failed to open file: ", err, ", file: ", pgsql_audit_log_file)
            return
        end
    end

    while processed_count < batch_size do
        local json_str = pgsql_audit_log:rpop("pgsql_audit_log_queue")
        if not json_str then
            break
        end
		
        file:write(json_str.."\n")
        
        processed_count = processed_count + 1
    end

    if file ~= nil then
        file:close()
    end
end

function _M.init()
    local ok, err =  ngx.timer.every(5, process_pgsql_audit_logs)
    if not ok then
        ngx.log(ngx.ERR, "Failed to create initial timer: ", err)
        return false, err
    end
    return true
end

return _M