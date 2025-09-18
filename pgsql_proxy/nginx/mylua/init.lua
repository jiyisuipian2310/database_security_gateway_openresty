--global var
local cjson = require "cjson.safe"  -- 使用安全模式

local _M = {}

local ngx = ngx
globalCfg = {}

function _M.get_global_cfg(cfgpath)
    local file, err = io.open(cfgpath, "rb")
    if not file then
        error( string.format("Failed to open file: %s", err));
    end

    local content = file:read("*a")
    if not content then
        error("File ".. cfgpath.. " is empty");
    end

    file:close()

    -- 解析 JSON
    local data, err = cjson.decode(content)
    if not data then
        error( string.format("Failed to decode JSON: %s", err));
    end

    globalCfg = data
end

return _M



