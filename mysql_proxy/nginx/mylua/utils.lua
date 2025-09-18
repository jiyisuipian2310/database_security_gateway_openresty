local ngx = ngx
local resty_lock = require "resty.lock"
local db_connect_number = ngx.shared.current_db_connect_number
local redis = require "resty.redis"
local http = require "resty.http"

local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_string = ffi.string
local C = ffi.C

local p_errmsg = ffi_new("char*[1]")
local aes_crypto_key = "63dTjxISXlwAso0n"

-- 定义C函数原型
ffi.cdef[[
int aes_encrypt(const char* szInput, int input_len, const char* szKey, int key_len, char** pOutput, char** szErrMsg);
int aes_decrypt(const char* szInput, int input_len, const char* szKey, int key_len, char** pOutput, char** szErrMsg);
void free(void *ptr);
]]

-- 加载动态库
local lib_path = "libaescrypto.so"
local aes_lib = ffi.load(lib_path)

local _M = {}

-- 为 socket 附加元数据：
function _M.attach_metadata(sock, metadata)
    local mt = getmetatable(sock) or {}
    mt.__metadata = mt.__metadata or {}
    for k, v in pairs(metadata) do
        mt.__metadata[k] = v
    end
    setmetatable(sock, mt)
    return sock
end

-- 获取元数据
function _M.get_metadata(sock)
    local mt = getmetatable(sock)
    return mt and mt.__metadata
end

function _M.int_to_4bytes(num, big_endian)
    if big_endian then
        return string.char(
            math.floor(num / 16777216) % 256,  -- 字节1 (最高位)
            math.floor(num / 65536) % 256,      -- 字节2
            math.floor(num / 256) % 256,        -- 字节3
            num % 256                           -- 字节4 (最低位)
        )
    else
        return string.char(
            num % 256,
            math.floor(num / 256) % 256,
            math.floor(num / 65536) % 256,
            math.floor(num / 16777216) % 256
        )
    end
end

function _M.int_to_3bytes(num, big_endian)
    if big_endian then
        -- 大端序 (高位在前)
        return string.char(
            math.floor(num / 65536) % 256,  -- 字节1 (最高位)
            math.floor(num / 256) % 256,    -- 字节2
            num % 256                       -- 字节3 (最低位)
        )
    else
        -- 小端序 (低位在前)
        return string.char(
            num % 256,                      -- 字节1 (最低位)
            math.floor(num / 256) % 256,    -- 字节2
            math.floor(num / 65536) % 256   -- 字节3 (最高位)
        )
    end
end

function _M.unpack_big_endian(data, beginpos, length)
    if length <= 0 then return 0 end

    if beginpos + length - 1 > #data then return 0 end
    
    if length == 2 then
        local b1, b2 = data:byte(beginpos, beginpos+length)
        return b1 * 0x100 + b2
    end

    if length == 3 then
        local b1, b2, b3 = data:byte(beginpos, beginpos+length)
        return b1 * 0x10000 + b2 * 0x100 + b3
    end

    if length == 4 then
        local b1, b2, b3, b4 = data:byte(beginpos, beginpos+length)
        return b1 * 0x1000000 + b2 * 0x10000 + b3 * 0x100 + b4
    end

    return 0
end

function _M.unpack_little_endian(data, beginpos, length)
    if length <= 0 then return 0 end

    if beginpos + length - 1 > #data then return 0 end
    
    if length == 2 then
        local b1, b2 = data:byte(beginpos, beginpos + 1)
        return b2 * 0x100 + b1  -- 小端序：低位在前
    end

    if length == 3 then
        local b1, b2, b3 = data:byte(beginpos, beginpos + 2)
        return b3 * 0x10000 + b2 * 0x100 + b1  -- 小端序：低位在前
    end

    if length == 4 then
        local b1, b2, b3, b4 = data:byte(beginpos, beginpos + 3)
        return b4 * 0x1000000 + b3 * 0x10000 + b2 * 0x100 + b1  -- 小端序：低位在前
    end

    return 0
end

function _M.send_http_request(url, body, params)
    params = params or {}
    local timeout = params.timeout or {}

    local httpc = http.new()
    httpc:set_timeouts(
        timeout.connect or 1000,   -- 连接超时
        timeout.send or 1000,      -- 发送超时
        timeout.read or 1000     -- 读取超时
    )

    local res, err = nil, nil
    if string.sub(url, 1, 5) == "https" then
        res, err = httpc:request_uri(url, {method = "POST", body = body, ssl_verify = false})
    else
        res, err = httpc:request_uri(url, {method = "POST", body = body})
    end
    
    if not res then
        httpc:close()
        return nil, string.format("HTTP request failed: %s, url: %s", err, url)
    end

    if res.status ~= 200 then
        httpc:close()
        return nil, "HTTP request failed: " .. res.body
    end

    httpc:close()
    return res.body, nil
end

local function get_redis(label, dbno)
    local red = redis:new()
    red:set_timeouts(10000, 10000, 10000)
    local ok, err = red:connect(globalCfg.redisIp, globalCfg.redisPort)
    if not ok then
        local errmsg = string.format("label: %s, connect to redis(%s:%d) error: %s", label, globalCfg.redisIp, globalCfg.redisPort, err)
        ngx.log(ngx.ERR, errmsg)
        return nil, err
    end

    if dbno ~= nil and type(dbno) == "number" then
        if dbno >= 0 and dbno <= 15 then
            red:select(dbno)
        else
            red:select(0)
        end
    else
        red:select(0)
    end

    return red
end

function _M.Lock(key, label)
    local lock, err = resty_lock:new("locks")
    if not lock then
        ngx.log(ngx.ERR, "label: ", label, ", Failed to create lock: ", err)
        return nil, err
    end

    local elapsed, err = lock:lock(key)
    if not elapsed then
        ngx.log(ngx.ERR, "label: ", label, ", Failed to lock: ", err)
        return nil, err
    end

    return lock, nil
end

function _M.increment_counter(key, value)
    value = value or 1
    local new_val, err = db_connect_number:incr(key, value, 0)
    if not new_val then
        ngx.log(ngx.ERR, "failed to increment counter: ", err)
        return nil, err
    end
    return new_val, nil
end

function _M.decrement_counter(key, value)
    value = value or 1
    local new_val, err = db_connect_number:incr(key, -value)  -- 注意负号
    if not new_val then
        ngx.log(ngx.ERR, "failed to decrement counter: ", err)
        return nil, err
    end
    return new_val, nil
end

function _M.get_counter(key)
    local val, err = db_connect_number:get(key)
    if not val then
        return 0
    end
    return val
end

function _M.print_binary(data)
    if not data then return end
    local hex = {}
    for i = 1, #data do
        hex[i] = string.format("%02X ", data:byte(i))
    end
    
    return table.concat(hex)
end

local function free_str(ptr)
    if ptr ~= nil and ptr ~= ffi.NULL then C.free(ptr) end
end

-- AES加密函数
function _M.aes_encrypt(input)
    local input_len = #input
    local key_len = #aes_crypto_key
    local p_output = ffi_new("char*[1]")
    
    -- 调用C函数
    local ret = aes_lib.aes_encrypt(input, input_len, aes_crypto_key, key_len, p_output, p_errmsg)
    
    -- 处理结果
    if ret ~= 0 then
        local errmsg = p_errmsg[0] ~= ffi.NULL and ffi_string(p_errmsg[0]) or "unknown error"
        if p_errmsg[0] ~= ffi.NULL then
            free_str(p_errmsg[0])
        end
        return nil, errmsg
    end
    
    local output = p_output[0] ~= ffi.NULL and ffi_string(p_output[0]) or nil
    if p_output[0] ~= ffi.NULL then
        free_str(p_output[0])
    end
    
    return output
end

-- AES解密函数
function _M.aes_decrypt(input)
    local p_output = ffi_new("char*[1]")
    local input_len = #input
    local key_len = #aes_crypto_key
    
    -- 调用C函数
    local ret = aes_lib.aes_decrypt(input, input_len, aes_crypto_key, key_len, p_output, p_errmsg)
    
    -- 处理结果
    if ret ~= 0 then
        local errmsg = p_errmsg[0] ~= ffi.NULL and ffi_string(p_errmsg[0]) or "unknown error"
        if p_errmsg[0] ~= ffi.NULL then
            free_str(p_errmsg[0])
        end
        return nil, errmsg
    end

    local output = p_output[0] ~= ffi.NULL and ffi_string(p_output[0]) or nil
    if p_output[0] ~= ffi.NULL then
        free_str(p_output[0])
    end
    
    return output
end

function _M.get_login_failed_count(loginUuid)
    local red = get_redis("deal_login_fail_message")
    if red == nil then
        return nil, "redis connect failed"
    end

    local exists, _ = red:exists(loginUuid)
    if exists ~= 1 then
        red:set_keepalive(30000, 200) -- 将连接放回连接池
        return nil, string.format("loginUuid[%s] not exists in redis: %s", loginUuid)
    end

    local loginFailedCount, _ = red:hget(loginUuid, "CurrentLoginFailedCount")
    if loginFailedCount == nil then
        red:set_keepalive(30000, 200) -- 将连接放回连接池
        return nil, string.format("get CurrentLoginFailedCount failed by loginUuid[%s]", loginUuid)
    end

    red:set_keepalive(30000, 200) -- 将连接放回连接池
    return loginFailedCount, nil
end

function _M.set_login_failed_count(loginUuid, loginFailedCount)
    local red = get_redis("deal_login_fail_message")
    if red == nil then 
        return "redis connect failed"
    end

    local exists, _ = red:exists(loginUuid)
    if exists ~= 1 then
        red:set_keepalive(30000, 200) -- 将连接放回连接池
        return string.format("loginUuid[%s] not exists in redis: %s", loginUuid)
    end

    red:hset(loginUuid, "CurrentLoginFailedCount", loginFailedCount)
    red:set_keepalive(30000, 200) -- 将连接放回连接池
    return nil
end

_M.get_redis = get_redis
return _M

