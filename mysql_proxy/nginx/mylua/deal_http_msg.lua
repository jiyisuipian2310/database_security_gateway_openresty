local ngx = ngx
local socket = ngx.socket.tcp
local cjson = require "cjson.safe"

local _M = {}

-- 辅助函数处理错误情况
local function handle_error(sock, err_msg)
    if sock then
        sock:close()
    end
    ngx.status = ngx.HTTP_BAD_REQUEST
    ngx.header.content_type = "application/json"
    ngx.say(err_msg)
    return ngx.exit(ngx.HTTP_BAD_REQUEST)
end

function _M.forward_http_msg(opcode, is_read_body)
	local new_json_str
	if not is_read_body then
    	local empty_table = {}
		empty_table.opcode = opcode
		new_json_str = cjson.encode(empty_table)
	else
		ngx.req.read_body()
	    local body_data = ngx.req.get_body_data()
		if not body_data or body_data == "" then
			handle_error(nil, '{"error": "Read bodyData Failed"}')
		end
		
		local json_table, err = cjson.decode(body_data)
		if not json_table then
			handle_error(nil, '{"error": "Invalid JSON format", "detail": "'.. (err or "") ..'"}')
		end
		json_table.opcode = opcode
		new_json_str = cjson.encode(json_table)
	end

	ngx.say("OK")
	
	local sock = socket()
	local ok, err = sock:connect("127.0.0.1", 2346)  -- stream 模块监听的端口
	if not ok then
		ngx.say("failed to connect to stream: ", err)
		return
	end

	sock:send(new_json_str)
	sock:close()
end

function _M.send_and_recv_msg(opcode)
	ngx.req.read_body()
	local body_data = ngx.req.get_body_data()
	if not body_data or body_data == "" then
		return handle_error(nil, '{"error": "Read bodyData Failed"}')
	end

	local json_table, _ = cjson.decode(body_data)
	if not json_table then
		return handle_error(nil, '{"error": "Invalid JSON format"}')
	end

	local sock = ngx.socket.tcp()
	sock:settimeouts(1000, 2000, 3000)  -- 连接超时1s，发送超时2s，接收超时3s
	local ok, _ = sock:connect("127.0.0.1", 2345)  -- stream 模块监听的端口
	if not ok then
		return handle_error(sock, '{"error": "connect 127.0.0.1:2345 failed"}')
	end

	json_table.opcode = opcode
	local new_json_str = cjson.encode(json_table)

	-- 发送客户端请求数据到 stream
	local bytes, _ = sock:send(new_json_str)
	if not bytes then
		return handle_error(sock, '{"error": "send data to 127.0.0.1:2345 failed"}')
	end

	-- 接收 stream 的响应
	local clientdata, err = sock:receiveany(8192)  -- 非阻塞读取
	if not clientdata then
		local err_msg = '{"error": "recv data from 127.0.0.1:2345 failed", "detail": "'.. (err or "") ..'"}'
		return handle_error(sock, err_msg)
	end

	-- 将 stream 的响应返回给客户端
	ngx.header.content_type = "application/json"
	ngx.say(clientdata)
	sock:close()
	return ngx.exit(ngx.HTTP_OK)
end

return _M
