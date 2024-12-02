local uv = require('uv')

local M_NOAUTH = '\0'
local M_USERNAMEPASSWORD = '\2'
local DEFAULT_RSV_BND_IPV4 = '\0\1\0\0\0\0\0\0'

local HOST = '127.0.0.1'
local PORT = 1080

--- working auth types:
--- M_NOAUTH - no auth
--- M_USERNAMEPASSWORD - username/password
local AUTH_TYPE = M_NOAUTH
--- only for username/password auth
local AUTH_USERNAME = 'test'
local AUTH_PASSWORD = 'test2'

local function safeCall(fn, ...)
    local a = {...}
    coroutine.wrap(function ()
        local b, c = xpcall(fn, debug.traceback, unpack(a))
        if not b then
            print(c)
        end
    end)()
end

local function stringReader(str)
    local offset = 0
    return function(n)
        if not n then return str:sub(offset + 1) end
        local chunk = str:sub(offset + 1, offset + n)
        offset = offset + n
        return chunk
    end
end

local function closeSocket(socket)
    socket:read_stop()
    if not socket:is_closing() then
        socket:close()
    end
end

local function authProcedure(reader, socket)
    reader(1)
    local nmethods = reader(1):byte()
    local methods = reader(nmethods)
    if methods:find(AUTH_TYPE) then
        socket:write('\5' .. AUTH_TYPE)
        p('selected auth', AUTH_TYPE)
        return (AUTH_TYPE == M_NOAUTH and 2 or 1)
    end
    p('invalid auth methods', methods)
    socket:write('\5\255')
    closeSocket(socket)
end

local function userpassAuthProcedure(reader, socket)
    reader(1)
    local ulen = reader(1):byte()
    local username = reader(ulen)
    local plen = reader(1):byte()
    local password = reader(plen)
    if username ~= AUTH_USERNAME or password ~= AUTH_PASSWORD then
        p('auth fail')
        socket:write('\1\1')
        closeSocket(socket)
        return
    end
    p('auth ok')
    socket:write('\1\0')
    return 2
end

local function cmd_connect(reader, socket)
    local addr, port
    local atyp = reader(1)
    p('atyp', atyp)
    if atyp == '\1' then
        p('selected ipv4')
        addr = table.concat({reader(1):byte(), reader(1):byte(), reader(1):byte(), reader(1):byte()}, '.')
    elseif atyp == '\3' then
        p('selected domain')
        local dlen = reader(1):byte()
        local domain = reader(dlen)

        p('domain', dlen, domain)
        addr = uv.getaddrinfo(domain, nil, {
            socktype = 'stream',
            family = 'inet'
        })

        if not addr then
            p('domain fail')
            socket:write('\5\3' .. DEFAULT_RSV_BND_IPV4)
            closeSocket(socket)
            return
        end
        p('domain addr', addr)

        addr = addr[1].addr
    elseif atyp == '\4' then
        socket:write('\5\8' .. DEFAULT_RSV_BND_IPV4)
        closeSocket(socket)
        return
    end

    port = string.unpack('>H', reader(2))

    p('addr', addr, 'port', port)

    local remote = uv.new_tcp()
    local function close()
        closeSocket(remote)
        closeSocket(socket)

        p('closed all sockets')
    end

    p('connecting to remote')
    remote:connect(addr, port, function (err)
        if err then
            p('connect fail', err)
            socket:write('\5\5' .. DEFAULT_RSV_BND_IPV4)
            close()
            return
        end

        socket:read_stop()

        socket:write('\5\0' .. DEFAULT_RSV_BND_IPV4)

        if not socket:read_start(function (err, data)
            if err then
                close()
                return
            end

            if data then
                remote:write(data, function (err)
                    if err then
                        close()
                    end
                end)
            else
                close()
            end
        end) then
            p('client socket read_start fail')
            close()
        end

        if not remote:read_start(function (err, data)
            if err then
                close()
                return
            end

            if data then
                socket:write(data, function (err)
                    if err then
                        close()
                    end
                end)
            else
                close()
            end
        end) then
            p('remote socket read_start fail')
            close()
        end
    end)
end

local function connectProcedure(reader, socket)
    reader(1)
    local cmd = reader(1)
    reader(1)
    if cmd == '\1' then
        cmd_connect(reader, socket)
    else
        socket:write('\5\7' .. DEFAULT_RSV_BND_IPV4)
        closeSocket(socket)
    end
end

--- states:
--- 0 - auth
--- 1 - userpass auth
--- 2 - connect
local function handleSocket(socket)
    --- @cast socket uv_tcp_t
    local state = 0
    p('new client', socket)
    assert(socket:read_start(function (err, data)
        if err or not data or not state then closeSocket(socket) return end
        local reader = stringReader(data)
        if state == 0 then
            p('authProcedure')
            safeCall(function ()
                state = authProcedure(reader, socket)
            end)
        elseif state == 1 then
            p('userpassAuthProcedure')
            safeCall(function ()
                state = userpassAuthProcedure(reader, socket)
            end)
        elseif state == 2 then
            p('connectProcedure')
            safeCall(connectProcedure, reader, socket)
        end
    end))
end

local server = uv.new_tcp()
assert(server:bind(HOST, PORT))
assert(server:listen(128, function (err)
    if err then error(err) end
    local socket = uv.new_tcp()
    server:accept(socket)
    safeCall(handleSocket, socket)
end))