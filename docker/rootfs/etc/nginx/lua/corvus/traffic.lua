-- NPM Sentinel: per-host request counters for the automatic "under attack" mode.
--
-- The log phase of every proxy host (corvus/hostlog.lua) counts requests, and requests
-- Sentinel refused (block rules, exploit and body blocking, bans: ngx.ctx.corvus_blocked
-- set by corvus/rules.lua deny), in 10-second buckets of the shared dict corvus_traffic.
-- The backend reads the sums over a window from the loopback status port (GET /traffic)
-- and decides when to activate the mode (backend/internal/sentinel-underattack.js),
-- which replaces Corvus' access-log based traffic collector.

local floor, tonumber, tostring = math.floor, tonumber, tostring
local find, sub = string.find, string.sub

local _M = {}

_M.BUCKET = 10                 -- seconds per bucket
_M.KEEP = 62                   -- buckets kept (a little over the 600 s maximum window)

local function bucket(now)
  return floor(now / _M.BUCKET)
end

-- log_by_lua of a proxy host: key is the proxy host id.
function _M.count(key)
  local d = ngx.shared.corvus_traffic
  if not d or key == nil or key == "" then return end
  local suffix = tostring(key) .. ":" .. bucket(ngx.time())
  local ttl = _M.KEEP * _M.BUCKET
  d:incr("r:" .. suffix, 1, 0, ttl)
  if ngx.ctx.corvus_blocked then d:incr("b:" .. suffix, 1, 0, ttl) end
end

-- Sums per host over the last `window` seconds: { ["<host>"] = { r, b, secs } }. Whole
-- buckets are summed, from the one holding now - window to the current one, and secs is
-- the time those buckets actually cover (from the start of the oldest one seen to now),
-- so the rate stays right whether the window starts mid-bucket or the counters are
-- still filling up after an nginx restart.
function _M.window(window, now)
  local d = ngx.shared.corvus_traffic
  local out = {}
  if not d then return out end
  now = now or ngx.time()
  local cur = bucket(now)
  local first = bucket(now - window)
  local oldest = {}
  for _, k in ipairs(d:get_keys(0)) do
    local kind = sub(k, 1, 2)
    if kind == "r:" or kind == "b:" then
      local c = find(k, ":", 3, true)
      local host = c and sub(k, 3, c - 1)
      local b = c and tonumber(sub(k, c + 1))
      if host and b and b >= first and b <= cur then
        local v = tonumber(d:get(k)) or 0
        local h = out[host]
        if not h then
          h = { r = 0, b = 0 }
          out[host] = h
        end
        if kind == "r:" then h.r = h.r + v else h.b = h.b + v end
        if not oldest[host] or b < oldest[host] then oldest[host] = b end
      end
    end
  end
  for host, h in pairs(out) do
    -- from the start of the oldest bucket seen to now
    h.secs = now - oldest[host] * _M.BUCKET + 1
  end
  return out
end

-- Status port: GET /traffic?window=<seconds> → {"<host>": {"r": n, "b": n, "secs": n}}
function _M.serve()
  local rules = require "corvus.rules"
  if not rules.status_key_ok() then return end
  local w = tonumber(ngx.var.arg_window) or 30
  if w < _M.BUCKET then w = _M.BUCKET elseif w > 600 then w = 600 end
  local cjson = require "cjson.safe"
  ngx.header["Content-Type"] = "application/json"
  local out = _M.window(w)
  ngx.say(next(out) and cjson.encode(out) or "{}")
end

return _M
