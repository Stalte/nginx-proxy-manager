-- log_by_lua_file of every proxy host (backend/templates/_sentinel.conf): traffic
-- counters, then automatic-ban counting (bad behaviour and security detections).
local key = ngx.var.corvus_key
require("corvus.traffic").count(key)
require("corvus.rules").npm_log(tonumber(key) or key)
