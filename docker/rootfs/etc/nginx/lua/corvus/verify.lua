-- content_by_lua_file of /__corvus/challenge/verify (backend/templates/_sentinel.conf).
local key = ngx.var.corvus_key
require("corvus.rules").challenge_verify(tonumber(key) or key)
