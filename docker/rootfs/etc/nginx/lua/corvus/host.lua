-- Entry point for Sentinel rules in each host's server block (backend/templates/_sentinel.conf).
-- $corvus_key is the proxy host id, or "r<id>" for a redirection host.
local key = ngx.var.corvus_key
require("corvus.rules").rewrite(tonumber(key) or key)
