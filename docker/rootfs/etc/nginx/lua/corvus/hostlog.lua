-- log_by_lua_file of every proxy host (backend/templates/_sentinel.conf): traffic counters.
require("corvus.traffic").count(ngx.var.corvus_key)
