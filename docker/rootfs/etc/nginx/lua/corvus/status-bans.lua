-- Status port PUT /bans (conf.d/sentinel.conf).
if ngx.req.get_method() ~= "PUT" then return ngx.exit(405) end
require("corvus.rules").set_bans()
