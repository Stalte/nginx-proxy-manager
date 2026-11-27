-- Status port GET /bad-behaviour (conf.d/sentinel.conf): pending gateway-local bans.
require("corvus.rules").bad_behaviour_hits()
