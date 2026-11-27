---
outline: deep
---

# Sentinel

Sentinel is the security engine in front of your proxy hosts. It can block requests with
security rules and IP or User-Agent lists, check that visitors are real browsers
("under attack" mode), ban clients that misbehave and rate limit requests.

Everything is off until you turn it on. With no rules, no under attack mode, automatic
bans off and no rate limits, Sentinel passes every request through unchanged.

## Protection settings of a host

Open **Sentinel > Under Attack Mode** and edit a host to set its protection:

- **Under attack mode**: *Off*, *Always on*, or *Automatic* (turns on by itself when the
  request rate or the share of blocked requests goes over a threshold).
- **Only challenge page loads**: only browser page loads get the browser check. API
  calls, websockets, media streams and requests from apps pass without a challenge.
- **Never ban clients because of this host**: error responses and blocked requests on
  this host do not count towards automatic bans.

The same "Only challenge page loads" option is available on security rules with the
*Challenge* action.

## Apps with their own clients

The browser check is a page that runs a small JavaScript puzzle. Browsers solve it once
and get a pass for a while. Apps cannot: TV, mobile and desktop apps, API clients and
websocket connections never see the page, so a challenge simply blocks them.

For an app like Plex, Jellyfin, Emby or Seerr, always turn on **Only challenge page
loads** for its host and for any challenge rule that covers it. The **Plex** and
**Seerr** presets in the protection settings fill in settings that keep these apps
working. Review them and save.

### Plex

| Setting | Recommended |
| --- | --- |
| Proxy host: Websockets Support | On (Plex uses websockets for live updates) |
| Under attack mode | Automatic, or Off |
| Only challenge page loads | **On** |
| Never ban clients because of this host | **On** |
| Rate limit | None |

Why:

- Plex apps call the server API constantly and stream media over long requests. With
  page loads only, none of these are challenged, even while under attack mode is on.
  Only someone opening the Plex web app on your domain in a browser solves the check
  once.
- The Plex web app at app.plex.tv talks to your server with cross-origin requests that
  cannot carry the pass cookie. Page loads only lets them through.
- Plex apps routinely get `401` (expired tokens) and `404` (missing artwork) responses.
  Counted as bad behaviour, they could ban a family member's TV. Leave the host out of
  automatic bans.
- A rate limit is easy to hit when a client scrolls a large library and loads hundreds
  of posters, so none is recommended.

### Seerr

| Setting | Recommended |
| --- | --- |
| Proxy host: Websockets Support | On |
| Under attack mode | Automatic |
| Only challenge page loads | **On** |
| Never ban clients because of this host | Off (bans stop login and scanner abuse) |
| Rate limit | Optional: 20 requests/s, burst 40, start with a dry run |

Why:

- Seerr is a web app that loads its data from its own API. Page loads only challenges
  the page itself under attack and leaves the API calls alone.
- Seerr is a common target for login guessing and scanners. With automatic bans on, a
  client that keeps getting `401`, `403` or `404` responses is banned.
- A rate limit protects the login and request APIs. Start it as a **dry run** and look
  at "would be refused" in the Rate limits tab for a few days before you enforce it.

## Automatic bans

**Sentinel > Bans > Automatic bans** bans a client that keeps getting error responses
(by default 30 responses with `400`, `401`, `403`, `404`, `405`, `429` or `444` within
60 seconds on one host) or keeps being refused by security rules (20 within 10 minutes).
The first ban lasts 15 minutes and doubles with each repeat offense, up to a week.

- A ban applies to **every host**, so a client banned for scanning Seerr also loses
  access to Plex. Bans of IPv6 clients cover their /64 network.
- Add your home network (for example `192.168.0.0/16`) to **Never ban these networks**,
  so a misconfigured device at home cannot lock you out. Loopback is never banned.
- `429` responses count as bad behaviour. A client that keeps running into an enforced
  rate limit is banned too, so keep rate limits loose, or remove `429` from the status
  codes.
- Lift a ban with the unlock button in the Bans tab. The offense count is kept, so a
  client that comes back is banned for longer.

## Rate limits

**Sentinel > Rate limits** limits how many requests per second one client (an IPv4
address or an IPv6 /64) can send to a host. *Burst* lets short spikes through, such as a
page loading its images. Each host can have one rate limit, and requests that a security
rule allowed are never limited.

Use **Dry run** first: requests are only counted, not refused, and the Rate limits tab
shows how many would have been refused over the last 10 minutes.
