local base64 = require "base64"
local datetime = require "datetime"
local http = require "http"
local os = require "os"
local shortport = require "shortport"
local slaxml = require "slaxml"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"

local openssl = stdnse.silent_require "openssl"

description = [[
ONVIF enumerator for IP cameras, NVRs and DVRs.

Talks SOAP to the ONVIF Device Service and reports: 
- whether the device requires authentication (and which mechanism it expects)
- basic device identification (manufacturer/model/firmware/serial)
- the credential/RTSP attack surface (configured users and roles, plus RTSP stream URIs pulled from the Media/Media2 profiles).

The authentication check always runs first, mirroring how a real ONVIF client
behaves: 
- the script probes the Device Service unauthenticated
- if that is rejected it inspects the challenge to identify HTTP Basic/Digest or WS-Security UsernameToken
- if credentials are supplied via script-args, they are retried using whichever mechanism the device asked for

]]

---
-- @usage
-- nmap -p 80,8000,8080,8899 --script onvif-enumerator <target>
-- nmap -p 8899 --script onvif-enumerator --script-args onvif-enumerator.username=admin,onvif-enumerator.password=admin <target>
--
-- @args onvif-enumerator.path Path to the ONVIF Device Service.
--       Default: /onvif/device_service
-- @args onvif-enumerator.username Username to try if the device requires
--       authentication.
-- @args onvif-enumerator.password Password to try if the device requires
--       authentication. Must be given together with the username.
--
-- @output
-- 8899/tcp open  soap
-- | onvif-enumerator:
-- |   Authentication:
-- |     Required: false
-- |     Status: ok
-- |   Device:
-- |     Manufacturer: H264
-- |     Model: XM530_RA50X20_8M
-- |     Firmware Version: V5.00.R02.00030665.10010.343706..ONVIF 16.12
-- |     Serial Number: efbd1abef49879fc
-- |   Users:
-- |     admin (Administrator)
-- |   RTSP URIs:
-- |     rtsp://192.168.1.177:554/stream=2
-- |_    rtsp://192.168.1.177:554/user=admin_password=NE83HO2r_channel=0_stream=0.sdp?real_stream
--
-- @xmloutput
-- <table key="Authentication">
-- <elem key="Required">false</elem>
-- <elem key="Status">ok</elem>
-- </table>
-- <table key="Device">
-- <elem key="Manufacturer">H264</elem>
-- <elem key="Model">XM530_RA50X20_8M</elem>
-- </table>
-- <table key="Users">
-- <table>
-- <elem key="Username">admin</elem>
-- <elem key="UserLevel">Administrator</elem>
-- </table>
-- </table>
-- <table key="RTSP URIs">
-- <elem>rtsp://192.168.1.177:554/stream=2</elem>
-- </table>
---

author = "Virgilio Castro"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "auth"}

-- These are the some ports actually seen
-- in the wild across consumer/industrial IP cameras, NVRs and DVRs.
local ONVIF_PORTS = {80, 443, 2020, 5000, 8000, 8080, 8081, 8443, 8899}

portrule = function(host, port)
  return shortport.http(host, port)
    or shortport.port_or_service(ONVIF_PORTS, {"http", "https", "soap", "http-alt"}, "tcp")(host, port)
end

-- ---------------------------------------------------------------------------
-- XML namespaces used to build outgoing SOAP requests and to recognize
-- services by namespace URI in GetServices/GetCapabilities responses.
-- ---------------------------------------------------------------------------
local NS = {
  wsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
  wsu  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
  tds  = "http://www.onvif.org/ver10/device/wsdl",
  tt   = "http://www.onvif.org/ver10/schema",
  trt  = "http://www.onvif.org/ver10/media/wsdl",
  tr2  = "http://www.onvif.org/ver20/media/wsdl",
}

local WSSE_PASSWORD_DIGEST_TYPE =
  "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
local WSSE_NONCE_ENCODING_TYPE =
  "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"

-- Only the namespaces actually used by the operations below need to be
-- declared on the envelope.
local SOAP_ENVELOPE = [[<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="%s" xmlns:tt="%s" xmlns:trt="%s" xmlns:tr2="%s"
            xmlns:wsse="%s" xmlns:wsu="%s">
<s:Header>%s</s:Header>
<s:Body>%s</s:Body>
</s:Envelope>]]

local WSSE_HEADER = [[<wsse:Security s:mustUnderstand="1">
<wsse:UsernameToken>
<wsse:Username>%s</wsse:Username>
<wsse:Password Type="%s">%s</wsse:Password>
<wsse:Nonce EncodingType="%s">%s</wsse:Nonce>
<wsu:Created>%s</wsu:Created>
</wsse:UsernameToken>
</wsse:Security>]]

-- ---------------------------------------------------------------------------
-- Generic XML helpers on top of slaxml's DOM. slaxml already splits each
-- element's namespace URI from its local name, so lookups below only ever
-- need to compare `.name` (never a "prefix:local" string).
-- ---------------------------------------------------------------------------

--- First direct child element of `el` whose local name is `name`, or nil.
local function firstChild(el, name)
  if not el then return nil end
  for _, child in ipairs(el.el or {}) do
    if child.name == name then return child end
  end
  return nil
end

--- Every descendant element (any depth) whose local name is `name`.
local function findDescendants(el, name, out)
  out = out or {}
  if not el then return out end
  for _, child in ipairs(el.el or {}) do
    if child.name == name then out[#out + 1] = child end
    findDescendants(child, name, out)
  end
  return out
end

local function firstDescendant(el, name)
  return (findDescendants(el, name))[1]
end

--- Concatenation of all direct text kids of an element, trimmed.
local function textOf(el)
  if not el then return nil end
  local parts = {}
  for _, kid in ipairs(el.kids or {}) do
    if kid.type == "text" then parts[#parts + 1] = kid.value end
  end
  local text = table.concat(parts)
  text = text:match("^%s*(.-)%s*$")
  return text ~= "" and text or nil
end

--- Text of the first direct child named `name`, or nil.
local function childText(el, name)
  return textOf(firstChild(el, name))
end

--- The single response element inside <Body>, e.g. GetDeviceInformationResponse.
local function responseBody(envelopeRoot)
  local body = firstDescendant(envelopeRoot, "Body")
  return body and body.el and body.el[1] or nil
end

local function xmlEscape(s)
  return (s:gsub('[&<>"\']', {
    ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;", ['"'] = "&quot;", ["'"] = "&apos;",
  }))
end

-- ---------------------------------------------------------------------------
-- SOAP fault handling
-- ---------------------------------------------------------------------------

--- Extract (code, reason) from a SOAP 1.1 or 1.2 Fault, or nil if there isn't one.
local function parseSoapFault(envelopeRoot)
  local fault = firstDescendant(envelopeRoot, "Fault")
  if not fault then return nil end

  local codes = {}
  for _, valueEl in ipairs(findDescendants(fault, "Value")) do
    local text = textOf(valueEl)
    if text then codes[#codes + 1] = text end
  end
  local code
  if #codes > 0 then
    code = table.concat(codes, " ")
  else
    code = childText(fault, "faultcode") or "Unknown"
  end

  local reasonEl = firstDescendant(fault, "Text") or firstChild(fault, "faultstring")
  local reason = textOf(reasonEl) or ""
  return code, reason
end

--- Map a SOAP fault to one of our result status strings.
--
-- ONVIF devices commonly reuse the same fault (ter:NotAuthorized) for both
-- "you must log in" and "you're logged in but lack permission"
local function classifyFault(code, reason, credsSent)
  local text = (code .. " " .. reason):lower()
  if text:find("notauthorized") or text:find("failedauthentication")
      or text:find("failedcheck") or text:find("unauthenticated") then
    return credsSent and "permission_denied" or "authentication_required"
  end
  if text:find("notsupported") or text:find("notimplemented") then
    return "not_supported"
  end
  return "soap_fault"
end

-- ---------------------------------------------------------------------------
-- WS-Security UsernameToken (PasswordDigest)
-- ---------------------------------------------------------------------------

--- PasswordDigest = Base64(SHA1(nonce_bytes + created_utf8 + password_utf8)).
-- The nonce is hashed as raw bytes, not as its base64 text.
local function buildWsseHeader(username, password, clockOffset)
  local nonce = openssl.rand_bytes(20)
  local created = os.date("!%Y-%m-%dT%H:%M:%SZ", os.time() + (clockOffset or 0))
  local digest = base64.enc(openssl.sha1(nonce .. created .. password))
  return WSSE_HEADER:format(
    xmlEscape(username), WSSE_PASSWORD_DIGEST_TYPE, digest,
    WSSE_NONCE_ENCODING_TYPE, base64.enc(nonce), created
  )
end

-- ---------------------------------------------------------------------------
-- HTTP Digest (RFC 2617), hand-rolled instead of relying on http.lua's
-- built-in options.auth.digest: that path (via nselib's sasl.DigestMD5)
-- never echoes back a challenge's "opaque" value, which plenty of embedded
-- DVR/NVR HTTP stacks require verbatim, rejecting an
-- otherwise-correctly-computed response that omits it.
-- ---------------------------------------------------------------------------

--- Parse the Digest scheme out of a WWW-Authenticate header value, which may
-- also list other schemes (e.g. "Basic realm=..., Digest realm=...,
-- nonce=...").  Returns a table keyed by lowercase attribute name, or nil if
-- no Digest challenge is present.
local function parseDigestChallenge(value)
  value = value or ""
  local _, dend = value:lower():find("digest%s+")
  if not dend then return nil end
  local body = value:sub(dend + 1)
  local challenge = {}
  local pos = 1
  while true do
    local ks, ke, key = body:find("([%w_-]+)%s*=%s*", pos)
    if not ks then break end
    local val
    if body:sub(ke + 1, ke + 1) == '"' then
      local qs, qe, qval = body:find('"(.-)"', ke + 1)
      if not qs then break end
      val, pos = qval, qe + 1
    else
      local _, ve, tval = body:find("([^,]*)", ke + 1)
      val, pos = (tval or ""):match("^%s*(.-)%s*$"), ve + 1
    end
    challenge[key:lower()] = val
    local _, ce = body:find("^%s*,%s*", pos)
    if not ce then break end
    pos = ce + 1
  end
  if challenge.stale then challenge.stale = challenge.stale:lower() == "true" end
  return next(challenge) and challenge or nil
end

--- Build an  Authorization: Digest header for one request,
-- reusing the stored challenge (nonce reuse with an incrementing nc is
-- valid and normal; the server can always force a refresh via stale=true).
local function buildDigestAuthorization(client, method, path)
  local d = client.digestChallenge
  client.digestNc = client.digestNc + 1
  local nc = ("%08x"):format(client.digestNc)
  local cnonce = stdnse.tohex(openssl.rand_bytes(8))

  local ha1 = stdnse.tohex(openssl.md5(("%s:%s:%s"):format(client.username, d.realm or "", client.password)))
  if d.algorithm and d.algorithm:upper() == "MD5-SESS" then
    ha1 = stdnse.tohex(openssl.md5(("%s:%s:%s"):format(ha1, d.nonce, cnonce)))
  end
  local ha2 = stdnse.tohex(openssl.md5(("%s:%s"):format(method, path)))

  local response
  if d.qop then
    response = stdnse.tohex(openssl.md5(("%s:%s:%s:%s:%s:%s"):format(ha1, d.nonce, nc, cnonce, d.qop, ha2)))
  else
    response = stdnse.tohex(openssl.md5(("%s:%s:%s"):format(ha1, d.nonce, ha2)))
  end

  local parts = {
    ('username="%s"'):format(client.username), ('realm="%s"'):format(d.realm or ""),
    ('nonce="%s"'):format(d.nonce), ('uri="%s"'):format(path), ('response="%s"'):format(response),
  }
  if d.algorithm then parts[#parts + 1] = ("algorithm=%s"):format(d.algorithm) end
  if d.qop then
    parts[#parts + 1] = ("qop=%s"):format(d.qop)
    parts[#parts + 1] = ("nc=%s"):format(nc)
    parts[#parts + 1] = ('cnonce="%s"'):format(cnonce)
  end
  if d.opaque then parts[#parts + 1] = ('opaque="%s"'):format(d.opaque) end
  return "Digest " .. table.concat(parts, ", ")
end

-- ---------------------------------------------------------------------------
-- ONVIF SOAP client: holds auth state shared across every call to one device,
-- and upgrades automatically the first time it gets challenged, exactly like
-- a real ONVIF client would.
-- ---------------------------------------------------------------------------

local OnvifClient = {}
OnvifClient.__index = OnvifClient

function OnvifClient.new(host, port, scheme, username, password)
  return setmetatable({
    host = host, port = port, scheme = scheme,
    username = username, password = password,
    needsHttp = false, httpScheme = nil, needsWsse = false,
    digestChallenge = nil, digestNc = 0,
    clockOffset = 0,
  }, OnvifClient)
end

function OnvifClient:_send(path, prefix, operation, bodyXml)
  local headerXml = ""
  if self.needsWsse then
    if not (self.username and self.password) then
      return nil, {status = "credentials_required"}
    end
    headerXml = buildWsseHeader(self.username, self.password, self.clockOffset)
  end

  local envelope = SOAP_ENVELOPE:format(NS.tds, NS.tt, NS.trt, NS.tr2, NS.wsse, NS.wsu, headerXml, bodyXml)
  local options = {
    scheme = self.scheme,
    timeout = 8000,
    header = {
      ["Content-Type"] = ('application/soap+xml; charset=utf-8; action="%s/%s"'):format(NS[prefix], operation),
    },
  }
  if self.needsHttp then
    if self.httpScheme == "digest" then
      options.header["Authorization"] = buildDigestAuthorization(self, "POST", path)
    else
      options.auth = {username = self.username, password = self.password}
    end
  end

  local resp = http.post(self.host, self.port, path, options, nil, envelope)
  if not resp.status then
    return nil, {status = "transport_error", error = resp["status-line"] or "request failed"}
  end

  if resp.status == 401 then
    local challenge = resp.header["www-authenticate"] or ""
    if self.needsHttp then
      -- Credentials were already sent for this scheme; a repeated 401 can
      -- still be a recoverable stale-nonce refresh request for Digest.
      if self.httpScheme == "digest" then
        local fresh = parseDigestChallenge(challenge)
        if fresh and fresh.stale then
          return nil, {status = "authentication_required", http_status = 401, digest_stale = true, digest_challenge = fresh}
        end
      end
      return nil, {status = "invalid_credentials", http_status = 401}
    end
    return nil, {
      status = "authentication_required", http_status = 401,
      http_challenge = true, digest_challenge = parseDigestChallenge(challenge),
    }
  end
  if resp.status == 403 then
    return nil, {status = "permission_denied", http_status = 403}
  end

  local dom = slaxml.parseDOM(resp.body or "", {stripWhitespace = true})
  if not dom or not dom.root then
    return nil, {status = "invalid_xml", http_status = resp.status}
  end

  local code, reason = parseSoapFault(dom.root)
  if code then
    local credsSent = self.needsWsse or self.needsHttp
    local status = classifyFault(code, reason, credsSent)
    local err = {status = status, http_status = resp.status, soap_fault_code = code, soap_fault_reason = reason}
    if status == "authentication_required" and not self.needsWsse then
      err.wsse_challenge = true
    end
    return nil, err
  end

  if resp.status >= 400 then
    return nil, {status = "http_error", http_status = resp.status}
  end

  return dom.root, nil
end

--- Invoke one ONVIF SOAP operation, upgrading auth automatically on a first challenge.
--
-- @return response body element (the operation's *Response element) on
--   success, or nil plus an error table on failure.
function OnvifClient:call(path, prefix, operation, inner)
  local bodyXml = inner and ("<%s:%s>%s</%s:%s>"):format(prefix, operation, inner, prefix, operation)
                        or ("<%s:%s/>"):format(prefix, operation)
  local root, err = self:_send(path, prefix, operation, bodyXml)

  if err and err.http_challenge and not self.needsHttp then
    self.needsHttp = true
    if err.digest_challenge then
      self.httpScheme, self.digestChallenge, self.digestNc = "digest", err.digest_challenge, 0
    else
      self.httpScheme = "basic"
    end
    if self.username and self.password then
      root, err = self:_send(path, prefix, operation, bodyXml)
    end
  end

  if err and err.digest_stale then
    self.digestChallenge, self.digestNc = err.digest_challenge, 0
    if self.username and self.password then
      root, err = self:_send(path, prefix, operation, bodyXml)
    end
  end

  if err and err.wsse_challenge and not self.needsWsse then
    self.needsWsse = true
    if self.username and self.password then
      root, err = self:_send(path, prefix, operation, bodyXml)
    end
  end

  if err then
    stdnse.debug1("%s.%s: %s", prefix, operation, err.status)
    return nil, err
  end

  return responseBody(root), nil
end

-- ---------------------------------------------------------------------------
-- Bootstrap / authentication detection
-- ---------------------------------------------------------------------------

--- Read GetSystemDateAndTime's UTCDateTime and store the device/local clock delta.
-- Only affects WS-Security's Created timestamp; a failure here just leaves
-- the offset at zero and WSSE falls back to the scanner's own clock.
local function primeClockOffset(client, path)
  local resp = client:call(path, "tds", "GetSystemDateAndTime")
  if not resp then return end
  local utc = firstDescendant(resp, "UTCDateTime")
  if not utc then return end
  local dateEl, timeEl = firstChild(utc, "Date"), firstChild(utc, "Time")
  if not (dateEl and timeEl) then return end
  local dateTable = {
    year = tonumber(childText(dateEl, "Year")), month = tonumber(childText(dateEl, "Month")),
    day = tonumber(childText(dateEl, "Day")), hour = tonumber(childText(timeEl, "Hour")),
    min = tonumber(childText(timeEl, "Minute")), sec = tonumber(childText(timeEl, "Second")),
  }
  for _, v in pairs(dateTable) do
    if v == nil then return end
  end
  local deviceTs = datetime.date_to_timestamp(dateTable)
  if deviceTs then
    client.clockOffset = deviceTs - os.time()
  end
end

--- Probe the Device Service to find out whether auth is required, and which
-- mechanism it expects.
--
-- @return authentication info table, and the GetDeviceInformationResponse
--   element (or nil if it couldn't be fetched).
local function bootstrapAuth(client, path)
  primeClockOffset(client, path)
  local infoResp = client:call(path, "tds", "GetDeviceInformation")

  local info = {
    Required = client.needsHttp or client.needsWsse,
  }
  if client.needsHttp then
    info.Mechanism = client.httpScheme == "digest" and "HTTP Digest" or "HTTP Basic"
  elseif client.needsWsse then
    info.Mechanism = "WS-Security (UsernameToken)"
  end
  info["Credentials provided"] = (client.username ~= nil) or nil

  if infoResp then
    info.Status = "ok"
  elseif info.Required and not client.username then
    info.Status = "credentials_required"
  elseif info.Required then
    info.Status = "invalid_credentials"
  else
    info.Status = "unreachable"
  end
  return info, infoResp
end

-- ---------------------------------------------------------------------------
-- Device identification
-- ---------------------------------------------------------------------------

local function extractDeviceInfo(infoResp)
  return {
    Manufacturer = childText(infoResp, "Manufacturer"),
    Model = childText(infoResp, "Model"),
    ["Firmware Version"] = childText(infoResp, "FirmwareVersion"),
    ["Serial Number"] = childText(infoResp, "SerialNumber"),
    ["Hardware Id"] = childText(infoResp, "HardwareId"),
  }
end

-- ---------------------------------------------------------------------------
-- Users and roles
-- ---------------------------------------------------------------------------

local function enumerateUsers(client, path)
  local resp = client:call(path, "tds", "GetUsers")
  if not resp then return {} end
  local users = {}
  for _, userEl in ipairs(resp.el or {}) do
    users[#users + 1] = {
      Username = childText(userEl, "Username"),
      UserLevel = childText(userEl, "UserLevel"),
    }
  end
  return users
end

-- ---------------------------------------------------------------------------
-- RTSP paths, via Media (ver10) and Media2 (ver20) profiles
-- ---------------------------------------------------------------------------

--- Resolve the Media/Media2 service paths from GetServices, falling back to
-- the Device Service path itself if discovery fails (many cheap devices
-- serve every ONVIF service off the same endpoint).
local function discoverMediaPaths(client, devicePath)
  local paths = {}
  local resp = client:call(devicePath, "tds", "GetServices", "<tds:IncludeCapability>false</tds:IncludeCapability>")
  if resp then
    for _, svc in ipairs(resp.el or {}) do
      local ns = childText(svc, "Namespace")
      local xaddr = childText(svc, "XAddr")
      if ns and xaddr then
        if ns == NS.trt then paths.trt = url.parse(xaddr).path end
        if ns == NS.tr2 then paths.tr2 = url.parse(xaddr).path end
      end
    end
  end
  paths.trt = paths.trt or devicePath
  paths.tr2 = paths.tr2 or devicePath
  return paths
end

local function streamUriFromResponse(resp)
  return resp and textOf(firstDescendant(resp, "Uri"))
end

--- Collect RTSP stream URIs advertised by every Media (ver10) profile.
local function enumerateMediaRtsp(client, path, uris, seen)
  local resp = client:call(path, "trt", "GetProfiles")
  if not resp then return end
  for _, profile in ipairs(resp.el or {}) do
    local token = profile.attr and profile.attr.token
    if token then
      local inner = "<trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream>"
        .. "<tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup>"
        .. ("<trt:ProfileToken>%s</trt:ProfileToken>"):format(xmlEscape(token))
      local uri = streamUriFromResponse(client:call(path, "trt", "GetStreamUri", inner))
      if uri and not seen[uri] then
        seen[uri] = true
        uris[#uris + 1] = uri
      end
    end
  end
end

--- Collect RTSP stream URIs advertised by every Media2 (ver20) profile.
local function enumerateMedia2Rtsp(client, path, uris, seen)
  local resp = client:call(path, "tr2", "GetProfiles", "<tr2:Type>All</tr2:Type>")
  if not resp then return end
  for _, profile in ipairs(resp.el or {}) do
    local token = profile.attr and profile.attr.token
    if token then
      local inner = ("<tr2:ProfileToken>%s</tr2:ProfileToken><tr2:Protocol>RTSP</tr2:Protocol>"):format(xmlEscape(token))
      local uri = streamUriFromResponse(client:call(path, "tr2", "GetStreamUri", inner))
      if uri and not seen[uri] then
        seen[uri] = true
        uris[#uris + 1] = uri
      end
    end
  end
end

local function enumerateRtsp(client, devicePath)
  local mediaPaths = discoverMediaPaths(client, devicePath)
  local uris, seen = {}, {}
  enumerateMediaRtsp(client, mediaPaths.trt, uris, seen)
  enumerateMedia2Rtsp(client, mediaPaths.tr2, uris, seen)
  return uris
end

-- ---------------------------------------------------------------------------
-- Action
-- ---------------------------------------------------------------------------

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/onvif/device_service"
  local username = stdnse.get_script_args(SCRIPT_NAME .. ".username")
  local password = stdnse.get_script_args(SCRIPT_NAME .. ".password")
  if (username == nil) ~= (password == nil) then
    return ("%s.username and %s.password must be provided together."):format(SCRIPT_NAME, SCRIPT_NAME)
  end

  local scheme = shortport.ssl(host, port) and "https" or "http"
  local client = OnvifClient.new(host, port, scheme, username, password)

  local auth, infoResp = bootstrapAuth(client, path)
  if auth.Status == "unreachable" then
    -- Nothing SOAP-shaped answered on this path/port; stay quiet like other
    -- service-detection scripts do for a non-match.
    return nil
  end

  local output = stdnse.output_table()
  output.Authentication = auth

  if auth.Status ~= "ok" then
    if auth.Status == "credentials_required" then
      output.Note = ("Device requires authentication; provide %s.username/%s.password."):format(SCRIPT_NAME, SCRIPT_NAME)
    elseif auth.Status == "invalid_credentials" then
      output.Note = "Authentication failed with the provided credentials."
    end
    return output
  end

  output.Device = extractDeviceInfo(infoResp)

  local users = enumerateUsers(client, path)
  if #users > 0 then
    local usersOut = {}
    for _, user in ipairs(users) do
      usersOut[#usersOut + 1] = stdnse.output_table()
      usersOut[#usersOut].Username = user.Username
      usersOut[#usersOut].UserLevel = user.UserLevel
    end
    output.Users = usersOut
  end

  local rtsp = enumerateRtsp(client, path)
  if #rtsp > 0 then
    output["RTSP URIs"] = rtsp
  end

  return output
end
