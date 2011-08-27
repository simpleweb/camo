Fs          = require 'fs'
Url         = require 'url'
Http        = require 'http'
Crypto      = require 'crypto'
QueryString = require 'querystring'

version         = "0.3.0"
port            = parseInt process.env.PORT        || 8081
excluded        = process.env.CAMO_HOST_EXCLUSIONS || /^(?:.*\.)?example\.(?:com|org|net)$/
allowed         = process.env.CAMO_HOST_WHITELIST  || ''
shared_key      = process.env.CAMO_KEY             || '0x24FEEDFACEDEADBEEFCAFE'
camo_hostname   = process.env.CAMO_HOSTNAME        || "unknown"
logging_enabled = process.env.CAMO_LOGGING_ENABLED || "disabled"

EXCLUDED_HOSTS  = new RegExp(excluded)
ALLOWED_HOSTS   = new RegExp(allowed)
RESTRICTED_IPS  = /^(?:(?:10\.)|(?:127\.)|(?:169\.254)|(?:192\.168)|(?:172\.(?:(?:1[6-9])|(?:2[0-9])|(?:3[0-1]))))/

total_connections   = 0
current_connections = 0
expire_sec          = 31536000
started_at          = new Date


###
## Helper functions
###
log = (msg) ->
  unless logging_enabled == "disabled"
    console.log("--------------------------------------------")
    console.log(msg)
    console.log("--------------------------------------------")


send404 = (resp, msg) ->
  log msg
  resp.writeHead 404
  finish resp, "Not Found"


finish = (resp, str) ->
  current_connections -= 1
  current_connections  = 0 if current_connections < 1
  resp.connection && resp.end str


# decode a string of two char hex digits
hexdec = (str) ->
  if str?.length > 0 and str.length % 2 == 0 and not str.match(/[^0-9a-f]/)
    buf = new Buffer(str.length / 2)
    for i in [0...str.length] by 2
      buf[i/2] = parseInt(str[i..i+1], 16)
    buf.toString()


###
## Handlers
###
rootHandler = (req, resp) ->
  resp.writeHead 200
  resp.end 'what?'


faviconHandler = (req, resp) ->
  expires = new Date()
  expires.setSeconds(expires.getSeconds() + expire_sec)
  resp.writeHead 200, {
      'Cache-Control': 'public;max-age='+ expire_sec,
      'Expires': expires.toUTCString() }
  resp.end 'ok'


statusHandler = (req, resp) ->
  resp.writeHead 200
  resp.end "ok #{current_connections}/#{total_connections} since #{started_at.toString()}"


proxyHandler = (req, resp) ->
  total_connections   += 1
  current_connections += 1
  url = Url.parse req.url

  transferred_headers =
    'Via'                    : process.env.CAMO_HEADER_VIA or= "Camo Asset Proxy #{version}"
    'Accept'                 : req.headers.accept
    'Accept-Encoding'        : req.headers['accept-encoding']
    'x-forwarded-for'        : req.headers['x-forwarded-for']
    'x-content-type-options' : 'nosniff'

  if req.headers['if-match']?
    transferred_headers['if-match'] = req.headers['if-match']
  if req.headers['if-none-match']?
    transferred_headers['if-none-match'] = req.headers['if-none-match']

  if req.headers['if-modified-since']?
    transferred_headers['if-modified-since'] = req.headers['if-modified-since']
  if req.headers['if-unmodified-since']?
    transferred_headers['if-unmodified-since'] = req.headers['if-unmodified-since']

  delete(req.headers.cookie)

  [query_digest, encoded_url] = url.pathname.replace(/^\//, '').split("/", 2)
  if encoded_url = hexdec(encoded_url)
    url_type = 'path'
    dest_url = encoded_url
  else
    url_type = 'query'
    dest_url = QueryString.parse(url.query).url

  log(
    type:     url_type
    url:      req.url
    headers:  req.headers
    dest:     dest_url
    digest:   query_digest
  )

  if !url.pathname? or !dest_url?
    return send404(resp, "No pathname provided on the server")

  hmac = Crypto.createHmac("sha1", shared_key)
  hmac.update(dest_url)
  hmac_digest = hmac.digest('hex')

  if hmac_digest != query_digest
    return send404(resp, "checksum mismatch #{hmac_digest}:#{query_digest}")

  dest_url = Url.parse dest_url
  if !dest_url.host? or dest_url.host.match(RESTRICTED_IPS)
    return send404(resp, "No host found #{dest_url.host}")

  if ALLOWED_HOSTS != '' and !dest_url.host.match(ALLOWED_HOSTS)
    return send404(resp, "Not in whitelist")

  if dest_url.host.match(EXCLUDED_HOSTS)
    return send404(resp, "Hitting excluded hostnames")

  src = Http.createClient dest_url.port || 80, dest_url.hostname

  src.on 'error', (error) ->
    send404(resp, "Client Request error #{error.stack}")

  query_path = dest_url.pathname
  query_path += "?#{dest_url.query}" if dest_url.query?

  transferred_headers.host = dest_url.host

  log transferred_headers

  srcReq = src.request 'GET', query_path, transferred_headers

  srcReq.on 'response', (srcResp) ->
    log srcResp.headers

    content_length  = srcResp.headers['content-length']
    if content_length? and content_length > 5242880
      send404(resp, "Content-Length exceeded")
    else
      newHeaders =
        'content-type'           : srcResp.headers['content-type']
        'Camo-Host'              : camo_hostname
        'X-Content-Type-Options' : 'nosniff'
     
      # only set these if upstream has them set
      if srcResp.headers['cache-control']?
        newHeaders['cache-control'] = srcResp.headers['cache-control']
      if srcResp.headers['expires']?
        newHeaders['expires'] = srcResp.headers['expires']
      if srcResp.headers['etag']?
        newHeaders['etag'] = srcResp.headers['etag']
      if srcResp.headers['last-modified']?
        newHeaders['last-modified'] = srcResp.headers['last-modified']

      # special case content-length. might not be sent by upstream server
      # if gzip encoded / chunked response
      if content_length?
        newHeaders['content-length'] = content_length
      if srcResp.headers['transfer-encoding']?
        newHeaders['transfer-encoding'] = srcResp.headers['transfer-encoding']
      if srcResp.headers['content-encoding']?
        newHeaders['content-encoding'] = srcResp.headers['content-encoding']

      srcResp.on 'end', -> finish resp
      srcResp.on 'error', -> finish resp

      switch srcResp.statusCode
        when 200
          if newHeaders['content-type'] && newHeaders['content-type'].slice(0, 5) != 'image'
            return send404(resp, "Non-Image content-type returned")
          log newHeaders
          resp.writeHead srcResp.statusCode, newHeaders
          srcResp.on 'data', (chunk) -> resp.write chunk
        when 304
          resp.writeHead srcResp.statusCode, newHeaders
        else
          send404(resp, "Responded with #{srcResp.statusCode}:#{srcResp.headers}")
  srcReq.on 'error', -> finish resp
  srcReq.end()


###
## Server / Router
###
server = Http.createServer (req, resp) ->
  if req.method != 'GET'
    return rootHandler(req, resp)
  switch req.url
    when '/'
      return rootHandler(req, resp)
    when '/favicon.ico'
      return faviconHandler(req, resp)
    when '/status'
      return statusHandler(req, resp)
    else
      return proxyHandler(req, resp)

# top level exception handler to keep server running
process.on 'uncaughtException', (error) ->
  log(error.stack)

## start server
console.log "SSL-Proxy running on #{port} with pid:#{process.pid}."
console.log "Using the secret key #{shared_key}"
console.log "Excluded Host RegExp: #{EXCLUDED_HOSTS}"
console.log "Allowed Host RegExp: #{ALLOWED_HOSTS}"
server.listen port
