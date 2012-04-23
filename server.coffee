Fs          = require 'fs'
Url         = require 'url'
Http        = require 'http'
Https        = require 'https'
Crypto      = require 'crypto'
QueryString = require 'querystring'

port            = parseInt process.env.PORT        || 8081
version         = "0.5.0"
ssl_key         = process.env.SSLKEY               || '/etc/apache2/ssl/lmc.key'
ssl_crt         = process.env.SSLCRT               || '/etc/apache2/ssl/lmc.crt'
excluded        = process.env.CAMO_HOST_EXCLUSIONS || '*.example.org'
shared_key      = process.env.CAMO_KEY             || '0x24FEEDFACEDEADBEEFCAFE'
max_redirects   = process.env.CAMO_MAX_REDIRECTS   || 4
camo_hostname   = process.env.CAMO_HOSTNAME        || "unknown"
logging_enabled = process.env.CAMO_LOGGING_ENABLED || "enabled"

log = (msg) ->
  unless logging_enabled == "disabled"
    console.log("--------------------------------------------")
    console.log(msg)
    console.log("--------------------------------------------")

EXCLUDED_HOSTS = new RegExp(excluded.replace(".", "\\.").replace("*", "\\.*"))
RESTRICTED_IPS = /^((10\.)|(127\.)|(169\.254)|(192\.168)|(172\.((1[6-9])|(2[0-9])|(3[0-1]))))/

total_connections   = 0
current_connections = 0
started_at          = new Date

four_oh_four = (resp, msg) ->
  log msg
  resp.writeHead 404
  finish resp, "Not Found"

finish = (resp, str) ->
  current_connections -= 1
  current_connections  = 0 if current_connections < 1
  resp.connection && resp.end str

process_url = (url, transferred_headers, resp, remaining_redirects) ->
  if url.host? && !url.host.match(RESTRICTED_IPS)
    if url.host.match(EXCLUDED_HOSTS)
      return four_oh_four(resp, "Hitting excluded hostnames")

    src = Http.createClient url.port || 80, url.hostname

    src.on 'error', (error) ->
      four_oh_four(resp, "Client Request error #{error.stack}")

    query_path = url.pathname
    if url.query?
      query_path += "?#{url.query}"

    transferred_headers.host = url.host

    log transferred_headers

    srcReq = src.request 'GET', query_path, transferred_headers

    srcReq.on 'response', (srcResp) ->
      is_finished = true

      log srcResp.headers

      content_length = srcResp.headers['content-length']

      if content_length > 5242880
        four_oh_four(resp, "Content-Length exceeded")
      else
        newHeaders =
          'expires'                : srcResp.headers['expires']
          'content-type'           : srcResp.headers['content-type']
          'cache-control'          : srcResp.headers['cache-control']
          'content-length'         : content_length
          'Camo-Host'              : camo_hostname
          'X-Content-Type-Options' : 'nosniff'

        if srcResp.headers['content-encoding']
          newHeaders['content-encoding'] = srcResp.headers['content-encoding']

        srcResp.on 'end', ->
          if is_finished
            finish resp
        srcResp.on 'error', ->
          if is_finished
            finish resp
        switch srcResp.statusCode
          when 200
            if newHeaders['content-type'] && newHeaders['content-type'].slice(0, 5) != 'image'
              four_oh_four(resp, "Non-Image content-type returned")

            log newHeaders

            resp.writeHead srcResp.statusCode, newHeaders
            srcResp.on 'data', (chunk) ->
              resp.write chunk
          when 301, 302
            if remaining_redirects <= 0
              four_oh_four(resp, "Exceeded max depth")
            else
              is_finished = false
              newUrl = Url.parse srcResp.headers['location']
              unless newUrl.host? and newUrl.hostname?
                newUrl.host = newUrl.hostname = url.hostname
                newUrl.protocol = url.protocol

              console.log newUrl
              process_url newUrl, transferred_headers, resp, remaining_redirects - 1
          when 304
            resp.writeHead srcResp.statusCode, newHeaders
          else
            four_oh_four(resp, "Responded with " + srcResp.statusCode + ":" + srcResp.headers)
    srcReq.on 'error', ->
      finish resp

    srcReq.end()
  else
    four_oh_four(resp, "No host found " + url.host)

# decode a string of two char hex digits
hexdec = (str) ->
  if str and str.length > 0 and str.length % 2 == 0 and not str.match(/[^0-9a-f]/)
    buf = new Buffer(str.length / 2)
    for i in [0...str.length] by 2
      buf[i/2] = parseInt(str[i..i+1], 16)
    buf.toString()

options = {
  key: Fs.readFileSync(ssl_key),
  cert: Fs.readFileSync(ssl_crt)
};

connect_failed = (reason) ->
  # End the request
  console.log reason
  # TODO: Notify developer and try to reconnect in a few seconds
    
# Connect to the database
mongoose = require 'mongoose'
ObjectId = require('mongoose').Types.ObjectId;
sys = require 'sys'
mongo_server      = process.env.MONGO_SERVER          || '127.0.0.1'
mongo_port        = parseInt process.env.MONGO_PORT   || 37017
mongo_collection  = process.env.MONGO_COLLECTION      || 'contactzilla_dev'
mongo_user        = parseInt process.env.MONGO_USER   || ''
mongo_password    = process.env.MONGO_PASSWORD        || ''
Goose       = require('./model')
database    = new Goose({
        server:   mongo_server,
        port:     mongo_port,
        store:    mongo_collection,
        username:   mongo_user,
        password:   mongo_password,
        debug:    (mongo_collection == 'contactzilla_dev'),
        autoConnect:true
      })

database.connection.on 'initialized', () ->
  sys.puts "Connected to MongoDB!"
        
database.connection.on 'timeout', () ->
  connect_failed "Connecting to mongo timed out"
  
database.connection.on 'close', () ->
  connect_failed "Database connection closed"
        
requestForProxy = (host) ->
  if (host.indexOf "sslproxy") != -1
    return true
  else  
    return false

server = Https.createServer options, (req, resp) ->
  
  transferred_headers =
      'Via'                    : process.env.CAMO_HEADER_VIA or= "Camo Asset Proxy #{version}"
      'Accept'                 : req.headers.accept
      'Accept-Encoding'        : req.headers['accept-encoding']
      'x-forwarded-for'        : req.headers['x-forwarded-for']
      'x-content-type-options' : 'nosniff'
      
  # Are we in proxy mode?
  if requestForProxy req.headers.host
    try
      # Get the app install id
      parts = req.headers.host.split "."
      appId = parts[0]
      if appId.length != 24
        resp.end "Invalid application id"
        log "Invalid application id: #{appId}"
        return
      
      # Find the application id
      database.data.application.findOne { '_id': new ObjectId(appId) }, (err, app) ->
        throw err if err
        if app?
          # Proxy init
          
          if app.get 'assetUrl'
          
            proxyUrl = Url.parse req.url
            
            assetUrl = app.get 'assetUrl'
            assetUrl = assetUrl.replace(/^\/$/,"") + proxyUrl.pathname
            
            total_connections   += 1
            current_connections += 1
            url = Url.parse assetUrl
            
            delete(req.headers.cookie)

            [query_digest, encoded_url] = url.pathname.replace(/^\//, '').split("/", 2)
            if encoded_url = hexdec(encoded_url)
              url_type = 'path'
              dest_url = encoded_url
            else
              url_type = 'query'
              dest_url = QueryString.parse(url.query).url

            if not dest_url
              dest_url = '/'
              
            if url.pathname? && dest_url
              # Heads up! ContactZilla does not use an encrypted digest, it should be ok for assets, but not for other content
              log url
              process_url url, transferred_headers, resp, max_redirects
              
            else
              four_oh_four(resp, "No pathname provided on the server")
              log dest_url
            
          else
            resp.end "This application does not have an asset url configured."
            log app
          
        else
          # End the request
          resp.writeHead 200
          resp.end 'Get out!'
      
    catch error
      log "Error: #{error}"
      
  else if req.method != 'GET' || req.url == '/'
    resp.writeHead 200
    resp.end 'hwhat'
  else if req.url == '/favicon.ico'
    resp.writeHead 200
    resp.end 'ok'
  else if req.url == '/status'
    resp.writeHead 200
    resp.end "ok #{current_connections}/#{total_connections} since #{started_at.toString()}"
  else
    total_connections   += 1
    current_connections += 1
    url = Url.parse req.url
    
    delete(req.headers.cookie)

    [query_digest, encoded_url] = url.pathname.replace(/^\//, '').split("/", 2)
    if encoded_url = hexdec(encoded_url)
      url_type = 'path'
      dest_url = encoded_url
    else
      url_type = 'query'
      dest_url = QueryString.parse(url.query).url

    log({
      type:     url_type
      url:      req.url
      headers:  req.headers
      dest:     dest_url
      digest:   query_digest
    })

    if url.pathname? && dest_url
      hmac = Crypto.createHmac("sha1", shared_key)
      hmac.update(dest_url)

      hmac_digest = hmac.digest('hex')

      if hmac_digest == query_digest
        url = Url.parse dest_url

        process_url url, transferred_headers, resp, max_redirects
      else
        four_oh_four(resp, "checksum mismatch #{hmac_digest}:#{query_digest}")
    else
      four_oh_four(resp, "No pathname provided on the server")

console.log "SSL-Proxy running on #{port} with pid:#{process.pid}."
console.log "Using the secret key #{shared_key}"

#Fs.open "tmp/camo.pid", "w", 0o600, (err, fd) ->
#  Fs.writeSync fd, process.pid

try 
  server.listen port
catch e
  console.log "Server could not listen on port #{port}: #{e}"