// Generated by CoffeeScript 1.3.1
(function() {
  var Crypto, EXCLUDED_HOSTS, Fs, Goose, Http, Https, ObjectId, QueryString, RESTRICTED_IPS, Url, camo_hostname, connect_failed, current_connections, database, excluded, finish, four_oh_four, hexdec, log, logging_enabled, max_redirects, mongo_collection, mongo_password, mongo_port, mongo_server, mongo_user, mongoose, options, port, process_url, requestForProxy, server, shared_key, ssl_crt, ssl_key, started_at, sys, total_connections, version;

  Fs = require('fs');

  Url = require('url');

  Http = require('http');

  Https = require('https');

  Crypto = require('crypto');

  QueryString = require('querystring');

  port = parseInt(process.env.PORT || 8081);

  version = "0.5.0";

  ssl_key = process.env.SSLKEY || '/etc/apache2/ssl/lmc.key';

  ssl_crt = process.env.SSLCRT || '/etc/apache2/ssl/lmc.crt';

  excluded = process.env.CAMO_HOST_EXCLUSIONS || '*.example.org';

  shared_key = process.env.CAMO_KEY || '0x24FEEDFACEDEADBEEFCAFE';

  max_redirects = process.env.CAMO_MAX_REDIRECTS || 4;

  camo_hostname = process.env.CAMO_HOSTNAME || "unknown";

  logging_enabled = process.env.CAMO_LOGGING_ENABLED || "enabled";

  log = function(msg) {
    if (logging_enabled !== "disabled") {
      console.log("--------------------------------------------");
      console.log(msg);
      return console.log("--------------------------------------------");
    }
  };

  EXCLUDED_HOSTS = new RegExp(excluded.replace(".", "\\.").replace("*", "\\.*"));

  RESTRICTED_IPS = /^((10\.)|(127\.)|(169\.254)|(192\.168)|(172\.((1[6-9])|(2[0-9])|(3[0-1]))))/;

  total_connections = 0;

  current_connections = 0;

  started_at = new Date;

  four_oh_four = function(resp, msg) {
    log(msg);
    resp.writeHead(404);
    return finish(resp, "Not Found");
  };

  finish = function(resp, str) {
    current_connections -= 1;
    if (current_connections < 1) {
      current_connections = 0;
    }
    return resp.connection && resp.end(str);
  };

  process_url = function(url, transferred_headers, resp, remaining_redirects) {
    var query_path, src, srcReq;
    if ((url.host != null) && !url.host.match(RESTRICTED_IPS)) {
      if (url.host.match(EXCLUDED_HOSTS)) {
        return four_oh_four(resp, "Hitting excluded hostnames");
      }
      src = Http.createClient(url.port || 80, url.hostname);
      src.on('error', function(error) {
        return four_oh_four(resp, "Client Request error " + error.stack);
      });
      query_path = url.pathname;
      if (url.query != null) {
        query_path += "?" + url.query;
      }
      transferred_headers.host = url.host;
      log(transferred_headers);
      srcReq = src.request('GET', query_path, transferred_headers);
      srcReq.on('response', function(srcResp) {
        var content_length, is_finished, newHeaders, newUrl;
        is_finished = true;
        log(srcResp.headers);
        content_length = srcResp.headers['content-length'];
        if (content_length > 5242880) {
          return four_oh_four(resp, "Content-Length exceeded");
        } else {
          newHeaders = {
            'expires': srcResp.headers['expires'],
            'content-type': srcResp.headers['content-type'],
            'cache-control': srcResp.headers['cache-control'],
            'content-length': content_length,
            'Camo-Host': camo_hostname,
            'X-Content-Type-Options': 'nosniff'
          };
          if (srcResp.headers['content-encoding']) {
            newHeaders['content-encoding'] = srcResp.headers['content-encoding'];
          }
          srcResp.on('end', function() {
            if (is_finished) {
              return finish(resp);
            }
          });
          srcResp.on('error', function() {
            if (is_finished) {
              return finish(resp);
            }
          });
          switch (srcResp.statusCode) {
            case 200:
              log(newHeaders);
              resp.writeHead(srcResp.statusCode, newHeaders);
              return srcResp.on('data', function(chunk) {
                return resp.write(chunk);
              });
            case 301:
            case 302:
              if (remaining_redirects <= 0) {
                return four_oh_four(resp, "Exceeded max depth");
              } else {
                is_finished = false;
                newUrl = Url.parse(srcResp.headers['location']);
                if (!((newUrl.host != null) && (newUrl.hostname != null))) {
                  newUrl.host = newUrl.hostname = url.hostname;
                  newUrl.protocol = url.protocol;
                }
                console.log(newUrl);
                return process_url(newUrl, transferred_headers, resp, remaining_redirects - 1);
              }
              break;
            case 304:
              return resp.writeHead(srcResp.statusCode, newHeaders);
            default:
              return four_oh_four(resp, "Responded with " + srcResp.statusCode + ":" + srcResp.headers);
          }
        }
      });
      srcReq.on('error', function() {
        return finish(resp);
      });
      return srcReq.end();
    } else {
      return four_oh_four(resp, "No host found " + url.host);
    }
  };

  hexdec = function(str) {
    var buf, i, _i, _ref;
    if (str && str.length > 0 && str.length % 2 === 0 && !str.match(/[^0-9a-f]/)) {
      buf = new Buffer(str.length / 2);
      for (i = _i = 0, _ref = str.length; _i < _ref; i = _i += 2) {
        buf[i / 2] = parseInt(str.slice(i, (i + 1) + 1 || 9e9), 16);
      }
      return buf.toString();
    }
  };

  options = {
    key: Fs.readFileSync(ssl_key),
    cert: Fs.readFileSync(ssl_crt)
  };

  connect_failed = function(reason) {
    return console.log(reason);
  };

  mongoose = require('mongoose');

  ObjectId = require('mongoose').Types.ObjectId;

  sys = require('sys');

  mongo_server = process.env.MONGO_SERVER || '127.0.0.1';

  mongo_port = parseInt(process.env.MONGO_PORT || 37017);

  mongo_collection = process.env.MONGO_COLLECTION || 'contactzilla_dev';

  mongo_user = parseInt(process.env.MONGO_USER || '');

  mongo_password = process.env.MONGO_PASSWORD || '';

  Goose = require('./model');

  database = new Goose({
    server: mongo_server,
    port: mongo_port,
    store: mongo_collection,
    username: mongo_user,
    password: mongo_password,
    debug: mongo_collection === 'contactzilla_dev',
    autoConnect: true
  });

  database.connection.on('initialized', function() {
    return sys.puts("Connected to MongoDB!");
  });

  database.connection.on('timeout', function() {
    return connect_failed("Connecting to mongo timed out");
  });

  database.connection.on('close', function() {
    return connect_failed("Database connection closed");
  });

  requestForProxy = function(host) {
    if ((host.indexOf("sslproxy")) !== -1) {
      return true;
    } else {
      return false;
    }
  };

  server = Https.createServer(options, function(req, resp) {
    var appId, dest_url, encoded_url, hmac, hmac_digest, parts, query_digest, transferred_headers, url, url_type, _base, _ref;
    transferred_headers = {
      'Via': (_base = process.env).CAMO_HEADER_VIA || (_base.CAMO_HEADER_VIA = "Camo Asset Proxy " + version),
      'Accept': req.headers.accept,
      'Accept-Encoding': req.headers['accept-encoding'],
      'x-forwarded-for': req.headers['x-forwarded-for'],
      'x-content-type-options': 'nosniff'
    };
    if (requestForProxy(req.headers.host)) {
      try {
        parts = req.headers.host.split(".");
        appId = parts[0];
        if (appId.length !== 24) {
          resp.end("Invalid application id");
          log("Invalid application id: " + appId);
          return;
        }
        return database.data.application.findOne({
          '_id': new ObjectId(appId)
        }, function(err, app) {
          var assetUrl, dest_url, encoded_url, proxyUrl, query_digest, url, url_type, _ref;
          if (err) {
            throw err;
          }
          if (app != null) {
            if (app.get('assetUrl')) {
              proxyUrl = Url.parse(req.url);
              assetUrl = app.get('assetUrl');
              assetUrl = assetUrl.replace(/\/$/, "") + proxyUrl.pathname;
              total_connections += 1;
              current_connections += 1;
              url = Url.parse(assetUrl);
              delete req.headers.cookie;
              _ref = url.pathname.replace(/^\//, '').split("/", 2), query_digest = _ref[0], encoded_url = _ref[1];
              if (encoded_url = hexdec(encoded_url)) {
                url_type = 'path';
                dest_url = encoded_url;
              } else {
                url_type = 'query';
                dest_url = QueryString.parse(url.query).url;
              }
              if (!dest_url) {
                dest_url = '/';
              }
              if ((url.pathname != null) && dest_url) {
                log(url);
                return process_url(url, transferred_headers, resp, max_redirects);
              } else {
                four_oh_four(resp, "No pathname provided on the server");
                return log(dest_url);
              }
            } else {
              resp.end("This application does not have an asset url configured.");
              return log(app);
            }
          } else {
            resp.writeHead(200);
            return resp.end('Get out!');
          }
        });
      } catch (error) {
        return log("Error: " + error);
      }
    } else if (req.method !== 'GET' || req.url === '/') {
      resp.writeHead(200);
      return resp.end('hwhat');
    } else if (req.url === '/favicon.ico') {
      resp.writeHead(200);
      return resp.end('ok');
    } else if (req.url === '/status') {
      resp.writeHead(200);
      return resp.end("ok " + current_connections + "/" + total_connections + " since " + (started_at.toString()));
    } else {
      total_connections += 1;
      current_connections += 1;
      url = Url.parse(req.url);
      delete req.headers.cookie;
      _ref = url.pathname.replace(/^\//, '').split("/", 2), query_digest = _ref[0], encoded_url = _ref[1];
      if (encoded_url = hexdec(encoded_url)) {
        url_type = 'path';
        dest_url = encoded_url;
      } else {
        url_type = 'query';
        dest_url = QueryString.parse(url.query).url;
      }
      log({
        type: url_type,
        url: req.url,
        headers: req.headers,
        dest: dest_url,
        digest: query_digest
      });
      if ((url.pathname != null) && dest_url) {
        hmac = Crypto.createHmac("sha1", shared_key);
        hmac.update(dest_url);
        hmac_digest = hmac.digest('hex');
        if (hmac_digest === query_digest) {
          url = Url.parse(dest_url);
          return process_url(url, transferred_headers, resp, max_redirects);
        } else {
          return four_oh_four(resp, "checksum mismatch " + hmac_digest + ":" + query_digest);
        }
      } else {
        return four_oh_four(resp, "No pathname provided on the server");
      }
    }
  });

  console.log("SSL-Proxy running on " + port + " with pid:" + process.pid + ".");

  console.log("Using the secret key " + shared_key);

  try {
    server.listen(port);
  } catch (e) {
    console.log("Server could not listen on port " + port + ": " + e);
  }

}).call(this);
