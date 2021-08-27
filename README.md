# rrdsrv

An [rrdtool](https://oss.oetiker.ch/rrdtool/) api server that exports a secure subset of rrdtool commands over http.

The main motivation of this server is to act as a grafana data source for a WIP
grafana plugin.

## Usage

```
Usage of ./rrdsrv:
  -config string
        Path to configuration file
```

## Configuration

See [examples/defaults.cfg](examples/defaults.cfg) for all configuration options.

## API

### /api/v1/ping

Returns the json encoded string "pong"

### /api/v1/xport?xport=$xport[&format=$format&...$opts]

Runs the equivalent to:

```
$ rrdtool xport $opts -- $xport
```

with the following exceptions:

- Short options are disabled.
- A new format=json|xml option replaces the --json.
- json output is the default.

### /api/v1/graph?graph=$graph[&...$opts]

Runs the equivalent to:

```
$ rrdtool xport $opts -- $graph
```

with the following exceptions:

- Short options are disabled.
- SVG output is the default.
- Only PNG and SVG is supported in the imgformat option.

## Encrypted query params

To allow users to view signed graphs, without arbitrary rrd access,
you can give them an encrypted query url.

Example signed and encrypted graph request:
```
https://$server/api/v1/graph?e=$signed_and_encrypted
```

If `encrypted_query_secret` or `encrypted_query_secret_file` is set in the rrdsrv configuration file, then only encrypted or password authenticated queries are permitted.

An encrypted query is computed as:

```
  path="/ping|/graph|/xport"
  expiry=$unixtime
  query = "p=$path&x=$expiry&$params""
  key = sha256(secret)
  nonce = random_nonce()
  encrypted-query = nacl_crypto_secretbox(key, nonce, msg)
  query= "e=" || base64url(nonce || rquery);
```

For more details on secretbox authenticated encryption see:

- https://nacl.cr.yp.to/secretbox.html

For testing you can generate encrypted query strings via:

```
 $ rrdsrv -c config -encrypt-query "$query"
```

## Notes on security

rrdsrv provides a few mechanisms for secure access:

- We recommend you setup a security sandbox for any public access to the api server.
  See [example/jail.cfg](example/jail.cfg) for one example of how to do this.
- We strongly recommend you do not allow public access to rrdsrv except via
  encrypted/presigned queries.
- For simple setups you can use http basic authentication, see [example/basic-auth.cfg](example/basic-auth.cfg)


## Building

```
$ go build
$ ./rrdsrv --help
```

## TODO

- Sandboxing of rrdtool... bwrap? nsjail?
- Implement grafana plugin.
