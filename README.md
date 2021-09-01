# rrdsrv

An [RRDtool](https://oss.oetiker.ch/rrdtool/) api server that exports a subset of rrdtool commands over http(s).

Be sure to checkout the [grafana plugin](https://github.com/andrewchambers/grafana-rrd-datasource).

[Demo video](https://www.youtube.com/watch?v=BuoPcyJik38).

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

### /api/v1/list_metrics?[glob=$glob]

Runs the configured list_rrds_command then extracts
matching ds metrics from the returned rrds.
The $path:$ds pairs are then matched against the provided glob pattern.

## Signed query and post params

To allow users to view signed graphs, without arbitrary rrd access,
you can give them a signed query with an optional unix time for expiry.

Example signed and encrypted graph request:
```
https://$server/api/v1/graph?foo=bar&x=$expiry&s=$sig
```

If `signed_query_secret` or `signed_query_secret_file` is set in the rrdsrv configuration file, then only signed or password authenticated queries are permitted.

A signed query is computed as:

```
path=/api/v1/ping,...
sig=hmac-sha256($secret, $path || "?" || $query-params || "&")
signed=$path || "?" || $query-params || "&s=$sig"
```

For testing you can generate a signed query string via:

```
 $ rrdsrv -c your-config.cfg -sign-query "$path?$query"
```

## Notes on security

rrdsrv provides a few mechanisms for secure access:

- We recommend you setup a security sandbox for any public access to the api server.
  See [example/jail.cfg](example/jail.cfg) for one example of how to do this.
- We strongly recommend you do not allow public access to rrdsrv except via presigned queries.
- For simple setups you can use http basic authentication, see [example/basic-auth.cfg](example/basic-auth.cfg)


## Building

```
$ go build
$ ./rrdsrv --help
```
