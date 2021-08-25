# rrdsrv

An api server that exports a secure subset of rrdtool commands over http.

The main motivation of this server is to act as a grafana data source for a WIP
grafana plugin.

## Usage

```
Usage of ./rrdsrv:
  -compress
        Enable transparent response compression.
  -listen-address string
        Address to listen on for http requests. (default "127.0.0.1:9191")
  -rrd-dir string
        Allow queries of rrd files under this path. (default "./")
```

## API

### /api/v1/xport?q=$query[&format=$format&start=$start&end=$end&step=$step]

Takes a query param 'q' and runs the equivalent to:

```
$ rrdtool xport --start $start --end $end --step $step -- $query
```

The query is split into arguments following normal shell rules.
If the query does not contain an XPORT directive, then XPORT:v is implicitly added.

All rrd paths are relative to -rrd-dir.

Valid format values are 'xml' and 'json' (the default).

On error the result is returned as plain text with an http error status code set.

## Building

```
$ go build
$ ./rrdsrv --help
```

## TODO

- Sandboxing of rrdtool... bwrap? nsjail?
- Pooling of rrdtool instances using remote control.
- Graphing api.
- Implement grafana plugin.
