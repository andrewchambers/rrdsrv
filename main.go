package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os/exec"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/alessio/shellescape"
	"github.com/andrewchambers/rrdsrv/rrdtool"
	"github.com/anmitsu/go-shlex"
	"github.com/tg123/go-htpasswd"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttprouter"
)

type ConfigDuration struct {
	time.Duration
}

func (d *ConfigDuration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}

type RRDSrvConfig struct {
	RRDToolCommand            string         `toml:"rrdtool_command"`
	RRDToolTimeout            ConfigDuration `toml:"rrdtool_timeout"`
	RRDToolPoolMaxSize        uint           `toml:"rrdtool_pool_max_size"`
	RRDToolPoolAttritionDelay ConfigDuration `toml:"rrdtool_pool_attrition_delay"`
	Shell                     string         `toml:"shell_path"`
	ListenAddress             string         `toml:"listen_address"`
	BasicAuthHtpasswdFile     string         `toml:"basic_auth_htpasswd_file"`
	UrlSigningSecret          string         `toml:"url_signing_secret"`
	UrlSigningSecretFile      string         `toml:"url_signing_secret_file"`
}

func (cfg *RRDSrvConfig) PopulateDefaults() {
	if cfg.RRDToolCommand == "" {
		cfg.RRDToolCommand = "exec rrdtool"
	}
	if cfg.RRDToolPoolMaxSize == 0 {
		cfg.RRDToolPoolMaxSize = 8
	}
	if cfg.RRDToolTimeout.Duration == 0 {
		cfg.RRDToolTimeout.Duration = 1 * time.Minute
	}
	if cfg.RRDToolPoolAttritionDelay.Duration == 0 {
		cfg.RRDToolPoolAttritionDelay.Duration = 5 * time.Minute
	}
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = "127.0.0.1:9191"
	}
	if cfg.Shell == "" {
		cfg.Shell = "/bin/sh"
	}
}

var (
	RRDToolPool    *rrdtool.RemoteControlPool
	Config         = RRDSrvConfig{}
	ConfigFilePath = flag.String("config", "", "Path to the configuration file.")
)

func RunRRDToolCommand(args []string) ([]byte, error) {
	var cmdBuf bytes.Buffer
	cmdBuf.WriteString(Config.RRDToolCommand)
	for _, arg := range args {
		cmdBuf.WriteByte(' ')
		cmdBuf.WriteString(shellescape.Quote(arg))
	}
	ctx, cancel := context.WithTimeout(context.Background(), Config.RRDToolTimeout.Duration)
	defer cancel()
	cmd := exec.CommandContext(ctx, Config.Shell, "-c", cmdBuf.String())
	out, err := cmd.Output()
	if err != nil {
		if err, ok := err.(*exec.ExitError); ok && len(err.Stderr) != 0 {
			return nil, errors.New(string(err.Stderr))
		} else {
			return nil, err
		}
	}
	return out, nil
}

func RunRRDToolCommandOnPool(args []string) ([]byte, error) {
	rc, err := RRDToolPool.Get()
	if err != nil {
		return nil, err
	}
	defer RRDToolPool.Recycle(rc)
	out := bytes.Buffer{}
	rc.OnStdout = func(b []byte) {
		out.Write(b)
	}
	err = rc.RunCommand(args)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func requestError(ctx *fasthttp.RequestCtx, err error) {
	io.WriteString(ctx, err.Error())
	ctx.SetStatusCode(400)
	ctx.SetContentType("text/plain; charset=utf8")
}

func pingHandler(ctx *fasthttp.RequestCtx, _ fasthttprouter.Params) {
	io.WriteString(ctx, "\"pong\"")
	ctx.SetContentType("text/json; charset=utf8")
}

var xportFlagArgs = map[string]struct{}{
	"start":   struct{}{},
	"step":    struct{}{},
	"end":     struct{}{},
	"maxrows": struct{}{},
}

func xportHandler(ctx *fasthttp.RequestCtx, _ fasthttprouter.Params) {
	qargs := ctx.QueryArgs()
	fullCmdArgs := []string{"xport"}
	wantJson := true

	var err error
	var xportSpec string

	qargs.VisitAll(func(k, v []byte) {
		ks := string(k)
		_, ok := xportFlagArgs[ks]
		if !ok {
			if ks == "xport" {
				xportSpec = string(v)
				return
			}
			if ks == "format" {
				switch string(v) {
				case "json":
					wantJson = true
					fullCmdArgs = append(fullCmdArgs, "--json")
				case "xml":
					wantJson = false
				default:
					err = fmt.Errorf("invalid format: %q", string(v))
				}
				return
			}
			err = fmt.Errorf("unknown query param: %q", string(k))
			return
		}
		fullCmdArgs = append(fullCmdArgs, "--"+ks, string(v))
	})

	if err != nil {
		requestError(ctx, err)
		return
	}

	if len(xportSpec) == 0 {
		requestError(ctx, errors.New("empty xport specification"))
		return
	}

	splitXportSpec, err := shlex.Split(xportSpec, true)
	if err != nil {
		requestError(ctx, fmt.Errorf("unable to perform arg splitting on xport specification: %s", err))
		return
	}

	fullCmdArgs = append(fullCmdArgs, "--")
	fullCmdArgs = append(fullCmdArgs, splitXportSpec...)

	log.Printf("rendering with args: %v", fullCmdArgs)

	var out []byte
	if Config.RRDToolPoolMaxSize != 0 {
		out, err = RunRRDToolCommandOnPool(fullCmdArgs)
	} else {
		out, err = RunRRDToolCommand(fullCmdArgs)
	}
	if err != nil {
		requestError(ctx, err)
		return
	}
	ctx.Write(out)
	if wantJson {
		ctx.SetContentType("application/json; charset=utf8")
	} else {
		ctx.SetContentType("application/xml; charset=utf8")
	}
}

var graphFlagToWantArg = map[string]bool{
	"start":                    true,
	"step":                     true,
	"end":                      true,
	"title":                    true,
	"vertical-label":           true,
	"width":                    true,
	"height":                   true,
	"upper-limit":              true,
	"lower-limit":              true,
	"x-grid":                   true,
	"week-fmt":                 true,
	"y-grid":                   true,
	"left-axis-formatter":      true,
	"left-axis-format":         true,
	"units-exponent":           true,
	"units-length":             true,
	"units":                    true,
	"right-axis":               true,
	"right-axis-label":         true,
	"right-axis-formatter":     true,
	"right-axis-format":        true,
	"legend-position":          true,
	"legend-direction":         true,
	"daemon":                   true,
	"imginfo":                  true,
	"color":                    true,
	"grid-dash":                true,
	"border":                   true,
	"zoom":                     true,
	"font":                     true,
	"font-render-mode":         true,
	"font-smoothing-threshold": true,
	"graph-render-mode":        true,
	"imgformat":                true,
	"tabwidth":                 true,
	"base":                     true,
	"watermark":                true,

	"only-graph":                   false,
	"full-size-mode":               false,
	"rigid":                        false,
	"allow-shrink":                 false,
	"alt-autoscale":                false,
	"alt-autoscale-min":            false,
	"alt-autoscale-max":            false,
	"no-gridfit":                   false,
	"alt-y-grid":                   false,
	"logarithmic":                  false,
	"no-legend":                    false,
	"force-rules-legend":           false,
	"lazy":                         false,
	"dynamic-labels":               false,
	"pango-markup":                 false,
	"slope-mode":                   false,
	"interlaced":                   false,
	"use-nan-for-all-missing-data": false,
}

var imgFormatToContentType = map[string]string{
	"PNG": "image/png",
	"SVG": "image/svg+xml",
}

func graphHandler(ctx *fasthttp.RequestCtx, _ fasthttprouter.Params) {
	qargs := ctx.QueryArgs()
	fullCmdArgs := []string{"graph", "-"}

	var err error
	var graphSpec string
	var imgFormat string

	qargs.VisitAll(func(k, v []byte) {
		ks := string(k)
		wantArg, ok := graphFlagToWantArg[ks]
		if !ok {
			if ks == "graph" {
				graphSpec = string(v)
				return
			}
			err = fmt.Errorf("unknown query param: %q", string(k))
			return
		}
		if wantArg {
			vs := string(v)
			if ks == "imgformat" {
				imgFormat = vs
				return
			}
		} else {
			if bytes.Equal(v, []byte("on")) {
				fullCmdArgs = append(fullCmdArgs, "--"+ks)
			}
		}
	})

	if err != nil {
		requestError(ctx, err)
		return
	}

	if len(graphSpec) == 0 {
		requestError(ctx, errors.New("empty graph specification"))
		return
	}

	splitQuery, err := shlex.Split(graphSpec, true)
	if err != nil {
		requestError(ctx, fmt.Errorf("unable to perform arg splitting on graph specification: %s", err))
		return
	}

	if imgFormat == "" {
		imgFormat = "SVG"
	}
	contentType, formatSupported := imgFormatToContentType[imgFormat]
	if !formatSupported {
		requestError(ctx, fmt.Errorf("graph api does not support the %q format", imgFormat))
		return
	}
	fullCmdArgs = append(fullCmdArgs, "--imgformat", imgFormat)
	fullCmdArgs = append(fullCmdArgs, "--")
	fullCmdArgs = append(fullCmdArgs, splitQuery...)

	log.Printf("rendering with args: %v", fullCmdArgs)

	out, err := RunRRDToolCommand(fullCmdArgs)
	if err != nil {
		requestError(ctx, err)
		return
	}
	ctx.Write(out)
	ctx.SetContentType(contentType)
}

var indexHTML string = `
<html>
<body>
<style> a { text-decoration: none }</style>

<h1>rrdsrv</h1>

<p>
An api server for exporting rrd data to the web.
</p>

Notes:
<ul>
  <li>
    Long form command line options are mapped directly to uri query parameters.
  </li>
  <li>
    Options that take no argument should be specified as 'foo=on' in the uri.
  </li>
</ul>

API:
<br>

<ul>
  <li>
    /api/v1/ping:
    <br>
    <form action="/api/v1/ping" accept-charset="UTF-8">
      <button type="submit">ping</button>
    </form>
  </li>
  <li>
    /api/v1/xport:
    <br>
    <form action="/api/v1/xport" accept-charset="UTF-8">
      Xport Specification:
      <br>
      <textarea name="xport" cols="80" rows="3"></textarea>
      <br>
      Start:
      <br>
      <input name="start" type="text" value="now-1day"></input>
      <br>
      End:
      <br>
      <input name="end" type="text" value="now"></input>
      <br>
      See the <a href="https://oss.oetiker.ch/rrdtool/doc/rrdxport.en.html">rrdxport manual</a> for more options, (--json is replaced with format=json|xml).
      <br>
      <br>
      <button type="submit">export</button>
    </form>
    <li>
    /api/v1/graph:
    <br>
    <form action="/api/v1/graph" accept-charset="UTF-8">
      Graph Specification:
      <br>
      <textarea name="graph" cols="80" rows="3"></textarea>
      <br>
      Start:
      <br>
      <input name="start" type="text" value="now-1day"></input>
      <br>
      End:
      <br>
      <input name="end" type="text" value="now"></input>
      <br>
      See the <a href="https://oss.oetiker.ch/rrdtool/doc/rrdgraph.en.html">rrdgraph manual</a> for more options.
      <br>
      <br>
      <button type="submit">export</button>
    </form>
  </li>
<ul/>

</body>
</html>
`

func indexHandler(ctx *fasthttp.RequestCtx, _ fasthttprouter.Params) {
	io.WriteString(ctx, indexHTML)
	ctx.SetContentType("text/html; charset=utf8")
}

func wrapLogging(h fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		begin := time.Now()
		h(ctx)
		end := time.Now()
		log.Printf("%s %s - %v - %v",
			ctx.Method(),
			ctx.RequestURI(),
			ctx.Response.Header.StatusCode(),
			end.Sub(begin),
		)
	}
}

func wrapBasicAuth(h fasthttp.RequestHandler, htpasswdPath string) fasthttp.RequestHandler {

	passwords, err := htpasswd.New(htpasswdPath, htpasswd.DefaultSystems, nil)
	if err != nil {
		log.Fatalf("error loading basic auth passwords from %q: %s", htpasswdPath, err)
	}

	var basicAuthPrefix = []byte("Basic ")

	return func(ctx *fasthttp.RequestCtx) {
		auth := ctx.Request.Header.Peek("Authorization")
		if bytes.HasPrefix(auth, basicAuthPrefix) {
			payload, err := base64.StdEncoding.DecodeString(string(auth[len(basicAuthPrefix):]))
			if err == nil {
				pair := bytes.SplitN(payload, []byte(":"), 2)
				if len(pair) == 2 &&
					passwords.Match(string(pair[0]), string(pair[1])) {
					h(ctx)
					return
				}
			}
		}
		ctx.Response.Header.Set("WWW-Authenticate", "Basic")
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
	}
}

func main() {

	flag.Parse()

	if *ConfigFilePath != "" {
		cfgData, err := ioutil.ReadFile(*ConfigFilePath)
		if err != nil {
			log.Fatalf("unable to read %q: %s", *ConfigFilePath, err)
		}

		_, err = toml.Decode(string(cfgData), &Config)
		if err != nil {
			log.Fatalf("unable to parse configuration: %s", err)
		}

	}

	Config.PopulateDefaults()

	if Config.RRDToolPoolMaxSize != 0 {
		RRDToolPool = rrdtool.NewPool(context.Background(), rrdtool.PoolOptions{
			RemoteControlOptions: rrdtool.RemoteControlOptions{
				CommandTimeout: Config.RRDToolTimeout.Duration,
				LaunchCommand:  []string{Config.Shell, "-c", Config.RRDToolCommand + " -"},
			},
			MaxSize:        int(Config.RRDToolPoolMaxSize),
			AttritionDelay: Config.RRDToolPoolAttritionDelay.Duration,
		})
		rc, err := RRDToolPool.Get()
		if err != nil {
			log.Fatalf("unable to spawn rrdtool remote control: %s", err)
		}
		RRDToolPool.Recycle(rc)
	}

	router := fasthttprouter.New()
	router.GET("/", indexHandler)
	router.GET("/api/v1/ping", pingHandler)
	router.GET("/api/v1/xport", xportHandler)
	router.GET("/api/v1/graph", graphHandler)

	h := wrapLogging(router.Handler)

	if Config.BasicAuthHtpasswdFile != "" {
		h = wrapBasicAuth(h, Config.BasicAuthHtpasswdFile)
	}

	log.Printf("listening on %s", Config.ListenAddress)
	srv := &fasthttp.Server{
		Handler: h,
		Name:    "rrdsrv",
	}

	if err := srv.ListenAndServe(Config.ListenAddress); err != nil {
		log.Fatalf("error in ListenAndServe: %s", err)
	}
}
