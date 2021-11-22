package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/alessio/shellescape"
	"github.com/andrewchambers/rrdsrv/querysign"
	"github.com/andrewchambers/rrdsrv/rrdtool"
	"github.com/anmitsu/go-shlex"
	"github.com/gobwas/glob"
	"github.com/tg123/go-htpasswd"
	"github.com/valyala/fasthttp"
	"golang.org/x/sys/unix"

	_ "embed"
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
	ListRRDsCommand           string         `toml:"list_rrds_command"`
	ListRRDsTimeout           ConfigDuration `toml:"list_rrds_timeout"`
	Shell                     string         `toml:"shell_path"`
	ListenAddress             string         `toml:"listen_address"`
	BasicAuthHtpasswdFile     string         `toml:"basic_auth_htpasswd_file"`
	SignedQuerySecret         string         `toml:"signed_query_secret"`
	SignedQuerySecretFile     string         `toml:"signed_query_secret_file"`
	signedQuerySecretBytes    []byte
}

func (cfg *RRDSrvConfig) AllowUnauthenticatedAccess() bool {
	return len(cfg.signedQuerySecretBytes) == 0 && len(cfg.BasicAuthHtpasswdFile) == 0
}

func (cfg *RRDSrvConfig) PopulateMissing() error {
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
	if cfg.ListRRDsTimeout.Duration == 0 {
		cfg.ListRRDsTimeout.Duration = 1 * time.Minute
	}
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = "localhost:9191"
	}
	if cfg.Shell == "" {
		cfg.Shell = "/bin/sh"
	}

	cfg.signedQuerySecretBytes = []byte(cfg.SignedQuerySecret)

	if cfg.SignedQuerySecretFile != "" {
		secret, err := ioutil.ReadFile(cfg.SignedQuerySecretFile)
		if err != nil {
			return fmt.Errorf("unable to load signed_query_secret_file: %s", err)
		}
		cfg.signedQuerySecretBytes = secret
	}

	return nil
}

var (
	RRDToolPool *rrdtool.RemoteControlPool
	passwords   *htpasswd.File
	Config      = RRDSrvConfig{}
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

func serverError(ctx *fasthttp.RequestCtx, err error) {
	io.WriteString(ctx, "internal error serving request")
	ctx.SetStatusCode(500)
	ctx.SetContentType("text/plain; charset=utf8")
	log.Printf("error serving request: %s", err)
}

func pingHandler(ctx *fasthttp.RequestCtx) {
	io.WriteString(ctx, "\"pong\"")
	ctx.SetContentType("text/json; charset=utf8")
}

var xportFlagArgs = map[string]struct{}{
	"start":   struct{}{},
	"step":    struct{}{},
	"end":     struct{}{},
	"maxrows": struct{}{},
}

func xportHandler(ctx *fasthttp.RequestCtx, query *fasthttp.Args) {
	fullCmdArgs := []string{"xport"}
	wantJson := true

	var err error
	var xportSpec string

	query.VisitAll(func(k, v []byte) {
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
		fullCmdArgs = append(fullCmdArgs, fmt.Sprintf("--%s=%s", ks, string(v)))
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

	if wantJson {
		fullCmdArgs = append(fullCmdArgs, "--json")
	}

	fullCmdArgs = append(fullCmdArgs, "--")
	fullCmdArgs = append(fullCmdArgs, splitXportSpec...)

	log.Printf("id=%d rendering with args: %v", ctx.ID(), fullCmdArgs)

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

func graphHandler(ctx *fasthttp.RequestCtx, query *fasthttp.Args) {
	fullCmdArgs := []string{"graph", "-"}

	var err error
	var graphSpec string
	var imgFormat string

	query.VisitAll(func(k, v []byte) {
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
			fullCmdArgs = append(fullCmdArgs, fmt.Sprintf("--%s=%s", ks, vs))
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
	fullCmdArgs = append(fullCmdArgs, "--imgformat="+imgFormat)
	fullCmdArgs = append(fullCmdArgs, "--")
	fullCmdArgs = append(fullCmdArgs, splitQuery...)

	log.Printf("id=%d rendering with args: %v", ctx.ID(), fullCmdArgs)

	out, err := RunRRDToolCommand(fullCmdArgs)
	if err != nil {
		requestError(ctx, err)
		return
	}
	ctx.Write(out)
	ctx.SetContentType(contentType)
}

func listMetricsHandler(ctx *fasthttp.RequestCtx, query *fasthttp.Args) {

	if Config.ListRRDsCommand == "" {
		ctx.SetStatusCode(501)
		ctx.WriteString("listing not enabled")
		return
	}

	cmdCtx, cancel := context.WithTimeout(context.Background(), Config.ListRRDsTimeout.Duration)
	defer cancel()

	rc, err := RRDToolPool.Get()
	if err != nil {
		serverError(ctx, fmt.Errorf("unable to get rrdtool remote control: %s", err))
		return
	}
	defer RRDToolPool.Recycle(rc)

	var wantGlob bool
	var globPattern string

	query.VisitAll(func(k, v []byte) {
		if bytes.Equal(k, []byte("glob")) {
			globPattern = string(v)
			wantGlob = true
		} else {
			err = fmt.Errorf("unknown query param: %q", string(k))
		}
	})

	if err != nil {
		requestError(ctx, err)
		return
	}

	var globber glob.Glob

	if wantGlob {
		g, err := glob.Compile(globPattern, '/')
		if err != nil {
			requestError(ctx, fmt.Errorf("unable to compile glob: %s", err))
			return
		}
		globber = g
	}

	metrics := make([]string, 0, 64)

	cmd := exec.CommandContext(cmdCtx, Config.Shell, "-c", Config.ListRRDsCommand)

	p1, p2, err := os.Pipe()
	if err != nil {
		serverError(ctx, fmt.Errorf("listing failed: %s", err))
		return
	}
	defer p1.Close()
	defer p2.Close()
	cmd.Stdout = p2

	err = cmd.Start()
	if err != nil {
		serverError(ctx, fmt.Errorf("unable to start listing command: %s", err))
		return
	}
	defer cmd.Wait()
	defer cmd.Process.Signal(unix.SIGTERM)

	_ = p2.Close()

	scanner := bufio.NewScanner(p1)

	for scanner.Scan() {

		rrdFile := string(scanner.Bytes())
		prevMetric := ""
		rc.OnStdout = func(l []byte) {
			if !(len(l) > 4 && l[0] == 'd' && l[1] == 's' && l[2] == '[') {
				return
			}
			end := bytes.IndexByte(l, ']')
			if end == -1 {
				return
			}
			metric := rrdFile + ":" + string(l[3:end])
			// skip runs.
			if metric == prevMetric {
				return
			}
			prevMetric = metric
			if !wantGlob {
				metrics = append(metrics, metric)
				return
			}
			if globber.Match(metric) {
				metrics = append(metrics, metric)
			}
		}

		err = rc.RunCommand([]string{"info", rrdFile})
		if err != nil {
			log.Printf("error running rrdtool info on %q: %s", rrdFile, err)
			// Just continue, not much else to do.
			continue
		}
	}

	err = scanner.Err()
	if err != nil {
		serverError(ctx, fmt.Errorf("unable to reading listing command output: %s", err))
		return
	}

	if err := cmd.Wait(); err != nil {
		serverError(ctx, fmt.Errorf("listing command failed: %s", err))
		return
	}

	buf, _ := json.Marshal(metrics)
	ctx.Write(buf)
	ctx.SetContentType("application/json; charset=utf8")
}

func indexHandler(ctx *fasthttp.RequestCtx) {
	io.WriteString(ctx, indexHTML)
	ctx.SetContentType("text/html; charset=utf8")
}

func routeHandler(ctx *fasthttp.RequestCtx, query *fasthttp.Args) {
	p := ctx.Path()
	// priority order
	if bytes.Equal(p, []byte("/api/v1/xport")) {
		xportHandler(ctx, query)
	} else if bytes.Equal(p, []byte("/api/v1/graph")) {
		graphHandler(ctx, query)
	} else if bytes.Equal(p, []byte("/api/v1/ping")) {
		pingHandler(ctx)
	} else if bytes.Equal(p, []byte("/api/v1/list_metrics")) {
		listMetricsHandler(ctx, query)
	} else if bytes.Equal(p, []byte("/")) {
		indexHandler(ctx)
	} else {
		ctx.WriteString("404")
		ctx.SetStatusCode(404)
	}
}

func mainHandler(ctx *fasthttp.RequestCtx) {

	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Set("Access-Control-Allow-Methods", "*")
	ctx.Response.Header.Set("Access-Control-Allow-Headers", "*")
	ctx.Response.Header.Set("Access-Control-Allow-Credentials", "true")

	// The headers are enough for options requests.
	if ctx.IsOptions() {
		return
	}

	var queryBytes []byte
	var args *fasthttp.Args
	if ctx.IsPost() {
		args = ctx.PostArgs()
		queryBytes = ctx.Request.Body()
	} else {
		args = ctx.QueryArgs()
		queryBytes = ctx.URI().QueryString()
	}

	expiryBytes := args.Peek("x")
	if expiryBytes != nil {
		expiry, err := strconv.ParseInt(string(expiryBytes), 10, 64)
		if err != nil || expiry < time.Now().Unix() {
			ctx.WriteString("request has expired")
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			return
		}
		args.Del("x")
	}

	sig := args.Peek("s")
	if sig != nil {
		args.Del("s")
		if !querysign.ValidateSignedQuery(Config.signedQuerySecretBytes, ctx.Path(), queryBytes) {
			ctx.WriteString("signature failure")
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			return
		}
		// Bypass basic auth only if a secret has been set.
		if len(Config.signedQuerySecretBytes) != 0 {
			routeHandler(ctx, args)
			return
		}
	}

	// Handle basic auth.
	basicAuthPrefix := []byte("Basic ")
	auth := ctx.Request.Header.Peek("Authorization")
	if bytes.HasPrefix(auth, basicAuthPrefix) {
		payload, err := base64.StdEncoding.DecodeString(string(auth[len(basicAuthPrefix):]))
		if err == nil {
			pair := bytes.SplitN(payload, []byte(":"), 2)
			if len(pair) == 2 &&
				passwords != nil &&
				passwords.Match(string(pair[0]), string(pair[1])) {
				routeHandler(ctx, args)
				return
			}
		}
	}

	if Config.AllowUnauthenticatedAccess() {
		routeHandler(ctx, args)
		return
	}

	// All auth methods have failed at this point.
	if passwords != nil {
		ctx.Response.Header.Set("WWW-Authenticate", "Basic")
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.WriteString("unauthorized")
	} else {
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.WriteString("forbidden")
	}

}

func logHandler(ctx *fasthttp.RequestCtx) {
	begin := time.Now()
	mainHandler(ctx)
	end := time.Now()
	log.Printf("id=%d method=%s path=%s status=%v duration=%v",
		ctx.ID(),
		ctx.Method(),
		ctx.Path(),
		ctx.Response.Header.StatusCode(),
		end.Sub(begin),
	)
}

//go:embed example/defaults.cfg
var defaultConfig string

//go:embed index.html
var indexHTML string

func main() {

	var (
		ConfigFilePath     = flag.String("config", "", "Path to the configuration file.")
		PrintDefaultConfig = flag.Bool("print-default-config", false, "Print the default config file and exit.")
		SignQuery          = flag.String("sign-query", "", "Sign a \"$path?$query\" string and print the result (useful for debugging signed requests).")
	)

	flag.Parse()

	if *PrintDefaultConfig {
		fmt.Print(defaultConfig)
		return
	}

	if *ConfigFilePath != "" {
		tomlData, err := toml.DecodeFile(*ConfigFilePath, &Config)
		if err != nil {
			log.Fatalf("unable to read configuration: %s", err)
		}
		hadUndecoded := false
		for _, k := range tomlData.Undecoded() {
			log.Printf("unknown config key: %s", k.String())
			hadUndecoded = true
		}
		if hadUndecoded {
			log.Fatalf("aborting due to invalid configuration.")
		}
	}

	err := Config.PopulateMissing()
	if err != nil {
		// Don't use logging to print this initial error, it looks nicer.
		fmt.Fprintf(os.Stderr, "unable to load config: %s", err)
		os.Exit(1)
	}

	if toSign := *SignQuery; toSign != "" {
		qIdx := strings.IndexRune(toSign, '?')
		if qIdx == -1 {
			fmt.Fprint(os.Stderr, "can only sign queries containing '?'")
			os.Exit(1)
		}
		signedQuery := querysign.SignQuery(
			Config.signedQuerySecretBytes,
			[]byte(toSign[:qIdx]),
			[]byte(toSign[qIdx+1:]),
		)
		fmt.Printf("%s?%s", toSign[:qIdx], signedQuery)
		return
	}

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

	if Config.BasicAuthHtpasswdFile != "" {
		pwds, err := htpasswd.New(Config.BasicAuthHtpasswdFile, htpasswd.DefaultSystems, nil)
		if err != nil {
			log.Fatalf("error loading basic auth passwords: %s", err)
		}
		passwords = pwds
	}

	log.Printf("listening on %s", Config.ListenAddress)
	srv := &fasthttp.Server{
		Handler: logHandler,
		Name:    "rrdsrv",
	}

	if err := srv.ListenAndServe(Config.ListenAddress); err != nil {
		log.Fatalf("error in ListenAndServe: %s", err)
	}
}
