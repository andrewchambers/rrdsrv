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
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/alessio/shellescape"
	"github.com/andrewchambers/rrdsrv/equery"
	"github.com/andrewchambers/rrdsrv/rrdtool"
	"github.com/anmitsu/go-shlex"
	"github.com/tg123/go-htpasswd"
	"github.com/valyala/fasthttp"

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
	Shell                     string         `toml:"shell_path"`
	ListenAddress             string         `toml:"listen_address"`
	BasicAuthHtpasswdFile     string         `toml:"basic_auth_htpasswd_file"`
	EncryptedQuerySecret      string         `toml:"encrypted_query_secret"`
	EncryptedQuerySecretFile  string         `toml:"encrypted_query_secret_file"`
	encryptedQueryKey         equery.Key
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
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = "127.0.0.1:9191"
	}
	if cfg.Shell == "" {
		cfg.Shell = "/bin/sh"
	}

	if cfg.EncryptedQuerySecretFile != "" {
		secret, err := ioutil.ReadFile(cfg.EncryptedQuerySecretFile)
		if err != nil {
			return fmt.Errorf("unable to load encrypted_query_secret_file: %s", err)
		}
		cfg.EncryptedQuerySecret = string(secret)
	}

	if cfg.EncryptedQuerySecret != "" {
		cfg.encryptedQueryKey = equery.KeyFromSecret(cfg.EncryptedQuerySecret)
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

//go:embed index.html
var indexHTML string

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
	} else if bytes.Equal(p, []byte("/")) {
		indexHandler(ctx)
	} else {
		ctx.WriteString("404")
		ctx.SetStatusCode(404)
	}
}

func authHandler(ctx *fasthttp.RequestCtx) {

	query := ctx.QueryArgs()
	eQuery := query.Peek("e")
	// Handle encrypted query.
	if eQuery != nil && query.Len() == 1 {
		log.Printf("%s", eQuery)
		decrypted, ok := equery.DecryptBytesWithKey(&Config.encryptedQueryKey, eQuery)
		if !ok {
			ctx.WriteString("invalid encrypted query")
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			return
		}
		decryptedQuery := fasthttp.AcquireArgs()
		defer fasthttp.ReleaseArgs(decryptedQuery)

		decryptedQuery.ParseBytes(decrypted)

		expiryStr := string(decryptedQuery.Peek("x"))
		if expiryStr != "" {
			expiry, err := strconv.ParseInt(expiryStr, 10, 64)
			if err != nil || time.Now().Unix() > expiry {
				ctx.WriteString("encrypted query has expired")
				ctx.SetStatusCode(fasthttp.StatusUnauthorized)
				return
			}
		}

		if !bytes.HasSuffix(ctx.Path(), decryptedQuery.Peek("p")) {
			ctx.WriteString("encrypted query is for different endpoint")
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			return
		}

		decryptedQuery.Del("x")
		decryptedQuery.Del("p")
		routeHandler(ctx, decryptedQuery)
		return
	}

	if passwords == nil {
		routeHandler(ctx, query)
		return
	}

	// Handle basic auth.
	basicAuthPrefix := []byte("Basic ")
	auth := ctx.Request.Header.Peek("Authorization")
	if bytes.HasPrefix(auth, basicAuthPrefix) {
		payload, err := base64.StdEncoding.DecodeString(string(auth[len(basicAuthPrefix):]))
		if err == nil {
			pair := bytes.SplitN(payload, []byte(":"), 2)
			if len(pair) == 2 &&
				passwords.Match(string(pair[0]), string(pair[1])) {
				routeHandler(ctx, query)
				return
			}
		}
	}
	ctx.Response.Header.Set("WWW-Authenticate", "Basic")
	ctx.SetStatusCode(fasthttp.StatusUnauthorized)
}

func logHandler(ctx *fasthttp.RequestCtx) {
	begin := time.Now()
	authHandler(ctx)
	end := time.Now()
	log.Printf("%s %s - %v - %v",
		ctx.Method(),
		ctx.Path(),
		ctx.Response.Header.StatusCode(),
		end.Sub(begin),
	)
}

func main() {

	var (
		ConfigFilePath  = flag.String("config", "", "Path to the configuration file.")
		EncryptQueryArg = flag.String("encrypt-query", "", "Print encrypted url query string and exit.")
		DecryptQueryArg = flag.String("decrypt-query", "", "Print decrypted url query string and exit.")
	)

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

	err := Config.PopulateMissing()
	if err != nil {
		// Don't use logging to print this initial error, it looks nicer.
		fmt.Fprintf(os.Stderr, "unable to load config: %s", err)
		os.Exit(1)
	}

	if *EncryptQueryArg != "" {
		toEncrypt := *EncryptQueryArg
		if strings.HasPrefix(toEncrypt, "?") {
			toEncrypt = toEncrypt[1:]
		}
		fmt.Printf("?e=%s\n", equery.EncryptWithKey(&Config.encryptedQueryKey, toEncrypt))
		return
	}

	if *DecryptQueryArg != "" {
		toDecrypt := *DecryptQueryArg
		if strings.HasPrefix(toDecrypt, "?e=") {
			toDecrypt = toDecrypt[3:]
		}
		q, ok := equery.DecryptWithKey(&Config.encryptedQueryKey, toDecrypt)
		if !ok {
			fmt.Fprint(os.Stderr, "unable to decrypt: invalid query string or mismatched secret")
			os.Exit(1)
		}
		fmt.Printf("%s\n", q)
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
