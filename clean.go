package main

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/anmitsu/go-shlex"
)

type CleanOpts struct {
	RRDRootPath string
}

const rrdDEFRegexpS = "^DEF:([\\-_a-zA-Z0-9]{0,255})=([^:]+):([\\-_a-zA-Z0-9]{0,255}):?(.*$)"

var rrdDEFRegexp *regexp.Regexp = regexp.MustCompile(rrdDEFRegexpS)

var validDefOptPrefixes = []string{
	"start=",
	"step=",
	"end=",
	"reduce=",
}

func cleanDEF(def string, opts CleanOpts) (string, error) {
	fields := rrdDEFRegexp.FindSubmatch([]byte(def))
	if fields == nil {
		return "", fmt.Errorf("expected %q did not match %s", def, rrdDEFRegexpS)
	}

	vName := string(fields[1])
	rrdPath := string(fields[2])
	dsName := string(fields[3])
	rest := string(fields[4])

	// We have already disallowed quotation, so simple splitting seems sufficient.
	restParts := strings.Split(rest, ":")

	// Use an allow list, it is more secure than a block list.
	for _, restPart := range restParts {
		if restPart == "MIN" || restPart == "MAX" || restPart == "AVERAGE" {
			continue
		}
		hasAllowedPrefix := false
		for _, pfx := range validDefOptPrefixes {
			if strings.HasPrefix(restPart, pfx) {
				hasAllowedPrefix = true
				break
			}
		}
		if !hasAllowedPrefix {
			return "", fmt.Errorf("DEF option %q is forbidden", restPart)
		}
	}

	rrdPath = path.Clean(rrdPath)

	if strings.Contains(rrdPath, "..") {
		return "", fmt.Errorf("\"..\" is not allowed in rrdPath (path %q)", rrdPath)
	}

	if !strings.HasSuffix(rrdPath, ".rrd") {
		return "", fmt.Errorf("rrd path must end in .rrd (from %q)", def)
	}

	rrdPath = path.Join(opts.RRDRootPath, rrdPath)

	return fmt.Sprintf("DEF:%s=%s:%s:%s", vName, rrdPath, dsName, rest), nil
}

func cleanXportArg(arg string, opts CleanOpts) (string, error) {
	for _, b := range arg {
		switch b {
		// This is more restrictive than needed
		// but better safe than sorry for now.
		// To relax the quotation rules we need to
		// fully understand how rrdtool handles escapes.
		case 0, '\n', '"', '\'', '\\':
			return "", fmt.Errorf("%q contains forbidden byte %q", arg, b)
		default:
		}
	}
	if strings.HasPrefix(arg, "DEF:") {
		return cleanDEF(arg, opts)
	} else if strings.HasPrefix(arg, "CDEF:") {
		return arg, nil
	} else if strings.HasPrefix(arg, "VDEF:") {
		return arg, nil
	} else if strings.HasPrefix(arg, "XPORT:") {
		return arg, nil
	} else {
		return "", fmt.Errorf("expected DEF, CDEF, VDEF or XPORT, got %q", arg)
	}
}

func CleanXport(xportQueryString string, opts CleanOpts) ([]string, error) {
	xportSplitArgs, err := shlex.Split(xportQueryString, true)
	if err != nil {
		return nil, err
	}
	for i := range xportSplitArgs {
		cleaned, err := cleanXportArg(xportSplitArgs[i], opts)
		if err != nil {
			return nil, err
		}
		xportSplitArgs[i] = cleaned
	}
	return xportSplitArgs, nil
}
