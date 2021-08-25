package main

import (
	"reflect"
	"testing"
)

func TestCleanXport(t *testing.T) {

	opts := CleanOpts{
		RRDRootPath: "/rrd",
	}

	validQueries := []string{
		"DEF:v=memory-used.rrd:value:AVERAGE",
		"DEF:v=memory-used.rrd:value:AVERAGE:start=0",
	}

	invalidQueries := []string{
		"DEF:v=\\\"memory-used.rrd\\\":value:AVERAGE",
		"DEF:v=memory-used.rrd:value:AVERAGE:daemon=localhost",
		"DEF:v=memory-used.rrd:value:AVERAGE:foo=bar",
		"DEF:v=memory-used.rrd\\':value:AVERAGE",
		"DEF:v=../../memory-used.rrd:value:AVERAGE",
	}

	for _, q := range validQueries {
		_, err := CleanXport(q, opts)
		if err != nil {
			t.Fatalf("unexpected error %s for %q", err, q)
		}
	}

	for _, q := range invalidQueries {
		_, err := CleanXport(q, opts)
		if err == nil {
			t.Fatalf("expected an error for %q", q)
		}
	}

}

func TestCleanXportPath(t *testing.T) {
	opts := CleanOpts{
		RRDRootPath: "/rrd",
	}

	c, err := CleanXport("DEF:v=./memory-used.rrd:value:AVERAGE", opts)
	if err != nil {
		t.Fatal(err)
	}

	expected := []string{"DEF:v=/rrd/memory-used.rrd:value:AVERAGE"}

	if !reflect.DeepEqual(expected, c) {
		t.Fatalf("expected %v, got %v", expected, c)
	}
}
