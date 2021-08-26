package rrdtool

import (
	"context"
	"testing"
	"time"
)

func TestRemoteControlSimpleTest(t *testing.T) {
	opts := RemoteControlOptions{}
	rc, err := StartRemoteControl(context.Background(), opts)
	if err != nil {
		t.Fatalf("%s", err)
	}
	err = rc.RunCommand([]string{"help"})
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestRemoteControlPoolSimpleTest(t *testing.T) {

	p := NewPool(context.Background(), PoolOptions{
		AttritionDelay: 10 * time.Millisecond,
	})

	rc, err := p.Get()
	if err != nil {
		t.Fatalf("%s", err)
	}
	err = rc.RunCommand([]string{"help"})
	if err != nil {
		t.Fatalf("%s", err)
	}
	p.Recycle(rc)

	rc, err = p.Get()
	if err != nil {
		t.Fatalf("%s", err)
	}
	err = rc.RunCommand([]string{"help"})
	if err != nil {
		t.Fatalf("%s", err)
	}
	p.Recycle(rc)

	time.Sleep(50 * time.Millisecond)

	p.Close()
}
