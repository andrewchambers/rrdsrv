package rrdtool

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"container/list"
)

type RemoteControl struct {
	commandTimeout time.Duration
	inp            *os.File
	outp           *os.File
	scanner        *bufio.Scanner
	cmd            *exec.Cmd
	argBuf         bytes.Buffer
	OnStdout       func([]byte)
}

func rrdtoolFmtArgs(buf *bytes.Buffer, args []string) error {
	buf.Reset()
	for i, a := range args {
		if i != 0 {
			_ = buf.WriteByte(' ')
		}
		needsQuote := false
		for _, b := range a {
			if b == ' ' {
				needsQuote = true
				break
			}
			// rrd_tool.c does not support any sort of escaping.
			if b == '\'' || b == '"' || b == '\n' {
				return fmt.Errorf("unable to quote %q for rrdtool remote control", a)
			}
		}
		if needsQuote {
			_ = buf.WriteByte('\'')
			_, _ = buf.WriteString(a)
			_ = buf.WriteByte('\'')
		} else {
			_, _ = buf.WriteString(a)
		}
	}
	_ = buf.WriteByte('\n')
	return nil
}

func (rc *RemoteControl) RunCommand(args []string) error {
	timeout := time.AfterFunc(rc.commandTimeout, func() {
		_ = rc.Kill()
	})
	defer timeout.Stop()

	err := rrdtoolFmtArgs(&rc.argBuf, args)
	if err != nil {
		return err
	}

	_, err = rc.inp.Write(rc.argBuf.Bytes())
	if err != nil {
		return err
	}

	for rc.scanner.Scan() {
		buf := rc.scanner.Bytes()
		if (len(buf) >= 3) &&
			(buf[0] == 'O') &&
			(buf[1] == 'K') &&
			(buf[2] == ' ') {
			return nil
		}
		if (len(buf) >= 7) &&
			(buf[0] == 'E') &&
			(buf[1] == 'R') &&
			(buf[2] == 'R') &&
			(buf[3] == 'O') &&
			(buf[4] == 'R') &&
			(buf[5] == ':') &&
			(buf[6] == ' ') {
			return errors.New(rc.scanner.Text())
		}

		if rc.OnStdout != nil {
			rc.OnStdout(buf)
		}
	}
	err = rc.scanner.Err()
	if err != nil {
		return fmt.Errorf("unable to read rrdtool command output: %s", err)
	}

	return fmt.Errorf("unexpected end of command output")
}

func (rc *RemoteControl) Kill() error {
	if rc.cmd.Process == nil {
		return nil
	}
	_ = rc.inp.Close()
	_ = rc.outp.Close()
	_ = rc.cmd.Process.Kill()
	return nil
}

func (rc *RemoteControl) Signal(sig os.Signal) error {
	if rc.cmd.Process == nil {
		return nil
	}
	return rc.cmd.Process.Signal(sig)
}

func (rc *RemoteControl) Close() error {
	_ = rc.inp.Close()
	_ = rc.outp.Close()

	timeout := time.AfterFunc(rc.commandTimeout, func() {
		_ = rc.Kill()
	})
	defer timeout.Stop()

	return rc.cmd.Wait()
}

type RemoteControlOptions struct {
	CommandTimeout time.Duration
	Stderr         *os.File
	OnStdout       func([]byte)
	LaunchCommand  []string
}

func StartRemoteControl(ctx context.Context, opts RemoteControlOptions) (*RemoteControl, error) {

	if opts.CommandTimeout == 0 {
		opts.CommandTimeout = 30 * time.Minute
	}

	if len(opts.LaunchCommand) == 0 {
		opts.LaunchCommand = []string{"rrdtool", "-"}
	}

	var cmd *exec.Cmd

	switch len(opts.LaunchCommand) {
	case 1:
		cmd = exec.CommandContext(ctx, opts.LaunchCommand[0])
	default:
		cmd = exec.CommandContext(ctx, opts.LaunchCommand[0], opts.LaunchCommand[1:]...)
	}

	p1, p2, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	p3, p4, err := os.Pipe()
	if err != nil {
		_ = p1.Close()
		_ = p2.Close()
		return nil, err
	}

	cmd.Stdin = p1
	cmd.Stdout = p4
	cmd.Stderr = opts.Stderr

	err = cmd.Start()
	if err != nil {
		_ = p1.Close()
		_ = p2.Close()
		_ = p3.Close()
		_ = p4.Close()
		return nil, err
	}

	_ = p1.Close()
	_ = p4.Close()

	return &RemoteControl{
		commandTimeout: opts.CommandTimeout,
		inp:            p2,
		outp:           p3,
		scanner:        bufio.NewScanner(p3),
		cmd:            cmd,
		OnStdout:       opts.OnStdout,
	}, nil
}

type PoolOptions struct {
	RemoteControlOptions RemoteControlOptions
	MaxSize              int
	AttritionDelay       time.Duration
}

type RemoteControlPool struct {
	opts                PoolOptions
	rrdToolFreeListLock sync.Mutex
	rrdToolFreeList     *list.List
	attritionTicker     *time.Ticker
	attritionMarker     int32
	workerWg            sync.WaitGroup
	ctx                 context.Context
	cancel              func()
}

func NewPool(ctx context.Context, opts PoolOptions) *RemoteControlPool {

	ctx, cancel := context.WithCancel(ctx)

	if opts.AttritionDelay == 0 {
		opts.AttritionDelay = 300 * time.Second
	}

	if opts.MaxSize <= 0 {
		opts.MaxSize = 8
	}

	p := &RemoteControlPool{
		opts:            opts,
		rrdToolFreeList: list.New(),
		ctx:             ctx,
		cancel:          cancel,
		attritionTicker: time.NewTicker(opts.AttritionDelay),
		attritionMarker: 0,
	}

	p.workerWg.Add(1)
	go func() {
		defer p.workerWg.Done()
		defer p.attritionTicker.Stop()
		for {
			select {
			case <-p.attritionTicker.C:
				if atomic.SwapInt32(&p.attritionMarker, 0) == 0 {
					p.rrdToolFreeListLock.Lock()
					l := p.rrdToolFreeList.Len()
					if l != 0 {
						rc := p.rrdToolFreeList.Remove(p.rrdToolFreeList.Front()).(*RemoteControl)
						_ = rc.Close()
					}
					p.rrdToolFreeListLock.Unlock()
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return p
}

func (p *RemoteControlPool) Get() (*RemoteControl, error) {

	select {
	case <-p.ctx.Done():
		return nil, errors.New("rrd tool pool closed")
	default:
	}

	atomic.StoreInt32(&p.attritionMarker, 1)

	p.rrdToolFreeListLock.Lock()

	if p.rrdToolFreeList.Len() == 0 {
		p.rrdToolFreeListLock.Unlock()
		return StartRemoteControl(p.ctx, p.opts.RemoteControlOptions)
	}
	rc := p.rrdToolFreeList.Remove(p.rrdToolFreeList.Front()).(*RemoteControl)
	rc.OnStdout = nil
	p.rrdToolFreeListLock.Unlock()

	err := rc.RunCommand([]string{"pwd"})
	if err != nil {
		_ = rc.Close()
		return StartRemoteControl(p.ctx, p.opts.RemoteControlOptions)
	}
	return rc, nil
}

func (p *RemoteControlPool) Recycle(rc *RemoteControl) {
	p.rrdToolFreeListLock.Lock()
	defer p.rrdToolFreeListLock.Unlock()
	if p.rrdToolFreeList.Len() < p.opts.MaxSize {
		p.rrdToolFreeList.PushBack(rc)
	} else {
		_ = rc.Close()
	}
}

func (p *RemoteControlPool) Close() {
	p.cancel()
	p.workerWg.Wait()

	p.rrdToolFreeListLock.Lock()
	defer p.rrdToolFreeListLock.Unlock()

	for p.rrdToolFreeList.Len() != 0 {
		rc := p.rrdToolFreeList.Remove(p.rrdToolFreeList.Front()).(*RemoteControl)
		rc.Close()
	}
}
