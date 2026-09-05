package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
)

type commandOptions struct {
	address      string
	deviceID     uint64
	electionID   uint64
	p4infoPath   string
	deviceConfig string
	threshold    uint64
	timeout      time.Duration
	verifyOnly   bool
}

func main() {
	opts := parseOptions()
	if err := run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "controller: %v\n", err)
		os.Exit(1)
	}

	operation := "configured and verified"
	if opts.verifyOnly {
		operation = "verified"
	}
	fmt.Printf("%s pipeline, 3 routes, threshold %d\n", operation, opts.threshold)
}

func parseOptions() commandOptions {
	var opts commandOptions
	flag.StringVar(&opts.address, "p4runtime-addr", "127.0.0.1:50051", "P4Runtime address")
	flag.Uint64Var(&opts.deviceID, "device-id", 1, "P4Runtime device ID")
	flag.Uint64Var(&opts.electionID, "election-id", 1, "controller election ID")
	flag.StringVar(&opts.p4infoPath, "p4info", "build/count_min_sketch.p4info.txtpb", "P4Info textproto path")
	flag.StringVar(&opts.deviceConfig, "device-config", "build/count_min_sketch.json", "BMv2 JSON path")
	flag.Uint64Var(&opts.threshold, "threshold", 50, "heavy-hitter packet threshold")
	flag.DurationVar(&opts.timeout, "timeout", 10*time.Second, "configuration timeout")
	flag.BoolVar(&opts.verifyOnly, "verify-only", false, "verify existing state without writing")
	flag.Parse()
	return opts
}

func run(opts commandOptions) (err error) {
	if err := validateOptions(opts); err != nil {
		return err
	}

	p, err := loadPipeline(opts.p4infoPath, opts.deviceConfig)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	c, err := client.Dial(ctx, opts.address,
		client.WithDeviceID(opts.deviceID),
		client.WithElectionID(client.ElectionID{Low: opts.electionID}),
		client.WithInsecure(),
	)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", opts.address, err)
	}
	defer func() {
		if closeErr := c.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close P4Runtime connection: %w", closeErr)
		}
	}()

	if err := c.BecomePrimary(ctx); err != nil {
		return fmt.Errorf("become primary: %w", err)
	}
	return applyConfiguration(ctx, c, p, uint32(opts.threshold), opts.verifyOnly)
}

func validateOptions(opts commandOptions) error {
	if opts.address == "" {
		return fmt.Errorf("P4Runtime address is required")
	}
	if opts.deviceID == 0 {
		return fmt.Errorf("device ID must be nonzero")
	}
	if opts.electionID == 0 {
		return fmt.Errorf("election ID must be nonzero")
	}
	if opts.threshold == 0 {
		return fmt.Errorf("threshold must be nonzero")
	}
	if opts.threshold > math.MaxUint32 {
		return fmt.Errorf("threshold %d exceeds 32 bits", opts.threshold)
	}
	if opts.timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	return nil
}

func loadPipeline(p4infoPath, deviceConfigPath string) (*pipeline.Pipeline, error) {
	p4info, err := os.ReadFile(p4infoPath)
	if err != nil {
		return nil, fmt.Errorf("read P4Info %q: %w", p4infoPath, err)
	}
	deviceConfig, err := os.ReadFile(deviceConfigPath)
	if err != nil {
		return nil, fmt.Errorf("read device config %q: %w", deviceConfigPath, err)
	}
	p, err := pipeline.LoadText(p4info, deviceConfig)
	if err != nil {
		return nil, fmt.Errorf("load pipeline: %w", err)
	}
	return p, nil
}
