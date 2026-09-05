package main

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/codec"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"github.com/zhh2001/p4runtime-go-controller/tableentry"
	"google.golang.org/protobuf/proto"
)

const (
	routeTableName      = "IngressImpl.ipv4_lpm"
	routeFieldName      = "hdr.ipv4.dst_addr"
	forwardActionName   = "IngressImpl.ipv4_forward"
	configTableName     = "IngressImpl.sketch_config"
	thresholdActionName = "IngressImpl.set_threshold"
)

type routeSpec struct {
	prefix string
	dstMAC string
	srcMAC string
	port   uint64
}

var topologyRoutes = []routeSpec{
	{prefix: "10.0.1.0", dstMAC: "08:00:00:00:01:11", srcMAC: "08:00:00:00:01:00", port: 1},
	{prefix: "10.0.2.0", dstMAC: "08:00:00:00:02:22", srcMAC: "08:00:00:00:02:00", port: 2},
	{prefix: "10.0.3.0", dstMAC: "08:00:00:00:03:33", srcMAC: "08:00:00:00:03:00", port: 3},
}

type staticConfig struct {
	routes    []*p4v1.TableEntry
	threshold *p4v1.TableEntry
}

type runtimeAPI interface {
	SetPipeline(context.Context, *pipeline.Pipeline, client.SetPipelineOptions) (client.SetPipelineResult, error)
	GetPipeline(context.Context) (*pipeline.Pipeline, error)
	Write(context.Context, client.WriteOptions, ...*p4v1.Update) error
	ReadTableEntries(context.Context, uint32) ([]*p4v1.TableEntry, error)
	Read(context.Context, ...*p4v1.Entity) ([]*p4v1.Entity, error)
}

func applyConfiguration(
	ctx context.Context,
	api runtimeAPI,
	p *pipeline.Pipeline,
	threshold uint32,
	verifyOnly bool,
) error {
	config, err := buildStaticConfig(p, threshold)
	if err != nil {
		return err
	}

	if !verifyOnly {
		result, err := api.SetPipeline(ctx, p, client.SetPipelineOptions{
			Action:     client.PipelineVerifyAndCommit,
			NoFallback: true,
		})
		if err != nil {
			return fmt.Errorf("install pipeline: %w", err)
		}
		if result.Action != client.PipelineVerifyAndCommit {
			return fmt.Errorf("install pipeline: target used action %v", result.Action)
		}

		updates := make([]*p4v1.Update, 0, len(config.routes)+1)
		for _, route := range config.routes {
			updates = append(updates, client.TableEntryUpdate(client.UpdateInsert, route))
		}
		updates = append(updates, client.TableEntryUpdate(client.UpdateModify, config.threshold))
		if err := api.Write(ctx, client.WriteOptions{
			Atomicity: client.AtomicityContinueOnError,
		}, updates...); err != nil {
			return fmt.Errorf("write static configuration: %w", err)
		}
	}

	if err := verifyStaticState(ctx, api, p, config); err != nil {
		return fmt.Errorf("verify static configuration: %w", err)
	}
	return nil
}

func buildStaticConfig(p *pipeline.Pipeline, threshold uint32) (staticConfig, error) {
	if threshold == 0 {
		return staticConfig{}, fmt.Errorf("threshold must be nonzero")
	}
	config := staticConfig{routes: make([]*p4v1.TableEntry, 0, len(topologyRoutes))}
	for _, spec := range topologyRoutes {
		prefix, err := codec.IPv4(spec.prefix)
		if err != nil {
			return staticConfig{}, fmt.Errorf("route %s/24: %w", spec.prefix, err)
		}
		dstMAC, err := codec.MAC(spec.dstMAC)
		if err != nil {
			return staticConfig{}, fmt.Errorf("route %s/24 destination MAC: %w", spec.prefix, err)
		}
		srcMAC, err := codec.MAC(spec.srcMAC)
		if err != nil {
			return staticConfig{}, fmt.Errorf("route %s/24 source MAC: %w", spec.prefix, err)
		}
		port, err := codec.EncodeUint(spec.port, 9)
		if err != nil {
			return staticConfig{}, fmt.Errorf("route %s/24 port: %w", spec.prefix, err)
		}

		entry, err := tableentry.NewBuilder(p, routeTableName).
			Match(routeFieldName, tableentry.LPM(prefix, 24)).
			Action(forwardActionName,
				tableentry.Param("dst_mac", dstMAC),
				tableentry.Param("src_mac", srcMAC),
				tableentry.Param("port", port)).
			Build()
		if err != nil {
			return staticConfig{}, fmt.Errorf("build route %s/24: %w", spec.prefix, err)
		}
		config.routes = append(config.routes, entry)
	}

	value, err := codec.EncodeUint(uint64(threshold), 32)
	if err != nil {
		return staticConfig{}, fmt.Errorf("encode threshold: %w", err)
	}
	config.threshold, err = tableentry.NewBuilder(p, configTableName).
		AsDefault().
		Action(thresholdActionName, tableentry.Param("value", value)).
		Build()
	if err != nil {
		return staticConfig{}, fmt.Errorf("build threshold configuration: %w", err)
	}
	return config, nil
}

func verifyStaticState(
	ctx context.Context,
	api runtimeAPI,
	expectedPipeline *pipeline.Pipeline,
	expected staticConfig,
) error {
	actualPipeline, err := api.GetPipeline(ctx)
	if err != nil {
		return fmt.Errorf("read pipeline: %w", err)
	}
	if err := comparePipelines(expectedPipeline, actualPipeline); err != nil {
		return err
	}

	routeTable, ok := expectedPipeline.Table(routeTableName)
	if !ok {
		return fmt.Errorf("P4Info has no table %q", routeTableName)
	}
	routes, err := api.ReadTableEntries(ctx, routeTable.ID)
	if err != nil {
		return fmt.Errorf("read routes: %w", err)
	}
	if err := compareTableEntries("routes", expected.routes, routes); err != nil {
		return err
	}

	configTable, ok := expectedPipeline.Table(configTableName)
	if !ok {
		return fmt.Errorf("P4Info has no table %q", configTableName)
	}
	regularConfigEntries, err := api.ReadTableEntries(ctx, configTable.ID)
	if err != nil {
		return fmt.Errorf("read non-default sketch configuration: %w", err)
	}
	if err := compareTableEntries("non-default sketch configuration", nil, regularConfigEntries); err != nil {
		return err
	}

	selector := &p4v1.Entity{Entity: &p4v1.Entity_TableEntry{
		TableEntry: &p4v1.TableEntry{
			TableId:         configTable.ID,
			IsDefaultAction: true,
		},
	}}
	entities, err := api.Read(ctx, selector)
	if err != nil {
		return fmt.Errorf("read sketch threshold: %w", err)
	}
	defaults := make([]*p4v1.TableEntry, 0, len(entities))
	for _, entity := range entities {
		entry := entity.GetTableEntry()
		if entry == nil {
			return fmt.Errorf("read sketch threshold: target returned a non-table entity")
		}
		defaults = append(defaults, entry)
	}
	if err := compareTableEntries("sketch threshold", []*p4v1.TableEntry{expected.threshold}, defaults); err != nil {
		return err
	}
	return nil
}

func comparePipelines(expected, actual *pipeline.Pipeline) error {
	if actual == nil {
		return fmt.Errorf("pipeline readback is empty")
	}
	if !proto.Equal(expected.Info(), actual.Info()) {
		return fmt.Errorf("P4Info readback mismatch")
	}
	if !bytes.Equal(expected.DeviceConfig(), actual.DeviceConfig()) {
		return fmt.Errorf("device config readback mismatch")
	}
	return nil
}

func compareTableEntries(label string, expected, actual []*p4v1.TableEntry) error {
	expectedByKey := make(map[string]*p4v1.TableEntry, len(expected))
	for _, entry := range expected {
		key, normalized, err := indexedEntry(entry)
		if err != nil {
			return fmt.Errorf("%s expected entry: %w", label, err)
		}
		if _, exists := expectedByKey[key]; exists {
			return fmt.Errorf("%s expected state contains a duplicate key", label)
		}
		expectedByKey[key] = normalized
	}

	actualByKey := make(map[string][]*p4v1.TableEntry, len(actual))
	for _, entry := range actual {
		key, normalized, err := indexedEntry(entry)
		if err != nil {
			return fmt.Errorf("%s readback entry: %w", label, err)
		}
		actualByKey[key] = append(actualByKey[key], normalized)
	}

	missing, wrong := 0, 0
	for key, want := range expectedByKey {
		candidates := actualByKey[key]
		if len(candidates) == 0 {
			missing++
			continue
		}
		match := -1
		for index, candidate := range candidates {
			if proto.Equal(want, candidate) {
				match = index
				break
			}
		}
		if match < 0 {
			wrong++
			match = 0
		}
		actualByKey[key] = append(candidates[:match], candidates[match+1:]...)
	}

	extra := 0
	for _, entries := range actualByKey {
		extra += len(entries)
	}
	if missing != 0 || wrong != 0 || extra != 0 {
		return fmt.Errorf("%s readback mismatch: missing=%d wrong=%d extra=%d", label, missing, wrong, extra)
	}
	return nil
}

func indexedEntry(entry *p4v1.TableEntry) (string, *p4v1.TableEntry, error) {
	if entry == nil {
		return "", nil, fmt.Errorf("nil table entry")
	}
	normalized := proto.Clone(entry).(*p4v1.TableEntry)
	sort.Slice(normalized.Match, func(i, j int) bool {
		return normalized.Match[i].FieldId < normalized.Match[j].FieldId
	})
	if action := normalized.GetAction().GetAction(); action != nil {
		sort.Slice(action.Params, func(i, j int) bool {
			return action.Params[i].ParamId < action.Params[j].ParamId
		})
	}

	identity := &p4v1.TableEntry{
		TableId:         normalized.TableId,
		Match:           normalized.Match,
		Priority:        normalized.Priority,
		IsDefaultAction: normalized.IsDefaultAction,
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(identity)
	if err != nil {
		return "", nil, fmt.Errorf("encode table key: %w", err)
	}
	return string(encoded), normalized, nil
}
