package main

import (
	"context"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	p4configv1 "github.com/p4lang/p4runtime/go/p4/config/v1"
	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/codec"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"google.golang.org/protobuf/proto"
)

const (
	testForwardActionID   = 0x01000001
	testThresholdActionID = 0x01000002
	testDropActionID      = 0x01000003
	testRouteTableID      = 0x02000001
	testConfigTableID     = 0x02000002
)

func testPipeline(t *testing.T, deviceConfig []byte) *pipeline.Pipeline {
	t.Helper()
	info := &p4configv1.P4Info{
		Actions: []*p4configv1.Action{
			{
				Preamble: &p4configv1.Preamble{Id: testForwardActionID, Name: forwardActionName},
				Params: []*p4configv1.Action_Param{
					{Id: 1, Name: "dst_mac", Bitwidth: 48},
					{Id: 2, Name: "src_mac", Bitwidth: 48},
					{Id: 3, Name: "port", Bitwidth: 9},
				},
			},
			{
				Preamble: &p4configv1.Preamble{Id: testThresholdActionID, Name: thresholdActionName},
				Params: []*p4configv1.Action_Param{
					{Id: 1, Name: "value", Bitwidth: 32},
				},
			},
			{Preamble: &p4configv1.Preamble{Id: testDropActionID, Name: "IngressImpl.drop"}},
		},
		Tables: []*p4configv1.Table{
			{
				Preamble: &p4configv1.Preamble{Id: testRouteTableID, Name: routeTableName},
				MatchFields: []*p4configv1.MatchField{
					{
						Id:       1,
						Name:     routeFieldName,
						Bitwidth: 32,
						Match: &p4configv1.MatchField_MatchType_{
							MatchType: p4configv1.MatchField_LPM,
						},
					},
				},
				ActionRefs: []*p4configv1.ActionRef{
					{Id: testForwardActionID},
					{Id: testDropActionID, Scope: p4configv1.ActionRef_DEFAULT_ONLY},
				},
				Size: 64,
			},
			{
				Preamble: &p4configv1.Preamble{Id: testConfigTableID, Name: configTableName},
				ActionRefs: []*p4configv1.ActionRef{
					{Id: testThresholdActionID, Scope: p4configv1.ActionRef_DEFAULT_ONLY},
				},
			},
		},
	}
	p, err := pipeline.New(info, deviceConfig)
	if err != nil {
		t.Fatalf("create test pipeline: %v", err)
	}
	return p
}

func TestBuildStaticConfig(t *testing.T) {
	p := testPipeline(t, []byte("device config"))
	config, err := buildStaticConfig(p, 50)
	if err != nil {
		t.Fatalf("build static configuration: %v", err)
	}
	if len(config.routes) != 3 {
		t.Fatalf("route count = %d, want 3", len(config.routes))
	}

	wantPrefixes := []string{"10.0.1.0", "10.0.2.0", "10.0.3.0"}
	wantDstMACs := []string{"08:00:00:00:01:11", "08:00:00:00:02:22", "08:00:00:00:03:33"}
	wantSrcMACs := []string{"08:00:00:00:01:00", "08:00:00:00:02:00", "08:00:00:00:03:00"}
	for index, entry := range config.routes {
		if entry.TableId != testRouteTableID {
			t.Errorf("route %d table ID = %#x, want %#x", index, entry.TableId, testRouteTableID)
		}
		if len(entry.Match) != 1 {
			t.Fatalf("route %d match count = %d, want 1", index, len(entry.Match))
		}
		if entry.Match[0].FieldId != 1 {
			t.Errorf("route %d match field ID = %d, want 1", index, entry.Match[0].FieldId)
		}
		lpm := entry.Match[0].GetLpm()
		if lpm == nil || lpm.PrefixLen != 24 {
			t.Fatalf("route %d has invalid LPM match: %v", index, entry.Match[0])
		}
		if want := codec.MustIPv4(wantPrefixes[index]); !reflect.DeepEqual(lpm.Value, want) {
			t.Errorf("route %d prefix = %v, want %v", index, lpm.Value, want)
		}

		action := entry.GetAction().GetAction()
		if action == nil || action.ActionId != testForwardActionID || len(action.Params) != 3 {
			t.Fatalf("route %d has invalid action: %v", index, entry.Action)
		}
		params := make(map[uint32][]byte, len(action.Params))
		for _, param := range action.Params {
			params[param.ParamId] = param.Value
		}
		if want := codec.MustMAC(wantDstMACs[index]); !reflect.DeepEqual(params[1], want) {
			t.Errorf("route %d destination MAC = %v, want %v", index, params[1], want)
		}
		if want := codec.MustMAC(wantSrcMACs[index]); !reflect.DeepEqual(params[2], want) {
			t.Errorf("route %d source MAC = %v, want %v", index, params[2], want)
		}
		port, err := codec.DecodeUint(params[3])
		if err != nil {
			t.Fatalf("decode route %d port: %v", index, err)
		}
		if port != uint64(index+1) {
			t.Errorf("route %d port = %d, want %d", index, port, index+1)
		}
	}

	threshold := config.threshold
	if threshold.TableId != testConfigTableID || !threshold.IsDefaultAction {
		t.Fatalf("invalid threshold table entry: %v", threshold)
	}
	if len(threshold.Match) != 0 {
		t.Errorf("threshold entry has %d match fields, want 0", len(threshold.Match))
	}
	action := threshold.GetAction().GetAction()
	if action == nil || action.ActionId != testThresholdActionID || len(action.Params) != 1 || action.Params[0].ParamId != 1 {
		t.Fatalf("invalid threshold action: %v", threshold.Action)
	}
	value, err := codec.DecodeUint(action.Params[0].Value)
	if err != nil {
		t.Fatalf("decode threshold: %v", err)
	}
	if value != 50 {
		t.Errorf("threshold = %d, want 50", value)
	}

	if _, err := buildStaticConfig(p, 0); err == nil {
		t.Fatal("zero threshold unexpectedly accepted")
	}
}

func TestCompareTableEntries(t *testing.T) {
	p := testPipeline(t, nil)
	config, err := buildStaticConfig(p, 50)
	if err != nil {
		t.Fatal(err)
	}

	reordered := cloneEntries(config.routes)
	reordered[0], reordered[2] = reordered[2], reordered[0]
	if err := compareTableEntries("routes", config.routes, reordered); err != nil {
		t.Fatalf("reordered exact entries rejected: %v", err)
	}

	wrong := cloneEntries(config.routes)
	wrong[0].GetAction().GetAction().Params[2].Value = codec.MustEncodeUint(9, 9)
	assertMismatch(t, compareTableEntries("routes", config.routes, wrong), "missing=0 wrong=1 extra=0")

	missing := cloneEntries(config.routes[:2])
	assertMismatch(t, compareTableEntries("routes", config.routes, missing), "missing=1 wrong=0 extra=0")

	extra := append(cloneEntries(config.routes), proto.Clone(config.threshold).(*p4v1.TableEntry))
	assertMismatch(t, compareTableEntries("routes", config.routes, extra), "missing=0 wrong=0 extra=1")
}

func TestComparePipelines(t *testing.T) {
	expected := testPipeline(t, []byte("device config"))
	exact, err := pipeline.New(proto.Clone(expected.Info()).(*p4configv1.P4Info), expected.DeviceConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := comparePipelines(expected, exact); err != nil {
		t.Fatalf("equal pipelines rejected: %v", err)
	}

	wrongInfo := proto.Clone(expected.Info()).(*p4configv1.P4Info)
	wrongInfo.Tables[0].Preamble.Name = "IngressImpl.wrong"
	actual, err := pipeline.New(wrongInfo, expected.DeviceConfig())
	if err != nil {
		t.Fatal(err)
	}
	assertMismatch(t, comparePipelines(expected, actual), "P4Info readback mismatch")

	wrongConfig := testPipeline(t, []byte("wrong config"))
	assertMismatch(t, comparePipelines(expected, wrongConfig), "device config readback mismatch")
	assertMismatch(t, comparePipelines(expected, nil), "pipeline readback is empty")
}

func TestVerifyStaticState(t *testing.T) {
	p := testPipeline(t, []byte("device config"))
	api := fakeWithStaticState(t, p, 50)
	config, err := buildStaticConfig(p, 50)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyStaticState(context.Background(), api, p, config); err != nil {
		t.Fatalf("verify exact state: %v", err)
	}
	if want := []uint32{testRouteTableID, testConfigTableID}; !reflect.DeepEqual(api.tableReads, want) {
		t.Errorf("table reads = %v, want %v", api.tableReads, want)
	}
	if len(api.readSelectors) != 1 {
		t.Fatalf("default selectors = %d, want 1", len(api.readSelectors))
	}
	selector := api.readSelectors[0].GetTableEntry()
	if selector == nil || selector.TableId != testConfigTableID || !selector.IsDefaultAction {
		t.Errorf("invalid threshold selector: %v", api.readSelectors[0])
	}

	wrongThreshold := fakeWithStaticState(t, p, 50)
	entry := wrongThreshold.defaultEntities[0].GetTableEntry()
	entry.GetAction().GetAction().Params[0].Value = codec.MustEncodeUint(51, 32)
	assertMismatch(
		t,
		verifyStaticState(context.Background(), wrongThreshold, p, config),
		"sketch threshold readback mismatch: missing=0 wrong=1 extra=0",
	)

	extraConfig := fakeWithStaticState(t, p, 50)
	entry = proto.Clone(config.threshold).(*p4v1.TableEntry)
	entry.IsDefaultAction = false
	extraConfig.configEntries = []*p4v1.TableEntry{entry}
	assertMismatch(
		t,
		verifyStaticState(context.Background(), extraConfig, p, config),
		"non-default sketch configuration readback mismatch: missing=0 wrong=0 extra=1",
	)
}

func TestApplyConfigurationVerifyOnly(t *testing.T) {
	p := testPipeline(t, []byte("device config"))
	api := fakeWithStaticState(t, p, 50)
	if err := applyConfiguration(context.Background(), api, p, 50, true); err != nil {
		t.Fatalf("verify-only configuration: %v", err)
	}
	if len(api.setCalls) != 0 || len(api.writeCalls) != 0 {
		t.Fatalf("verify-only wrote state: set=%d write=%d", len(api.setCalls), len(api.writeCalls))
	}
	wantEvents := []string{"get-pipeline", "read-table", "read-table", "read-default"}
	if !reflect.DeepEqual(api.events, wantEvents) {
		t.Errorf("verify-only events = %v, want %v", api.events, wantEvents)
	}
}

func TestApplyConfigurationWritesStrictState(t *testing.T) {
	p := testPipeline(t, []byte("device config"))
	api := fakeWithStaticState(t, p, 50)
	if err := applyConfiguration(context.Background(), api, p, 50, false); err != nil {
		t.Fatalf("apply configuration: %v", err)
	}
	if len(api.setCalls) != 1 {
		t.Fatalf("pipeline writes = %d, want 1", len(api.setCalls))
	}
	set := api.setCalls[0]
	if set.pipeline != p || set.options.Action != client.PipelineVerifyAndCommit || !set.options.NoFallback {
		t.Errorf("pipeline write was not strict VERIFY_AND_COMMIT: %+v", set.options)
	}
	if len(api.writeCalls) != 1 {
		t.Fatalf("table writes = %d, want 1", len(api.writeCalls))
	}
	write := api.writeCalls[0]
	if write.options.Atomicity != client.AtomicityContinueOnError {
		t.Errorf("write atomicity = %v, want CONTINUE_ON_ERROR", write.options.Atomicity)
	}
	if len(write.updates) != 4 {
		t.Fatalf("updates = %d, want 4", len(write.updates))
	}

	writtenRoutes := make([]*p4v1.TableEntry, 0, 3)
	var writtenThreshold []*p4v1.TableEntry
	for index, update := range write.updates {
		entry := update.GetEntity().GetTableEntry()
		if entry == nil {
			t.Fatalf("update %d is not a table entry", index)
		}
		if index < 3 {
			if update.Type != p4v1.Update_INSERT {
				t.Errorf("route update %d type = %v, want INSERT", index, update.Type)
			}
			writtenRoutes = append(writtenRoutes, entry)
		} else {
			if update.Type != p4v1.Update_MODIFY {
				t.Errorf("threshold update type = %v, want MODIFY", update.Type)
			}
			writtenThreshold = append(writtenThreshold, entry)
		}
	}
	expected, err := buildStaticConfig(p, 50)
	if err != nil {
		t.Fatal(err)
	}
	if err := compareTableEntries("written routes", expected.routes, writtenRoutes); err != nil {
		t.Error(err)
	}
	if err := compareTableEntries("written threshold", []*p4v1.TableEntry{expected.threshold}, writtenThreshold); err != nil {
		t.Error(err)
	}
	wantEvents := []string{"set-pipeline", "write", "get-pipeline", "read-table", "read-table", "read-default"}
	if !reflect.DeepEqual(api.events, wantEvents) {
		t.Errorf("configuration events = %v, want %v", api.events, wantEvents)
	}
}

func TestValidateOptions(t *testing.T) {
	valid := commandOptions{
		address:      "127.0.0.1:50051",
		deviceID:     1,
		electionID:   1,
		threshold:    50,
		timeout:      time.Second,
		p4infoPath:   "p4info",
		deviceConfig: "device config",
	}
	if err := validateOptions(valid); err != nil {
		t.Fatalf("valid options rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*commandOptions)
	}{
		{name: "address", mutate: func(opts *commandOptions) { opts.address = "" }},
		{name: "device ID", mutate: func(opts *commandOptions) { opts.deviceID = 0 }},
		{name: "election ID", mutate: func(opts *commandOptions) { opts.electionID = 0 }},
		{name: "zero threshold", mutate: func(opts *commandOptions) { opts.threshold = 0 }},
		{name: "large threshold", mutate: func(opts *commandOptions) { opts.threshold = math.MaxUint32 + 1 }},
		{name: "timeout", mutate: func(opts *commandOptions) { opts.timeout = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := valid
			test.mutate(&opts)
			if err := validateOptions(opts); err == nil {
				t.Fatal("invalid options accepted")
			}
		})
	}
}

func assertMismatch(t *testing.T, err error, text string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q", text)
	}
	if !strings.Contains(err.Error(), text) {
		t.Fatalf("error = %q, want substring %q", err, text)
	}
}

func cloneEntries(entries []*p4v1.TableEntry) []*p4v1.TableEntry {
	cloned := make([]*p4v1.TableEntry, len(entries))
	for index, entry := range entries {
		cloned[index] = proto.Clone(entry).(*p4v1.TableEntry)
	}
	return cloned
}

type setCall struct {
	pipeline *pipeline.Pipeline
	options  client.SetPipelineOptions
}

type writeCall struct {
	options client.WriteOptions
	updates []*p4v1.Update
}

type fakeRuntime struct {
	pipeline        *pipeline.Pipeline
	routeEntries    []*p4v1.TableEntry
	configEntries   []*p4v1.TableEntry
	defaultEntities []*p4v1.Entity
	setCalls        []setCall
	writeCalls      []writeCall
	tableReads      []uint32
	readSelectors   []*p4v1.Entity
	events          []string
}

func fakeWithStaticState(t *testing.T, p *pipeline.Pipeline, threshold uint32) *fakeRuntime {
	t.Helper()
	config, err := buildStaticConfig(p, threshold)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeRuntime{
		pipeline:     p,
		routeEntries: cloneEntries(config.routes),
		defaultEntities: []*p4v1.Entity{
			{Entity: &p4v1.Entity_TableEntry{TableEntry: proto.Clone(config.threshold).(*p4v1.TableEntry)}},
		},
	}
}

func (f *fakeRuntime) SetPipeline(
	_ context.Context,
	p *pipeline.Pipeline,
	opts client.SetPipelineOptions,
) (client.SetPipelineResult, error) {
	f.events = append(f.events, "set-pipeline")
	f.setCalls = append(f.setCalls, setCall{pipeline: p, options: opts})
	return client.SetPipelineResult{Action: opts.Action, Attempted: []client.SetPipelineAction{opts.Action}}, nil
}

func (f *fakeRuntime) GetPipeline(context.Context) (*pipeline.Pipeline, error) {
	f.events = append(f.events, "get-pipeline")
	return f.pipeline, nil
}

func (f *fakeRuntime) Write(_ context.Context, opts client.WriteOptions, updates ...*p4v1.Update) error {
	f.events = append(f.events, "write")
	cloned := make([]*p4v1.Update, len(updates))
	for index, update := range updates {
		cloned[index] = proto.Clone(update).(*p4v1.Update)
	}
	f.writeCalls = append(f.writeCalls, writeCall{options: opts, updates: cloned})
	return nil
}

func (f *fakeRuntime) ReadTableEntries(_ context.Context, tableID uint32) ([]*p4v1.TableEntry, error) {
	f.events = append(f.events, "read-table")
	f.tableReads = append(f.tableReads, tableID)
	switch tableID {
	case testRouteTableID:
		return cloneEntries(f.routeEntries), nil
	case testConfigTableID:
		return cloneEntries(f.configEntries), nil
	default:
		return nil, nil
	}
}

func (f *fakeRuntime) Read(_ context.Context, selectors ...*p4v1.Entity) ([]*p4v1.Entity, error) {
	f.events = append(f.events, "read-default")
	for _, selector := range selectors {
		f.readSelectors = append(f.readSelectors, proto.Clone(selector).(*p4v1.Entity))
	}
	entities := make([]*p4v1.Entity, len(f.defaultEntities))
	for index, entity := range f.defaultEntities {
		entities[index] = proto.Clone(entity).(*p4v1.Entity)
	}
	return entities, nil
}
