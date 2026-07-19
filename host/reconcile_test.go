package provisioner

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestPlanDiffUsesDeterministicFailClosedOrdering(t *testing.T) {
	updateOld := testRule(t, "F0000000AA01", "", 0x01)
	updateNew := testRule(t, "F0000000AA01", "", 0x00)
	obsoleteBroad := testRule(t, "F0000000BB01", "", 0x01)
	addRestricted := testRule(t, "F0000000BB01", make([]byte, 32), 0x01)
	addLater := testRule(t, "F0000000CC01", "", 0x01)

	plan, err := PlanDiff(
		[]Rule{obsoleteBroad, updateOld},
		[]Rule{addLater, updateNew, addRestricted},
		16,
	)
	if err != nil {
		t.Fatalf("PlanDiff: %v", err)
	}

	phases := make([]MutationPhase, len(plan.Mutations))
	for i, mutation := range plan.Mutations {
		phases[i] = mutation.Phase
		if mutation.Phase == PhaseUpdate || mutation.Phase == PhaseAdd {
			if got, want := mutation.Command[0], byte(0xF0); got != want {
				t.Fatalf("mutation %d command tag = %02X, want F0", i, got)
			}
			if int(mutation.Command[1])+2 != len(mutation.Command) {
				t.Fatalf("mutation %d is not one complete F0", i)
			}
		} else {
			if got, want := mutation.Command[0], byte(0xF1); got != want {
				t.Fatalf("mutation %d command tag = %02X, want F1", i, got)
			}
			if int(mutation.Command[1])+2 != len(mutation.Command) || len(mutation.Command)-2 != len(mutation.Key.AID)+len(mutation.Key.DeviceAppID)+6 {
				t.Fatalf("mutation %d is not one exact REF-DO F1", i)
			}
		}
	}
	want := []MutationPhase{PhaseUpdate, PhaseDelete, PhaseAdd, PhaseAdd}
	if !reflect.DeepEqual(phases, want) {
		t.Fatalf("phases = %v, want %v", phases, want)
	}
}

func TestPlanDiffRefusesCatchAllGrantWithoutOptIn(t *testing.T) {
	scoped := testRule(t, "F0000000AA01", "", 0x01)
	catchAllAllow := testRule(t, "", "", 0x01)

	_, err := PlanDiff(nil, []Rule{scoped, catchAllAllow}, 16)
	if err == nil {
		t.Fatal("PlanDiff accepted a catch-all allow without the opt-in")
	}
	if !strings.Contains(err.Error(), catchAllAllow.Identifier()) {
		t.Fatalf("error does not name the offending rule %s: %v", catchAllAllow.Identifier(), err)
	}
	if strings.Contains(err.Error(), scoped.Identifier()) {
		t.Fatalf("error names an unrelated rule: %v", err)
	}
}

func TestPlanDiffRefusesCatchAllApduFilterGrantWithoutOptIn(t *testing.T) {
	filtered, err := ParseRule(buildRuleWithAPDURule(nil, nil, bytes.Repeat([]byte{0xA0}, 8)))
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}

	if _, err := PlanDiff(nil, []Rule{filtered}, 16); err == nil {
		t.Fatal("PlanDiff accepted a catch-all APDU filter grant without the opt-in")
	}
}

func TestPlanDiffAcceptsCatchAllGrantWithOptIn(t *testing.T) {
	catchAllAllow := testRule(t, "", "", 0x01)

	plan, err := PlanDiff(nil, []Rule{catchAllAllow}, 16, AllowCatchAllGrants())
	if err != nil {
		t.Fatalf("PlanDiff with opt-in: %v", err)
	}
	if len(plan.Mutations) != 1 || plan.Mutations[0].Phase != PhaseAdd {
		t.Fatalf("unexpected plan: %+v", plan.Mutations)
	}
}

func TestPlanDiffAcceptsCatchAllDenyWithoutOptIn(t *testing.T) {
	catchAllDeny := testRule(t, "", "", 0x00)

	plan, err := PlanDiff(nil, []Rule{catchAllDeny}, 16)
	if err != nil {
		t.Fatalf("PlanDiff of a catch-all deny: %v", err)
	}
	if len(plan.Mutations) != 1 || plan.Mutations[0].Phase != PhaseAdd {
		t.Fatalf("unexpected plan: %+v", plan.Mutations)
	}
}

func TestPlanDiffRemovesAnExistingCatchAllGrantWithoutOptIn(t *testing.T) {
	catchAllAllow := testRule(t, "", "", 0x01)

	plan, err := PlanDiff([]Rule{catchAllAllow}, nil, 16)
	if err != nil {
		t.Fatalf("PlanDiff removing an on-card catch-all: %v", err)
	}
	if len(plan.Mutations) != 1 || plan.Mutations[0].Phase != PhaseDelete {
		t.Fatalf("unexpected plan: %+v", plan.Mutations)
	}
}

func TestReconcileRefusesCatchAllGrantWithoutOptInAndNeverCallsSink(t *testing.T) {
	state := newMemoryCatalog()
	sink := &interruptingMutator{state: state, failAfter: -1}
	reconciler := Reconciler{Source: state, Sink: sink}
	desired := []Rule{testRule(t, "", "", 0x01)}

	if _, err := reconciler.Reconcile(context.Background(), desired, 16, true); err == nil {
		t.Fatal("Reconcile accepted a catch-all allow without the opt-in")
	}
	if sink.calls != 0 {
		t.Fatalf("sink calls = %d, want 0", sink.calls)
	}

	result, err := reconciler.Reconcile(context.Background(), desired, 16, true, AllowCatchAllGrants())
	if err != nil {
		t.Fatalf("Reconcile with opt-in: %v", err)
	}
	if !result.Verified || sink.calls != 1 {
		t.Fatalf("verified=%v sink calls=%d", result.Verified, sink.calls)
	}
}

func TestReconcileResumesByRereadAndRediffAfterInterruption(t *testing.T) {
	state := newMemoryCatalog()
	desired := []Rule{
		testRule(t, "F0000000AA01", "", 0x01),
		testRule(t, "F0000000BB01", "", 0x01),
		testRule(t, "F0000000CC01", "", 0x01),
	}
	mutator := &interruptingMutator{state: state, failAfter: 1}
	reconciler := Reconciler{Source: state, Sink: mutator}

	if _, err := reconciler.Reconcile(context.Background(), desired, 16, true); err == nil {
		t.Fatal("first Reconcile unexpectedly succeeded")
	}
	if got := len(state.rules); got != 1 {
		t.Fatalf("committed prefix size = %d, want 1", got)
	}

	mutator.failAfter = -1
	result, err := reconciler.Reconcile(context.Background(), desired, 16, true)
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if !result.Verified {
		t.Fatal("second Reconcile did not verify desired state")
	}
	if got := len(result.Plan.Mutations); got != 2 {
		t.Fatalf("remaining mutation count = %d, want 2", got)
	}
}

func TestReconcileDryRunDoesNotInvokeMutationSink(t *testing.T) {
	state := newMemoryCatalog()
	sink := &interruptingMutator{state: state, failAfter: -1}
	reconciler := Reconciler{Source: state, Sink: sink}

	result, err := reconciler.Reconcile(
		context.Background(),
		[]Rule{testRule(t, "F0000000AA01", "", 0x01)},
		16,
		false,
	)
	if err != nil {
		t.Fatalf("Reconcile dry-run: %v", err)
	}
	if result.Executed || sink.calls != 0 {
		t.Fatalf("dry-run executed=%v sink calls=%d", result.Executed, sink.calls)
	}
}

type memoryCatalog struct {
	rules map[string]Rule
}

func newMemoryCatalog(rules ...Rule) *memoryCatalog {
	state := &memoryCatalog{rules: make(map[string]Rule)}
	for _, rule := range rules {
		state.rules[rule.Key.mapKey()] = rule
	}
	return state
}

func (m *memoryCatalog) ReadCatalog(context.Context) (CatalogSnapshot, error) {
	rules := make([]Rule, 0, len(m.rules))
	for _, rule := range m.rules {
		rules = append(rules, rule)
	}
	return CatalogSnapshot{Rules: rules}, nil
}

type interruptingMutator struct {
	state     *memoryCatalog
	failAfter int
	calls     int
}

func (m *interruptingMutator) Apply(_ context.Context, mutations []Mutation) error {
	m.calls++
	for i, mutation := range mutations {
		if m.failAfter >= 0 && i == m.failAfter {
			return errors.New("simulated transport interruption")
		}
		if err := applyMutationToMemory(m.state, mutation); err != nil {
			return err
		}
	}
	return nil
}

func applyMutationToMemory(state *memoryCatalog, mutation Mutation) error {
	switch mutation.Phase {
	case PhaseUpdate, PhaseAdd:
		state.rules[mutation.Rule.Key.mapKey()] = mutation.Rule
	case PhaseDelete:
		delete(state.rules, mutation.Key.mapKey())
	default:
		return errors.New("unknown mutation phase")
	}
	return nil
}
