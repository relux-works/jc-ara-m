package provisioner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

type MutationPhase string

const (
	PhaseUpdate MutationPhase = "update"
	PhaseDelete MutationPhase = "delete"
	PhaseAdd    MutationPhase = "add"
)

type Mutation struct {
	Phase   MutationPhase
	Key     RuleKey
	Rule    Rule
	Command []byte
	APDU    []byte
}

type Plan struct {
	CurrentCount int
	DesiredCount int
	Mutations    []Mutation
}

type MutationSummary struct {
	Ordinal       int           `json:"ordinal"`
	Phase         MutationPhase `json:"phase"`
	KeyID         string        `json:"key_id"`
	RuleID        string        `json:"rule_id,omitempty"`
	CommandLength int           `json:"command_length"`
}

type PlanSummary struct {
	CurrentCount int               `json:"current_count"`
	DesiredCount int               `json:"desired_count"`
	CommandCount int               `json:"command_count"`
	Mutations    []MutationSummary `json:"mutations"`
}

func (p Plan) Summary() PlanSummary {
	summary := PlanSummary{
		CurrentCount: p.CurrentCount,
		DesiredCount: p.DesiredCount,
		CommandCount: len(p.Mutations),
		Mutations:    make([]MutationSummary, len(p.Mutations)),
	}
	for i, mutation := range p.Mutations {
		ruleID := ""
		if mutation.Phase != PhaseDelete {
			ruleID = mutation.Rule.Identifier()
		}
		summary.Mutations[i] = MutationSummary{
			Ordinal:       i + 1,
			Phase:         mutation.Phase,
			KeyID:         mutation.Key.Identifier(),
			RuleID:        ruleID,
			CommandLength: len(mutation.Command),
		}
	}
	return summary
}

// planPolicy holds host-side policy decisions that are deliberately absent from
// the card: the applet is a faithful SEAC store, the reviewable guard lives here.
type planPolicy struct {
	allowCatchAllGrants bool
}

// PlanOption opts a plan out of a default-closed host policy guard.
type PlanOption func(*planPolicy)

// AllowCatchAllGrants opts in to desired rules that grant access to every SE
// applet through a zero-length AID-REF-DO. Without it, such a rule is refused.
func AllowCatchAllGrants() PlanOption {
	return func(policy *planPolicy) { policy.allowCatchAllGrants = true }
}

// CheckCatchAllPolicy refuses a desired catalog that grants access through the
// zero-length AID-REF-DO catch-all unless the caller opted in. A catch-all that
// denies access needs no opt-in: it only removes reach.
func CheckCatchAllPolicy(desired []Rule, options ...PlanOption) error {
	policy := planPolicy{}
	for _, option := range options {
		option(&policy)
	}
	if policy.allowCatchAllGrants {
		return nil
	}
	for _, rule := range desired {
		if rule.IsCatchAll() && rule.GrantsAccess() {
			return fmt.Errorf(
				"desired rule %s (key %s) grants access to every SE applet through a zero-length AID-REF-DO catch-all; re-run with --allow-catch-all to opt in",
				rule.Identifier(),
				rule.Key.Identifier(),
			)
		}
	}
	return nil
}

func PlanDiff(currentRules, desiredRules []Rule, capacity int, options ...PlanOption) (Plan, error) {
	current, err := NormalizeRules(currentRules, capacity)
	if err != nil {
		return Plan{}, fmt.Errorf("normalize current catalog: %w", err)
	}
	desired, err := NormalizeRules(desiredRules, capacity)
	if err != nil {
		return Plan{}, fmt.Errorf("normalize desired catalog: %w", err)
	}
	// Only the desired state is policed. An existing on-card catch-all must stay
	// plannable so it can be diffed away without the opt-in.
	if err := CheckCatchAllPolicy(desired, options...); err != nil {
		return Plan{}, err
	}
	currentByKey := make(map[string]Rule, len(current))
	desiredByKey := make(map[string]Rule, len(desired))
	for _, rule := range current {
		currentByKey[rule.Key.mapKey()] = rule
	}
	for _, rule := range desired {
		desiredByKey[rule.Key.mapKey()] = rule
	}

	updates := make([]Mutation, 0)
	deletes := make([]Mutation, 0)
	adds := make([]Mutation, 0)
	for _, desiredRule := range desired {
		currentRule, exists := currentByKey[desiredRule.Key.mapKey()]
		if !exists {
			mutation, err := newUpsertMutation(PhaseAdd, desiredRule)
			if err != nil {
				return Plan{}, err
			}
			adds = append(adds, mutation)
			continue
		}
		if !bytes.Equal(currentRule.Bytes, desiredRule.Bytes) {
			mutation, err := newUpsertMutation(PhaseUpdate, desiredRule)
			if err != nil {
				return Plan{}, err
			}
			updates = append(updates, mutation)
		}
	}
	for _, currentRule := range current {
		if _, exists := desiredByKey[currentRule.Key.mapKey()]; exists {
			continue
		}
		mutation, err := newDeleteMutation(currentRule)
		if err != nil {
			return Plan{}, err
		}
		deletes = append(deletes, mutation)
	}

	mutations := make([]Mutation, 0, len(updates)+len(deletes)+len(adds))
	mutations = append(mutations, updates...)
	mutations = append(mutations, deletes...)
	mutations = append(mutations, adds...)
	return Plan{CurrentCount: len(current), DesiredCount: len(desired), Mutations: mutations}, nil
}

func newUpsertMutation(phase MutationPhase, rule Rule) (Mutation, error) {
	length, err := encodeShortLength(len(rule.Bytes))
	if err != nil {
		return Mutation{}, err
	}
	command := append([]byte{0xF0, length}, rule.Bytes...)
	apdu, err := storeDataAPDU(command)
	if err != nil {
		return Mutation{}, err
	}
	return Mutation{Phase: phase, Key: rule.Key, Rule: rule, Command: command, APDU: apdu}, nil
}

func newDeleteMutation(rule Rule) (Mutation, error) {
	length, err := encodeShortLength(len(rule.RefDO))
	if err != nil {
		return Mutation{}, err
	}
	command := append([]byte{0xF1, length}, rule.RefDO...)
	apdu, err := storeDataAPDU(command)
	if err != nil {
		return Mutation{}, err
	}
	return Mutation{Phase: PhaseDelete, Key: rule.Key, Command: command, APDU: apdu}, nil
}

func encodeShortLength(length int) (byte, error) {
	if length < 0 || length > 0x7F {
		return 0, fmt.Errorf("short APDU TLV length %d exceeds 0..127", length)
	}
	return byte(length), nil
}

func storeDataAPDU(command []byte) ([]byte, error) {
	if len(command) == 0 || len(command) > 0x7F {
		return nil, fmt.Errorf("STORE DATA command length %d exceeds bounded short APDU profile", len(command))
	}
	apdu := []byte{0x80, 0xE2, 0x90, 0x00, byte(len(command))}
	apdu = append(apdu, command...)
	return apdu, nil
}

type CatalogSource interface {
	ReadCatalog(context.Context) (CatalogSnapshot, error)
}

type MutationSink interface {
	Apply(context.Context, []Mutation) error
}

type Reconciler struct {
	Source CatalogSource
	Sink   MutationSink
}

type ReconcileResult struct {
	Plan     Plan `json:"-"`
	Executed bool `json:"executed"`
	Verified bool `json:"verified"`
}

func (r Reconciler) Reconcile(ctx context.Context, desired []Rule, capacity int, execute bool, options ...PlanOption) (ReconcileResult, error) {
	if r.Source == nil {
		return ReconcileResult{}, errors.New("catalog source is required")
	}
	current, err := r.Source.ReadCatalog(ctx)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("read current catalog: %w", err)
	}
	plan, err := PlanDiff(current.Rules, desired, capacity, options...)
	if err != nil {
		return ReconcileResult{}, err
	}
	result := ReconcileResult{Plan: plan}
	if !execute {
		return result, nil
	}
	if len(plan.Mutations) > 0 {
		if r.Sink == nil {
			return result, errors.New("authenticated mutation sink is required for execution")
		}
		result.Executed = true
		if err := r.Sink.Apply(ctx, plan.Mutations); err != nil {
			return result, fmt.Errorf("authenticated mutation manifest interrupted; state is unknown, re-run to re-read/re-diff: %w", err)
		}
	}
	readback, err := r.Source.ReadCatalog(ctx)
	if err != nil {
		return result, fmt.Errorf("read back catalog: %w", err)
	}
	remaining, err := PlanDiff(readback.Rules, desired, capacity, options...)
	if err != nil {
		return result, fmt.Errorf("normalize readback: %w", err)
	}
	if len(remaining.Mutations) != 0 {
		return result, fmt.Errorf("readback differs from desired catalog: %d mutations remain", len(remaining.Mutations))
	}
	result.Verified = true
	return result, nil
}
