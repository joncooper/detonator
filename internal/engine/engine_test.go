package engine

import (
	"testing"

	"github.com/joncooper/detonator/internal/verdict"
)

func sig(sev verdict.Severity) verdict.Signal {
	return verdict.Signal{Stage: "static", Rule: "r", Severity: sev, Description: "d"}
}

func TestDecisionTiers(t *testing.T) {
	art := verdict.Artifact{Name: "x"}
	cases := []struct {
		name    string
		signals []verdict.Signal
		want    verdict.Decision
	}{
		{"clean", nil, verdict.Allow},
		{"one low", []verdict.Signal{sig(verdict.SevLow)}, verdict.Allow},
		{"one medium", []verdict.Signal{sig(verdict.SevMedium)}, verdict.Allow},
		{"two medium", []verdict.Signal{sig(verdict.SevMedium), sig(verdict.SevMedium)}, verdict.Quarantine},
		{"one high", []verdict.Signal{sig(verdict.SevHigh)}, verdict.Quarantine},
		{"one critical", []verdict.Signal{sig(verdict.SevCritical)}, verdict.Block},
		{"critical dominates", []verdict.Signal{sig(verdict.SevLow), sig(verdict.SevCritical)}, verdict.Block},
	}
	for _, c := range cases {
		got := Decide(art, c.signals, DefaultPolicy(), "test")
		if got.Decision != c.want {
			t.Errorf("%s: got %s want %s", c.name, got.Decision, c.want)
		}
	}
}

func TestFailClosedFlipsQuarantine(t *testing.T) {
	art := verdict.Artifact{Name: "x"}
	high := []verdict.Signal{sig(verdict.SevHigh)}
	if d := Decide(art, high, DefaultPolicy(), "t").Decision; d != verdict.Quarantine {
		t.Fatalf("default: want quarantine, got %s", d)
	}
	if d := Decide(art, high, Policy{FailClosed: true}, "t").Decision; d != verdict.Block {
		t.Fatalf("fail-closed: want block, got %s", d)
	}
}

func TestSignalsSortedMostSevereFirst(t *testing.T) {
	art := verdict.Artifact{Name: "x"}
	v := Decide(art, []verdict.Signal{sig(verdict.SevLow), sig(verdict.SevCritical), sig(verdict.SevMedium)}, DefaultPolicy(), "t")
	if v.Signals[0].Severity != verdict.SevCritical {
		t.Fatalf("signals not sorted: %+v", v.Signals)
	}
}
