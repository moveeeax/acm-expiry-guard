package main

import "testing"

func TestDefaultRegionsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range defaultRegions {
		if seen[r] {
			t.Errorf("duplicate region %q", r)
		}
		seen[r] = true
	}
	if len(defaultRegions) != 34 {
		t.Errorf("got %d regions, want the 34 commercial regions", len(defaultRegions))
	}
}

func TestResolveRegionsAll(t *testing.T) {
	got := resolveRegions("us-east-1", true)
	if len(got) != len(defaultRegions) {
		t.Errorf("--all-regions returned %d regions, want %d", len(got), len(defaultRegions))
	}
}
