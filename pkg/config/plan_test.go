package config

import "testing"

// Merges of independent features both append dependency groups; a duplicate
// ID makes plans report a group twice and hides newly added keys.
func TestConfigurationDependencyGroupsAreUnique(t *testing.T) {
	ids := map[string]bool{}
	keys := map[string]string{}
	for _, group := range configurationDependencies {
		if ids[group.id] {
			t.Errorf("dependency group %q is declared twice", group.id)
		}
		ids[group.id] = true
		for _, key := range group.keys {
			if other, ok := keys[key]; ok && other != group.id {
				t.Errorf("setting %q is in groups %q and %q", key, other, group.id)
			}
			keys[key] = group.id
		}
	}
}
