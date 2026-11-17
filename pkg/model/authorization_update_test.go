package model

import (
	"strings"
	"testing"
)

func TestPolicyStoreUpdatePreservesIndexedIdentity(t *testing.T) {
	t.Parallel()
	ts := testStore(t)
	for _, namespace := range []string{NSPolicyBindings, NSPolicyIndexes} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatalf("ensure namespace %q: %v", namespace, err)
		}
	}
	policies := NewPolicyStore(ts)
	original, err := policies.Create(t.Context(), PolicyBinding{
		Principal:   PrincipalRef{Kind: PrincipalUser, ID: "reader"},
		Resource:    ResourceRef{Kind: ResourceFolder, ID: "owner:folder"},
		Effect:      EffectAllow,
		RoleID:      "folder.viewer",
		Inheritance: InheritanceSelf,
		GrantedBy:   "owner",
	})
	if err != nil {
		t.Fatalf("create binding: %v", err)
	}

	updated, err := policies.Update(t.Context(), original.ID, func(binding *PolicyBinding) error {
		binding.RoleID = "folder.editor"
		binding.Inheritance = InheritanceSubtree
		return nil
	})
	if err != nil {
		t.Fatalf("update mutable fields: %v", err)
	}
	if updated.RoleID != "folder.editor" || updated.Inheritance != InheritanceSubtree {
		t.Fatalf("updated binding = %#v", updated)
	}

	_, err = policies.Update(t.Context(), original.ID, func(binding *PolicyBinding) error {
		binding.Principal.ID = "intruder"
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "identity is immutable") {
		t.Fatalf("change principal error = %v", err)
	}
	stored, err := policies.Get(t.Context(), original.ID)
	if err != nil {
		t.Fatalf("get binding after rejected update: %v", err)
	}
	if stored.Principal != original.Principal || stored.Resource != original.Resource || stored.RoleID != "folder.editor" {
		t.Fatalf("rejected update changed binding: %#v", stored)
	}
	bindings, err := policies.ListForPrincipal(t.Context(), original.Principal)
	if err != nil || len(bindings) != 1 || bindings[0].ID != original.ID {
		t.Fatalf("original principal index = %#v, %v", bindings, err)
	}
	bindings, err = policies.ListForPrincipal(t.Context(), PrincipalRef{Kind: PrincipalUser, ID: "intruder"})
	if err != nil || len(bindings) != 0 {
		t.Fatalf("unexpected replacement principal index = %#v, %v", bindings, err)
	}
}
