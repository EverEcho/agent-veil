package egress

import "testing"

func TestProcessTreeTracksOnlyRootIdentityAndDescendants(t *testing.T) {
	root := ProcessIdentity{ProcessID: 10, StartedAt: 100}
	tree, err := NewProcessTree(root, 16)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := []Process{
		{ProcessIdentity: root, ParentID: 1},
		{ProcessIdentity: ProcessIdentity{ProcessID: 11, StartedAt: 110}, ParentID: 10},
		{ProcessIdentity: ProcessIdentity{ProcessID: 12, StartedAt: 120}, ParentID: 11},
		{ProcessIdentity: ProcessIdentity{ProcessID: 20, StartedAt: 200}, ParentID: 1},
		{ProcessIdentity: ProcessIdentity{ProcessID: 21, StartedAt: 210}, ParentID: 99},
	}
	if err := tree.Update(snapshot); err != nil {
		t.Fatal(err)
	}
	for _, identity := range []ProcessIdentity{root, {ProcessID: 11, StartedAt: 110}, {ProcessID: 12, StartedAt: 120}} {
		if !tree.Contains(identity) {
			t.Fatalf("descendant missing: %+v", identity)
		}
	}
	if tree.Contains(ProcessIdentity{ProcessID: 20, StartedAt: 200}) || tree.Contains(ProcessIdentity{ProcessID: 11, StartedAt: 999}) {
		t.Fatal("unrelated or PID-reused process entered the tree")
	}
	if got := tree.Descendants(); len(got) != 3 || got[0].ProcessID != 10 || got[2].ProcessID != 12 {
		t.Fatalf("descendants=%+v", got)
	}
}

func TestProcessTreeFailsClosedOnRootReuseCyclesAndDuplicates(t *testing.T) {
	root := ProcessIdentity{ProcessID: 10, StartedAt: 100}
	for _, snapshot := range [][]Process{
		{{ProcessIdentity: ProcessIdentity{ProcessID: 10, StartedAt: 999}, ParentID: 1}},
		{{ProcessIdentity: root, ParentID: 1}, {ProcessIdentity: ProcessIdentity{ProcessID: 11, StartedAt: 110}, ParentID: 12}, {ProcessIdentity: ProcessIdentity{ProcessID: 12, StartedAt: 120}, ParentID: 11}},
		{{ProcessIdentity: root, ParentID: 1}, {ProcessIdentity: ProcessIdentity{ProcessID: 10, StartedAt: 101}, ParentID: 1}},
	} {
		tree, err := NewProcessTree(root, 16)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.Update(snapshot); err == nil {
			t.Fatalf("unsafe snapshot was accepted: %+v", snapshot)
		}
		if len(tree.Descendants()) != 0 {
			t.Fatal("failed update changed the authoritative tree")
		}
	}
}

func TestProcessTreeBoundsSnapshots(t *testing.T) {
	root := ProcessIdentity{ProcessID: 1, StartedAt: 1}
	tree, err := NewProcessTree(root, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Update([]Process{{ProcessIdentity: root}, {ProcessIdentity: ProcessIdentity{ProcessID: 2, StartedAt: 2}, ParentID: 1}, {ProcessIdentity: ProcessIdentity{ProcessID: 3, StartedAt: 3}, ParentID: 2}}); err == nil {
		t.Fatal("oversized process snapshot was accepted")
	}
}
