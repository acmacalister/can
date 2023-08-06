package can

import "testing"

func TestOpenFile(t *testing.T) {
	r, err := OpenFile("testdata/rbac.yml")
	if err != nil {
		t.Fatal(err)
	}

	role, ok := r["admin"]
	if !ok {
		t.Fatal("fail")
	}

	perm, ok := role.Permissions["users"]
	if !ok {
		t.Fatal("fail")
	}

	if _, ok := perm.Abilities[Manage]; !ok {
		t.Fatal("fail")
	}
}
