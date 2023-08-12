package can

import (
	"context"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCan(t *testing.T) {
	r, err := OpenFile("testdata/rbac.yml")
	if err != nil {
		t.Fatal(err)
	}

	adminRole, ok := r["admin"]
	if !ok {
		t.Fatal("fail")
	}

	userRole, ok := r["user"]
	if !ok {
		t.Fatal("fail")
	}

	if !Can(context.Background(), adminRole, "users", Read, func() bool {
		return true
	}) {
		t.Fatal("failed admin auth check")
	}

	if !Can(context.Background(), userRole, "users", Read, func() bool {
		return true
	}) {
		t.Fatal("failed user auth read check")
	}

	if Can(context.Background(), userRole, "users", Create, func() bool {
		return true
	}) {
		t.Fatal("failed user auth create check")
	}

	if Can(context.Background(), userRole, "users", Read, func() bool {
		return false // if it wasn't there resource for example
	}) {
		t.Fatal("failed user auth resource read check")
	}
}

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

	if _, ok := perm.Abilities[All]; !ok {
		t.Fatal("fail")
	}
}

func TestConfig(t *testing.T) {
	f, err := os.OpenFile("testdata/config.yml", os.O_RDONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}

	type config struct {
		Roles DiskRoles `yaml:"roles"`
	}

	var c config
	if err := yaml.NewDecoder(f).Decode(&c); err != nil {
		t.Fatal(err)
	}

	r := Config(c.Roles)

	role, ok := r["admin"]
	if !ok {
		t.Fatal("fail")
	}

	perm, ok := role.Permissions["users"]
	if !ok {
		t.Fatal("fail")
	}

	if _, ok := perm.Abilities[All]; !ok {
		t.Fatal("fail")
	}
}
