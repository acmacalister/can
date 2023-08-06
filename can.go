// Package can provides primitives for authorization.
// Authorization is the way it restricts what resource a
// given role and permissions. Simple primitives for RBAC
// (Role Based Access Control) are the building blocks
// for can. This package was inspired by https://github.com/CanCanCommunity/cancancan
package can

import (
	"context"
	"net/http"
	"os"
	"path"
	"strings"

	"golang.org/x/exp/constraints"
	"gopkg.in/yaml.v3"
)

// CanFn is a type for the implementing custom authorization functions.
type CanFn func(ctx context.Context, role *Role, compare func() bool, permission string, ability Ability) bool

// Ability provides typed constants for general
// resource control.
type Ability int64

// String implements the Stringer interface.
//
// returns a string representation of the ability type
func (a Ability) String() string {
	switch a {
	case Manage:
		return "manage"
	case Read:
		return "read"
	case Create:
		return "create"
	case Update:
		return "update"
	case Delete:
		return "delete"
	}
	return ""
}

// StringToAbility converts a string to an ability type
//
// s is a string to convert
//
// returns an ability or -1 if the string is incorrect
func StringToAbility(s string) Ability {
	switch strings.ToLower(s) {
	case "manage":
		return Manage
	case "read":
		return Read
	case "create":
		return Create
	case "update":
		return Update
	case "delete":
		return Delete
	}

	return -1
}

const (
	// Manage is a default for full control or "admin" abilities.
	Manage Ability = iota
	// Read is a default for access to a given resource.
	Read
	// Create is a default for creating a given resource.
	Create
	// Update is a default for updating a given resource.
	Update
	// Delete is a default for deleting a given resource.
	Delete
)

// Permission provides typed structure for general permissions or
// access to a given resource. This struct is easily embedded in
// other types to extend the permissions (see examples).
type Permission struct {
	Abilities map[Ability]struct{} `json:"abilities" db:"abilities" yaml:"abilities"`
}

// Role provides typed structure for general roles that
// enumerates a set of permissions. This struct is easily embedded in
// other types to extend the role (see examples).
type Role struct {
	Permissions map[string]Permission `json:"permissions" db:"permissions" yaml:"permissions"`
}

// Roles is a map of Role type
// use for disk encoding rbac setting
type Roles map[string]*Role

// diskRole is the private struct that represents how
// the roles are encoded in yaml to disk
type diskRole struct {
	Permission map[string][]string `yaml:"permissions"`
}

// diskRoles is a map of diskRole
type diskRoles map[string]diskRole

// UnmarshalYAML implement the yaml Unmarshaler interface
func (r Roles) UnmarshalYAML(value *yaml.Node) error {
	var diskYaml diskRoles
	if err := value.Decode(&diskYaml); err != nil {
		return err
	}

	for k, v := range diskYaml {
		p := buildPermissions(v.Permission)
		r[k] = &Role{
			Permissions: p,
		}
	}

	return nil
}

func buildPermissions(dp map[string][]string) map[string]Permission {
	p := make(map[string]Permission)
	for k, v := range dp {
		p[k] = Permission{Abilities: buildAbility(v)}
	}

	return p
}

func buildAbility(abilities []string) map[Ability]struct{} {
	a := make(map[Ability]struct{})
	for _, ability := range abilities {
		a[Ability(StringToAbility(ability))] = struct{}{}
	}

	return a
}

type Comparable interface {
	constraints.Ordered | bool
}

// Compare is a helper function to easily satisfies the compare function in the main Can function
func Compare[T Comparable](i, j T) func() bool {
	result := i == j
	return func() bool { return result }
}

// OpenFile takes a yaml file and returns a map of Roles
// filename - yaml encoded file for parsing
//
// returns a map of Roles and an error
func OpenFile(filename string) (Roles, error) {
	f, err := os.OpenFile(filename, os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}

	r := make(Roles)
	if err := yaml.NewDecoder(f).Decode(&r); err != nil {
		return nil, err
	}

	return r, nil
}

// Can is the heart and soul of the can package. It can take a custom compare function to do various authorization checking
//
// ctx - a standard ctx to pass to authorization. Useful for passing additional request specific data and canceling the can
// function call if it was signal to a remote authorization service.
//
// role - a role structure that contains the role and permissions to check authorization on.
//
// permission - defines the permission to check of a given object.
//
// ability - defines the ability to check of a given object.
//
// compare - a simple function to check request specific data. Things like if a user can update
// their own comments or the like.
//
// returns a true or false if the role or permission is allowed.
func Can(ctx context.Context, role *Role, permission string, ability Ability, compare func() bool) bool {
	if role == nil {
		return false
	}

	perm, ok := role.Permissions[permission]
	if !ok {
		return false
	}

	if _, ok := perm.Abilities[ability]; !ok {
		return false
	}

	switch ability {
	case Manage:
		return true
	case Read, Create, Update, Delete:
		if compare == nil {
			return false
		}
		return compare()
	}

	return false
}

// BuildFromRequest uses standard Rest conventions to build a
// permission and ability from the request. Useful for implementing
// authorization middleware
func BuildFromRequest(r *http.Request) (string, Ability) {
	perm := path.Base(r.URL.Path)

	var ability Ability
	switch r.Method {
	case http.MethodGet:
		ability = Read
	case http.MethodPost:
		ability = Create
	case http.MethodPut, http.MethodPatch:
		ability = Update
	case http.MethodDelete:
		ability = Delete
	}

	return perm, ability
}
