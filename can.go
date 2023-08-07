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
	case All:
		return "all"
	case Read:
		return "read"
	case Create:
		return "create"
	case Update:
		return "update"
	case Delete:
		return "delete"
	case Skip:
		return "skip"
	}
	return "none"
}

// StringToAbility converts a string to an ability type
//
// s is a string to convert
//
// returns an ability or -1 if the string is incorrect
func StringToAbility(s string) Ability {
	switch strings.ToLower(s) {
	case "all":
		return All
	case "read":
		return Read
	case "create":
		return Create
	case "update":
		return Update
	case "delete":
		return Delete
	case "skip":
		return Skip
	}

	return None
}

const (
	// Read is for access to a given resource
	Read Ability = iota
	// Create is for creating a given resource
	Create
	// Update is for updating a given resource
	Update
	// Delete is for deleting a given resource
	Delete
	// All is read/create/update/delete for a give resource
	All
	// Skip is for skipping authorization lookups on a given resource.
	// Useful if for options style results and when authorization might be
	// handled later in a request chain.
	Skip
	// None is useful for signaling no access to given resource. Also useful for
	// error states
	None
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

// buildPermissions converts config representations of roles into in Roles structs
func buildPermissions(dp map[string][]string) map[string]Permission {
	p := make(map[string]Permission)
	for k, v := range dp {
		p[k] = Permission{Abilities: buildAbility(v)}
	}

	return p
}

// buildAbility converts config representations of roles into in Roles structs
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
// returns - a map of Roles and an error
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

	_, ok = perm.Abilities[ability]
	_, okAll := perm.Abilities[All]
	_, okSkip := perm.Abilities[Skip]
	if !ok && !okAll && !okSkip {
		return false
	}

	switch ability {
	case All, Skip:
		return true
	case Read, Create, Update, Delete:
		if compare == nil {
			return false
		}
		return compare()
	}

	return false
}

// BuildFromMethod uses standard Rest conventions to build a
// permission and ability from the request. Useful for implementing
// authorization middleware
//
// method - a string representation of an HTTP verb. GET/POST/PUT, etc
//
// returns - an ability
func BuildFromMethod(method string) Ability {
	switch method {
	case http.MethodGet:
		return Read
	case http.MethodPost:
		return Create
	case http.MethodPut, http.MethodPatch:
		return Update
	case http.MethodDelete:
		return Delete
	case http.MethodOptions:
		return Skip
	}

	return None
}
