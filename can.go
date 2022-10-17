// Package can provides primitives for authorization.
// Authorization is the way it restricts what resource a
// given role and permissions. Simple primitives for RBAC
// (Role Based Access Control) are the building blocks
// for can. This package was inspired by https://github.com/CanCanCommunity/cancancan
package can

import (
	"context"

	"golang.org/x/exp/constraints"
)

// CanFn is a type for the implementing custom authorization functions.
type CanFn func(ctx context.Context, role *Role, compare func() bool, permission string, ability Ability) bool

// Ability provides typed constants for general
// resource control.
type Ability int64

func (a Ability) String() string {
	switch a {
	case Manage:
		return "Manage"
	case ReadAll:
		return "ReadAll"
	case Read:
		return "Read"
	case Create:
		return "Create"
	case Update:
		return "Update"
	case Delete:
		return "Delete"
	}

	return "Custom"
}

const (
	// Manage is a default for full control or "admin" abilities.
	Manage Ability = iota
	// ReadAll is a default for all items of a given resource.
	ReadAll
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
	ID        int64                `json:"id" db:"id"`
	Name      string               `json:"name" db:"name"`
	Abilities map[Ability]struct{} `json:"abilities" db:"abilities"`
}

// Role provides typed structure for general roles that
// enumerates a set of permissions. This struct is easily embedded in
// other types to extend the role (see examples).
type Role struct {
	ID          int64                 `json:"id" db:"id"`
	Name        string                `json:"name" db:"name"`
	Permissions map[string]Permission `json:"permissions" db:"permissions"`
}

type Comparable interface {
	constraints.Ordered | bool
}

// Compare is a helper function to easily satisfies the compare function in the main Can function
func Compare[T Comparable](i, j T) func() bool {
	result := i == j
	return func() bool { return result }
}

// Can is the heart and soul of the can package. It can take a custom can function to do various authorization checking
// ctx - a standard ctx to pass to authorization. Useful for passing additional request specific data and canceling the can
// function call if it was signal to a remote authorization service.
//
// role - a role structure that contains the role and permissions to check authorization on.
//
// compare - a simple function to check request specific data. Things like if a user can update
// their own comments or the like.
//
// permission - defines the permission to check of a given object.
//
// ability - defines the ability to check of a given object.
//
// can - a custom can function to check authorization. If nil, DefaultCan is used.
//
// returns a true or false if the role or permission is allowed.
func Can(ctx context.Context, role *Role, compare func() bool, permission string, ability Ability, can CanFn) bool {
	if can == nil {
		return DefaultCan(ctx, role, compare, permission, ability)
	}
	return can(ctx, role, compare, permission, ability)
}

// DefaultCan provides a default implementation for checking authorization.
// It checks that the given permission exists.
// If Manage permission is defined for the given role, it is allowed.
// If Read, ReadAll, Update, or Delete are defined for the given role
// and match the compare function is true, it is allowed.
// Anything that doesn't match those above, will return false.
func DefaultCan(ctx context.Context, role *Role, compare func() bool, permission string, ability Ability) bool {
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
	case Read, ReadAll, Create, Update, Delete:
		if compare == nil {
			return false
		}
		return compare()
	}

	return false
}
