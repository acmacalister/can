# can

[![GoDoc Widget]][GoDoc]

`can` provides primitives for authorization. Authorization is the way it restricts what resource a given role and permissions. Simple primitives for RBAC (Role Based Access Control) are the building blocks for can. This package was inspired by https://github.com/CanCanCommunity/cancancan

## Install

`go get -u github.com/acmacalister/can`

## Examples

See a complete HTTP application in examples/main.go.

TODO: fix up these 

```go
const (
    PermissionClients string = "permission_clients"
    UserDetailsContextKey string = "userDetailsContextKey"
)

type userDetails {
    Role *can.Role
}

type Client struct {
    ID int64 `json:"id"`
    UserID null.Int64 `json:"user_id"`
    Name string `json:"name"`
}

if !can.Can(r.Context(), userDetails.Role, can.Compare(client.UserID, userDetails.ID), PermissionClients, can.Read, nil) {
    return errors.New("unauthorized")
}

if !can.Can(r.Context(), userDetails.Role, can.Compare(client.UserID, userDetails.ID), PermissionClients, can.Read, nil) {
    return errors.New("unauthorized")
}


func CustomAuthorization(ctx context.Context, role *Role, compare func() bool, permission string, ability Ability) bool {
    return true // everything is allowed!
}

if !can.Can(r.Context(), userDetails.Role, can.Compare(client.UserID, userDetails.ID), PermissionClients, can.Read, CustomAuthorization) {
    return errors.New("unauthorized")
}

func getSomething(w http.ResponseWriter, r *http.Request) {
	userDetails, ok := r.Context().Value(UserDetailsContextKey).(UserDetail)
	if !ok {
        w.WriteHeader(http.StatusBadRequest)
        return
	}

    id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
    if err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    client, err := service.ByID(id, userDetails.OrganizationID) // some sort of model or service to pull clients off of the ID.
    if err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    if !can.Can(r.Context(), userDetails.Role, can.Compare(client.UserID, userDetails.ID), PermissionClients, can.Read, nil) {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }

    w.WriteHeader(http.StatusOK)
    return
}

func createSomething(w http.ResponseWriter, r *http.Request) {
	userDetails, ok := r.Context().Value(UserDetailsContextKey).(UserDetail)
	if !ok {
        w.WriteHeader(http.StatusBadRequest)
        return
	}

    var client Client
    if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }

	allowed := (newClient.UserID.Valid && newClient.UserID.Int64 == userDetails.ID)

    if !can.Can(r.Context(), userDetails.Role, can.Compare(allowed, true), PermissionClients, can.Create, nil) {
        w.WriteHeader(http.StatusUnauthorized)
        return
	}


    w.WriteHeader(http.StatusOK)
    return
}
```

## How do I store the permissions in the database?

TODO. 

## How do add custom abilities?

Just create new constants with the `can.Ability` type.

## What does the default authorization look like?

Basically the DefaultCan method looks like so:

```go
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
```

Basically the manage ability allows all the abilities for the permission (useful for an "admin" type role). Otherwise, all other abilities only allow a user to access if the compare function is true. Think of the compare function as a way to check that the user ID is owned by that user. Obviously you can customize as you like, but that is a concrete example of its usage as seen above.

## Details

can is designed for authorization for the "controller" or routing layer of an application. It isn't designed for views/presentation layer. Users should have permissions and every permission has abilities. You could implement this in a middleware like the `authorize_and_load` in the RoR version, but would either require shoving everything in a request context, using reflect, or requiring application logic specific to your application. This was a first attempt to build a simple generic authorization library for Go applications. Feel free to open issues or Pull Requests with some feedback or thoughts.

## License

MIT