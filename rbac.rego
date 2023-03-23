

package app.rbac

default allow := false


allow {
    user := input.user_id
    resource := input.resource
    action := input.action
    roles := get_roles_for_user(user)
    role := roles[_]
    permissions := get_permissions_for_role(role)
    permission := permissions[_]
    permission.resource == resource
    permission.action == action
}

get_roles_for_user(user_id) = roles {
    roles := [r.role_id | r := data.users_roles[_]; r.user_id == user_id]
}

get_permissions_for_role(role_id) = permissions {
    permissions := [p | rp := data.roles_permissions[_]; rp.role_id == role_id; p := data.permissions[_]; p.permission_id == rp.permission_id]
}