

package app.rbac

default allow := false


allow {
	user := input.user_id
	resource := input.resource
	action := input.action
	user_role := get_user_role(user)
	user_permission := get_user_permission(user_role)
	user_has_permission(user_permission, resource, action)
}

get_user_role(user_id) = r {
	user_roles := [ur | ur := data.users_roles[_]; ur.user_id == user_id]
	count(user_roles) > 0
	r := [role | some i; role := user_roles[i].role_id]
}

get_user_permission(role_id) = p {
	roles_permissions := [rp.permission_id | rp := data.roles_permissions[_]; rp.role_id == role_id[_]]
	count(roles_permissions) > 0
	p := [ permission | some i; permission := roles_permissions[i]]
}

user_has_permission(permission_id, resource, action) {
	permissions := [p | p := data.permissions[_]; p.permission_id == permission_id[_]]
# 	count(permissions) == 1
	permissions[_].resource == resource
	permissions[_].action == action
}