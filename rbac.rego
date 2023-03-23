

package app.rbac

default allow := false


allow {
	user := input.userId
	resource := input.resource
	action := input.action
	user_role := get_user_role(user)
	user_permission := get_user_permission(user_role)
	user_has_permission(user_permission, resource, action)
}

get_user_role(user_id) = role_id {
	user_roles := [ur | ur := data.users_roles[_]; ur.userId == user_id]
	count(user_roles) > 0
	role_id := [role | some i; role := user_roles[i].roleId]
}

get_user_permission(role_id) = permission_id {
	roles_permissions := [rp.permissionId | rp := data.roles_permissions[_]; rp.roleId == role_id[_]]
	count(roles_permissions) > 0
	permission_id := [ permission | some i; permission := roles_permissions[i]]
}

user_has_permission(permission_id, resource, action) {
	permissions := [p | p := data.permissions[_]; p.permissionId == permission_id[_]]
# 	count(permissions) == 1
	permissions[_].resource == resource
	permissions[_].action == action
}