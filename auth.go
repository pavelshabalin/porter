package auth

import "go-auth/auth/security"

type AuthConfiguration struct  {
	Logger func(string)
	PermissionConstructor func(interface{}) (*security.Permission)
}