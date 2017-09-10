package porter

const (
	ALL_PERMISSIONS Permission = 4294967295
	ALL_STATUSES Status = 4294967295
)

/*
	Type for represent permissions.
	Use:
	const (
		PERM_1 Permission = 1 << iota
		PERM_2
		PERM_3
		...
		...
		PERM_32
	)
	A maximum of 32 values (uint32).
*/

type Permission uint32

/*
	Type for represent statuses.
	Use:
	const (
		STAT_1 Status = 1 << iota
		STAT_2
		...
		STAT_32
	)
	A maximum of 32 values (uint32).
*/
type Status uint32

// Permissions and statuses container
type Permissions struct {
	permissions Permission
	statuses    Status
}

func NewPermissions(permissions uint32, statuses uint32) Permissions {
	return Permissions{
		permissions:Permission(permissions),
		statuses:Status(statuses),
	}
}

func (p *Permissions)GetStatuses() uint32 {
	return uint32(p.statuses)
}

func (p *Permissions)GetPermissions() uint32  {
	return uint32(p.permissions)
}


/*
	Checking permission. Returns true, if the permissions have been set.
	You can use several arguments or bitwise addition.
	perm.HasPermissions(PERM_1 | PERM_2) or perm.HasPermissions(PERM_1, PERM_2)
*/
func (p *Permissions) HasPermissions(permissions ...Permission) bool {
	return p.permissions & combinePermissions(permissions) > 0
}

/*
	Checking statuses.
	You can use several arguments or bitwise addition.
	perm.HasStatuses(STAT_1 | STAT_2) or perm.HasStatuses(STAT_1, STAT_2)
*/
func (p *Permissions) HasStatuses(statuses ...Status) bool {
	return p.statuses & combineStatuses(statuses) > 0
}

/*
	Set statuses.
*/
func (p *Permissions) AddStatus(statuses ...Status) {
	p.statuses = p.statuses | combineStatuses(statuses)
}

/*
	Set permissions.
*/
func (p *Permissions) AddPermissions(permissions ...Permission) {
	p.permissions = p.permissions | combinePermissions(permissions)
}

/*
	Remove statuses.
*/
func (p *Permissions) RemoveStatuses(statuses ...Status) {
	p.statuses = p.statuses &^ combineStatuses(statuses)
}

/*
	Remove permission.
*/
func (p *Permissions) RemovePermissions(statuses ...Permission) {
	p.permissions = p.permissions &^ combinePermissions(statuses)
}

func combinePermissions(flags []Permission) Permission {
	var t Permission = Permission(0)
	for _, flag := range flags {
		t = t | flag
	}
	return t
}

func combineStatuses(flags []Status) Status {
	var t Status = Status(0)
	for _, flag := range flags {
		t = t | flag
	}
	return t
}
