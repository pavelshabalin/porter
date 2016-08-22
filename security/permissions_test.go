package security

import (
	"strconv"
	"strings"
	"testing"
)

const (
	TEST_PERM_1 Permission = 1 << iota
	TEST_PERM_2
	TEST_PERM_3
	TEST_PERM_4
	TEST_PERM_5
	TEST_PERM_6
	TEST_PERM_7
	TEST_PERM_8
	TEST_PERM_9
	TEST_PERM_10

	TEST_PERM_11
	TEST_PERM_12
	TEST_PERM_13
	TEST_PERM_14
	TEST_PERM_15
	TEST_PERM_16
	TEST_PERM_17
	TEST_PERM_18
	TEST_PERM_19
	TEST_PERM_20

	TEST_PERM_21
	TEST_PERM_22
	TEST_PERM_23
	TEST_PERM_24
	TEST_PERM_25
	TEST_PERM_26
	TEST_PERM_27
	TEST_PERM_28
	TEST_PERM_29
	TEST_PERM_30

	TEST_PERM_31

	FULL_PERM_32_STRING string = "11111111111111111111111111111111"
)

func TestPermissions(t *testing.T) {
	//	errStr := "Not added premission: %s"
	perm := Permissions{}
	perm.AddPermissions(ALL_PERMISSIONS)
	if perm_s := strconv.FormatUint(uint64(ALL_PERMISSIONS), 2); strings.Compare(perm_s, FULL_PERM_32_STRING) != 0 {
		t.Error("ALL_PERMISSIONS constant do't set all permission flag: " + perm_s)
	}
	perm.RemovePermissions(ALL_PERMISSIONS)
	if perm.HasPermissions(TEST_PERM_1) {
		t.Error("Dont remove all permmisions")
	}

	perm.AddPermissions(TEST_PERM_1)
	if !perm.HasPermissions(TEST_PERM_1) {
		t.Error("Dont added permission")
	}
	perm.AddPermissions(TEST_PERM_2)
	if !perm.HasPermissions(TEST_PERM_1) {
		t.Error("Dont added permission")
	}
	perm.AddPermissions(TEST_PERM_16)
	if !perm.HasPermissions(TEST_PERM_1) {
		t.Error("Dont added permission")
	}
	perm.AddPermissions(TEST_PERM_31)
	if !perm.HasPermissions(TEST_PERM_1) {
		t.Error("Dont added permission")
	}
}
