package pki

import "testing"

func TestValidIdentity(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"a", true},
		{"svc-1", true},
		{"svc.orders.internal", true},
		{"node-7.eu-west", true},
		{"", false},
		{".", false},
		{"svc.", false},
		{".svc", false},
		{"-svc", false},
		{"svc-", false},
		{"SVC", false},    // no uppercase
		{"sv c", false},   // no space
		{"svc_1", false},  // underscore illegal
		{"svc..x", false}, // empty label
		{"svc/x", false},
		{"中国", false},
	}
	for _, c := range cases {
		if got := validIdentity(c.name); got != c.want {
			t.Errorf("validIdentity(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}
