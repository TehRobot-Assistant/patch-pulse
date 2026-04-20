package update

import "testing"

func TestIsSafeIdentifier(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		// Valid
		{"web", true},
		{"nextcloud", true},
		{"my_service", true},
		{"svc.1", true},
		{"a-b", true},
		{"A.Service-1", true},

		// Invalid — hostile compose labels we must reject.
		{"", false},
		{"-dry-run", false},
		{"--force-recreate", false},
		{"-f/etc/passwd", false},
		{"svc -v /etc:/mnt", false},
		{"svc;id", false},
		{"svc\tfoo", false},
		{"svc\nfoo", false},
		{"../evil", false},
		{"svc$HOME", false},
		{"svc|pwn", false},
		{"svc`id`", false},
	}
	for _, c := range cases {
		got := IsSafeIdentifier(c.in)
		if got != c.want {
			t.Errorf("IsSafeIdentifier(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIsSafeComposePath(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"/etc/compose/stack.yml", true},
		{"/mnt/user/appdata/x/docker-compose.yml", true},
		{"", false},
		{"relative/path.yml", false},
		{"-fattack", false},
		{"-v/etc:/mnt", false},
	}
	for _, c := range cases {
		got := IsSafeComposePath(c.in)
		if got != c.want {
			t.Errorf("IsSafeComposePath(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
