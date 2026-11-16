package kdf

import "testing"

func TestIterations(t *testing.T) {
	cases := []struct {
		pim, want int
		ok        bool
	}{
		{0, 500000, true},
		{1, 16000, true},
		{485, 500000, true},
		{1000, 1015000, true},
		{-1, 0, false},
	}
	for _, c := range cases {
		got, err := Iterations(c.pim)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("Iterations(%d) = %d, %v; want %d, ok=%v", c.pim, got, err, c.want, c.ok)
		}
	}
}

func TestHeaderKeyRejectsBadInput(t *testing.T) {
	salt := make([]byte, SaltSize)
	if _, err := HeaderKey(nil, salt, 1); err == nil {
		t.Error("empty password accepted")
	}
	if _, err := HeaderKey(make([]byte, 129), salt, 1); err == nil {
		t.Error("129-byte password accepted")
	}
	if _, err := HeaderKey([]byte("x"), salt[:10], 1); err == nil {
		t.Error("short salt accepted")
	}
	k, err := HeaderKey([]byte("x"), salt, 1)
	if err != nil || len(k) != KeySize {
		t.Errorf("HeaderKey = %d bytes, %v", len(k), err)
	}
}
