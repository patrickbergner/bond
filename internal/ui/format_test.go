package ui

import "testing"

func TestBytes(t *testing.T) {
	cases := map[int64]string{
		0:           "0 B",
		512:         "512 B",
		1023:        "1023 B",
		1024:        "1.00 KiB",
		1536:        "1.50 KiB",
		10 * 1024:   "10.0 KiB",
		100 * 1024:  "100 KiB",
		1024 * 1024: "1.00 MiB",
		207 << 30:   "207 GiB",
		5 << 40:     "5.00 TiB",
		1 << 60:     "1.00 EiB",
	}
	for in, want := range cases {
		if got := Bytes(in); got != want {
			t.Errorf("Bytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestCount(t *testing.T) {
	cases := map[int]string{
		0:       "0",
		7:       "7",
		999:     "999",
		1000:    "1,000",
		12345:   "12,345",
		1234567: "1,234,567",
		-4567:   "-4,567",
	}
	for in, want := range cases {
		if got := Count(in); got != want {
			t.Errorf("Count(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestItems(t *testing.T) {
	if got := Items(1, "file", "files"); got != "1 file" {
		t.Errorf("Items(1) = %q", got)
	}
	if got := Items(2345, "file", "files"); got != "2,345 files" {
		t.Errorf("Items(2345) = %q", got)
	}
}
