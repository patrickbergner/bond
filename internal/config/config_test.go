package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

const minimal = `{
  "targets": [ { "id": "tools", "sources": [ { "path": "/data/tools" } ] } ]
}`

func TestParseAppliesDefaults(t *testing.T) {
	cfg, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := cfg.Targets[0].Effective()
	want := Defaults()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("effective settings = %+v, want %+v", got, want)
	}
}

func TestParseMergesThreeLayers(t *testing.T) {
	const src = `{
      "targets": [
        { "id": "music", "sources": [ { "path": "/music" } ],
          "settings": { "compressionLevel": 0 } },
        { "id": "docs", "sources": [ { "path": "/docs" } ] }
      ],
      "settings": { "compressionLevel": 7, "recoveryPercent": 20 }
    }`
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	music := cfg.Targets[0].Effective()
	if music.CompressionLevel != 0 {
		t.Errorf("music compressionLevel = %d, want 0 (an explicit zero must survive the merge)", music.CompressionLevel)
	}
	if music.RecoveryPercent != 20 {
		t.Errorf("music recoveryPercent = %d, want 20 inherited from the global block", music.RecoveryPercent)
	}
	docs := cfg.Targets[1].Effective()
	if docs.CompressionLevel != 7 {
		t.Errorf("docs compressionLevel = %d, want 7", docs.CompressionLevel)
	}
	if docs.HashAlgorithm != HashSHA384 {
		t.Errorf("docs hashAlgorithm = %q, want the default %q", docs.HashAlgorithm, HashSHA384)
	}
}

func TestParseRejects(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "unknown field",
			src:  `{"targets":[{"id":"a","sources":[{"path":"/a"}],"excludedFilenames":["x"]}]}`,
			want: "excludedFilenames",
		},
		{
			name: "no targets",
			src:  `{"targets":[]}`,
			want: "at least one target",
		},
		{
			name: "missing id",
			src:  `{"targets":[{"sources":[{"path":"/a"}]}]}`,
			want: "id is required",
		},
		{
			name: "id unusable as a file name",
			src:  `{"targets":[{"id":"a/b","sources":[{"path":"/a"}]}]}`,
			want: "becomes a file name",
		},
		{
			name: "duplicate id",
			src:  `{"targets":[{"id":"a","sources":[{"path":"/a"}]},{"id":"A","sources":[{"path":"/b"}]}]}`,
			want: "duplicate id",
		},
		{
			name: "no sources",
			src:  `{"targets":[{"id":"a","sources":[]}]}`,
			want: "at least one source",
		},
		{
			name: "relative source path",
			src:  `{"targets":[{"id":"a","sources":[{"path":"tools"}]}]}`,
			want: "must be absolute",
		},
		{
			name: "bad regex",
			src:  `{"targets":[{"id":"a","sources":[{"path":"/a","excludedPathPatterns":["("]}]}]}`,
			want: "not a valid regular expression",
		},
		{
			name: "path in a name list",
			src:  `{"targets":[{"id":"a","sources":[{"path":"/a","excludedDirectoryNames":["x/y"]}]}]}`,
			want: "is a path, not a name",
		},
		{
			name: "absolute filter entry",
			src:  `{"targets":[{"id":"a","sources":[{"path":"/a","excludedPaths":["/etc"]}]}]}`,
			want: "must be relative to the source path",
		},
		{
			name: "unknown encryption method",
			src:  `{"targets":[{"id":"a","sources":[{"path":"/a"}]}],"settings":{"encryptionMethod":"ROT13"}}`,
			want: "encryptionMethod",
		},
		{
			name: "recovery percent out of range",
			src:  `{"targets":[{"id":"a","sources":[{"path":"/a"}]}],"settings":{"recoveryPercent":80}}`,
			want: "outside 0..50",
		},
		{
			name: "shard size not a multiple of 4096",
			src:  `{"targets":[{"id":"a","sources":[{"path":"/a"}]}],"settings":{"shardBytes":100000}}`,
			want: "multiple of 4096",
		},
		{
			name: "keyfile slot without a path",
			src:  `{"targets":[{"id":"a","sources":[{"path":"/a"}]}],"settings":{"keySlots":[{"type":"keyfile"}]}}`,
			want: "needs a path",
		},
		{
			name: "recipient slot without a key",
			src:  `{"targets":[{"id":"a","sources":[{"path":"/a"}]}],"settings":{"keySlots":[{"type":"recipient"}]}}`,
			want: "needs a publicKey",
		},
		{
			name: "misspelled placeholder",
			src:  `{"targets":[{"id":"a","sources":[{"path":"/a"}]}],"settings":{"outputPath":"{{TOOLDIR}}/out"}}`,
			want: "unknown placeholder",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.src))
			if err == nil {
				t.Fatalf("Parse succeeded, want an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v\nwant it to mention %q", err, tc.want)
			}
		})
	}
}

func TestParseReportsEveryProblemAtOnce(t *testing.T) {
	const src = `{"targets":[
      {"id":"","sources":[]},
      {"id":"b","sources":[{"path":"rel"}]}
    ]}`
	_, err := Parse([]byte(src))
	if err == nil {
		t.Fatal("Parse succeeded on a control file with several problems")
	}
	var ve *Error
	if e, ok := err.(*Error); ok {
		ve = e
	} else {
		t.Fatalf("error type = %T, want *Error", err)
	}
	if len(ve.Problems) < 3 {
		t.Errorf("reported %d problems, want at least 3:\n%v", len(ve.Problems), err)
	}
}

func TestSelected(t *testing.T) {
	const src = `{"targets":[
      {"id":"a","sources":[{"path":"/a"}]},
      {"id":"b","skip":true,"sources":[{"path":"/b"}]},
      {"id":"c","sources":[{"path":"/c"}]}
    ]}`
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	got, err := cfg.Selected(nil)
	if err != nil {
		t.Fatalf("Selected(nil): %v", err)
	}
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "c" {
		t.Errorf("Selected(nil) = %v, want the two targets that are not skipped", ids(got))
	}

	got, err = cfg.Selected([]string{"B"})
	if err != nil {
		t.Fatalf("Selected([B]): %v", err)
	}
	if len(got) != 1 || got[0].ID != "b" {
		t.Errorf("Selected([B]) = %v, want [b] – naming a target explicitly overrides skip", ids(got))
	}

	if _, err := cfg.Selected([]string{"nope"}); err == nil {
		t.Error("Selected([nope]) succeeded, want an error naming the unknown target")
	}
}

func ids(ts []*Target) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.ID
	}
	return out
}

func TestExpand(t *testing.T) {
	at := time.Date(2026, 8, 18, 21, 30, 5, 0, time.UTC)
	vars := Vars{VarToolDir: "/opt/bond", VarHome: "/home/p"}.ForTarget("photos", at)

	cases := []struct{ in, want string }{
		{"{{TOOL_DIR}}/output", "/opt/bond/output"},
		{"{{HOME}}/keys/{{TARGET_ID}}.key", "/home/p/keys/photos.key"},
		{"{{TARGET_ID}}-{{TIMESTAMP}}.bond", "photos-20260818-213005.bond"},
		{"backup on {{DATE}}", "backup on 2026-08-18"},
		{"nothing to do here", "nothing to do here"},
	}
	for _, tc := range cases {
		got, err := Expand(tc.in, vars)
		if err != nil {
			t.Errorf("Expand(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Expand(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	if _, err := Expand("{{NOPE}}", vars); err == nil {
		t.Error("Expand({{NOPE}}) succeeded, want an error")
	}
	if _, err := Expand("{{TOOL_DIR", vars); err == nil {
		t.Error("Expand of an unterminated placeholder succeeded, want an error")
	}
	if _, err := Expand("{{TARGET_ID}}", Vars{}); err == nil {
		t.Error("Expand succeeded with no value for the placeholder, want an error")
	}
}

func TestSampleControlFileIsValid(t *testing.T) {
	cfg, err := Load("../../config.sample.json")
	if err != nil {
		t.Fatalf("the sample control file must stay loadable: %v", err)
	}
	if len(cfg.Targets) == 0 {
		t.Fatal("sample control file has no targets")
	}
}
