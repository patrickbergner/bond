package config

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const schemaPath = "../../schema/bond-config.schema.json"

// schemaLocations maps each control-file struct to the schema object that
// describes it. A struct missing from this map is a struct the drift test
// cannot police, so adding one to the control file means adding it here.
var schemaLocations = map[reflect.Type]string{
	reflect.TypeOf(Config{}):   "",
	reflect.TypeOf(Target{}):   "target",
	reflect.TypeOf(Source{}):   "source",
	reflect.TypeOf(Settings{}): "settings",
	reflect.TypeOf(KeySlot{}):  "keySlot",
}

// TestSchemaMatchesStructs is the reason the JSON Schema can be trusted: it
// fails the moment a field exists on one side and not the other. Editors
// validate against the schema, the loader validates against the structs, and
// this keeps the two from telling the operator different things.
func TestSchemaMatchesStructs(t *testing.T) {
	root := loadSchema(t)
	defs, _ := root["$defs"].(map[string]any)
	if defs == nil {
		t.Fatal("schema has no $defs")
	}

	for typ, location := range schemaLocations {
		obj := root
		if location != "" {
			var ok bool
			obj, ok = defs[location].(map[string]any)
			if !ok {
				t.Errorf("%s: schema has no $defs/%s", typ, location)
				continue
			}
		}

		if additional, ok := obj["additionalProperties"].(bool); !ok || additional {
			t.Errorf("%s: $defs/%s must set additionalProperties:false, matching the loader's DisallowUnknownFields", typ, location)
		}

		props, _ := obj["properties"].(map[string]any)
		inSchema := make(map[string]bool, len(props))
		for name := range props {
			inSchema[name] = true
		}
		inGo := goFields(typ)

		for _, name := range sortedKeys(inGo) {
			if !inSchema[name] {
				t.Errorf("%s.%s is in Go but not in the schema (add it to $defs/%s)", typ.Name(), name, location)
			}
		}
		for _, name := range sortedKeys(inSchema) {
			if !inGo[name] {
				t.Errorf("%q is in schema $defs/%s but not on %s", name, location, typ.Name())
			}
		}
	}
}

// TestSchemaDefaultsMatchCode keeps the documented defaults honest – the
// schema is what an editor shows the operator, and Defaults is what actually
// runs.
func TestSchemaDefaultsMatchCode(t *testing.T) {
	root := loadSchema(t)
	defs := root["$defs"].(map[string]any)
	settings := defs["settings"].(map[string]any)
	props := settings["properties"].(map[string]any)

	d := Defaults()
	want := map[string]any{
		"compressionLevel": float64(d.CompressionLevel),
		"encryptionMethod": d.EncryptionMethod,
		"recoveryPercent":  float64(d.RecoveryPercent),
		"shardBytes":       float64(d.ShardBytes),
		"maxVolumeBytes":   float64(d.MaxVolumeBytes),
		"hashAlgorithm":    d.HashAlgorithm,
		"storeFileIndex":   d.StoreFileIndex,
		"followSymlinks":   d.FollowSymlinks,
		"outputPath":       d.OutputPath,
		"workPath":         d.WorkPath,
	}
	for name, expected := range want {
		prop, ok := props[name].(map[string]any)
		if !ok {
			t.Errorf("schema settings has no %q", name)
			continue
		}
		got, ok := prop["default"]
		if !ok {
			t.Errorf("schema settings.%s has no default, want %v", name, expected)
			continue
		}
		if got != expected {
			t.Errorf("schema settings.%s default = %v, want %v from Defaults()", name, got, expected)
		}
	}
}

// TestSchemaEnumsMatchCode does the same for the closed value sets.
func TestSchemaEnumsMatchCode(t *testing.T) {
	root := loadSchema(t)
	defs := root["$defs"].(map[string]any)

	settingsProps := defs["settings"].(map[string]any)["properties"].(map[string]any)
	slotProps := defs["keySlot"].(map[string]any)["properties"].(map[string]any)

	cases := []struct {
		name  string
		prop  map[string]any
		allow []string
	}{
		{"encryptionMethod", settingsProps["encryptionMethod"].(map[string]any), encryptionMethods},
		{"hashAlgorithm", settingsProps["hashAlgorithm"].(map[string]any), hashAlgorithms},
		{"keySlot.type", slotProps["type"].(map[string]any), slotTypes},
	}
	for _, tc := range cases {
		raw, _ := tc.prop["enum"].([]any)
		got := make([]string, 0, len(raw))
		for _, v := range raw {
			got = append(got, v.(string))
		}
		want := append([]string(nil), tc.allow...)
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("schema %s enum = %v, want %v", tc.name, got, want)
		}
	}
}

func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("reading schema: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("parsing schema: %v", err)
	}
	return root
}

func goFields(typ reflect.Type) map[string]bool {
	out := make(map[string]bool, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" {
			name = f.Name
		}
		if name == "-" {
			continue
		}
		out[name] = true
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
