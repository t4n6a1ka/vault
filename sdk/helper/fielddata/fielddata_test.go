package fielddata

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestParserCreateExplicitAndDefaults(t *testing.T) {
	fd := &framework.FieldData{
		Schema: testSchema,
	}
	for name, schema := range testSchema {
		// Test what happens when each field is explicitly set by the user.
		fd.Raw = make(map[string]interface{})
		fd.Raw[name] = example[schema.Type]

		result, err := Parse(nil, logical.CreateOperation, fd)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(result[name], fd.Get(name)) {
			t.Fatalf("for %s, expected %q but received %q", name, example[schema.Type], result[name])
		}

		// Test that defaults are used properly.
		if schema.Default != nil {
			fd = &framework.FieldData{
				Schema: testSchema,
				Raw:    make(map[string]interface{}),
			}
			result, err = Parse(nil, logical.CreateOperation, fd)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(result[name], schema.Default) {
				t.Fatalf("for %s, expected %q but received %q", name, schema.Default, result[name])
			}
		}
	}
}

func TestParseUpdate(t *testing.T) {
	raw := make(map[string]interface{})
	for name, schema := range testSchema {
		raw[name] = example[schema.Type]
	}
	fd := &framework.FieldData{
		Schema: testSchema,
		Raw:    raw,
	}
	resultFromCreation, err := Parse(nil, logical.CreateOperation, fd)
	if err != nil {
		t.Fatal(err)
	}
	if resultFromCreation["lower-case-string"] != "shouting" {
		t.Fatal("expected shouting")
	}
	fd.Raw["int"] = 1
	resultFromUpdate, err := Parse(resultFromCreation, logical.UpdateOperation, fd)
	if err != nil {
		t.Fatal(err)
	}
	if resultFromCreation["lower-case-string"] != "shouting" {
		t.Fatal("expected shouting")
	}
	if resultFromUpdate["int"].(int) != 1 {
		t.Fatal("expected 1")
	}
	if resultFromUpdate["bool"] == false {
		t.Fatal("expected true")
	}
	fd.Raw["bool"] = false
	resultFromUpdate, err = Parse(resultFromCreation, logical.UpdateOperation, fd)
	if err != nil {
		t.Fatal(err)
	}
	if resultFromCreation["lower-case-string"] != "shouting" {
		t.Fatal("expected shouting")
	}
	if resultFromUpdate["bool"] == true {
		t.Fatal("expected false")
	}
}

var testSchema = map[string]*framework.FieldSchema{
	"string-with-default": {
		Type:    framework.TypeString,
		Default: "default",
	},
	"int": {
		Type:    framework.TypeInt,
		Default: 12,
	},
	"bool": {
		Type:    framework.TypeBool,
		Default: true,
	},
	"map": {
		Type:    framework.TypeMap,
		Default: map[string]string{"favorite-fruit": "bananas"},
	},
	"duration-second": {
		Type:    framework.TypeDurationSecond,
		Default: 1,
	},
	"slice": {
		Type:    framework.TypeSlice,
		Default: []int{1, 2, 3},
	},
	"string-slice": {
		Type:    framework.TypeStringSlice,
		Default: []string{"apples", "oranges", "pears"},
	},
	"comma-string-slice": {
		Type: framework.TypeCommaStringSlice,
	},
	"lower-case-string": {
		Type: framework.TypeLowerCaseString,
	},
	"name-string": {
		Type: framework.TypeNameString,
	},
	"kv-pairs": {
		Type: framework.TypeKVPairs,
	},
	"comma-int-slice": {
		Type: framework.TypeCommaIntSlice,
	},
	"header": {
		Type: framework.TypeHeader,
	},
}

var example = map[framework.FieldType]interface{}{
	framework.TypeString: "string",
	framework.TypeInt:    1,
	framework.TypeBool:   true,
	framework.TypeMap: map[string]interface{}{
		"hello": "world",
	},
	framework.TypeDurationSecond:   100,
	framework.TypeSlice:            []bool{false},
	framework.TypeStringSlice:      []string{"one"},
	framework.TypeCommaStringSlice: "konnichiwa,chikyuu",
	framework.TypeLowerCaseString:  "SHOUTING",
	framework.TypeNameString:       "my-role",
	framework.TypeKVPairs:          "hola=terre",
	framework.TypeCommaIntSlice:    "1,2,3",
	framework.TypeHeader:           &http.Header{"Bonjour": []string{"monde"}},
}
