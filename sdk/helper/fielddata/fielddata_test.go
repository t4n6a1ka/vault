package fielddata

import (
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"testing"
)

type testConf struct {
	Url            string `json:"url,omitempty"`
	UserDN         string `json:"userdn"`
	BindDN         string `json:"bind_dn"`
	CaseSensitiveNames *bool `json:"CaseSensitiveNames,omitempty"`
}

func TestParser(t *testing.T) {
	// TODO the name differences seem error-prone, can they be detected?
	testConfParser := NewParser(&NameDifference{
		SchemaName: "case_sensitive_names",
		JSONName:   "CaseSensitiveNames",
	}, &NameDifference{
		SchemaName: "user_dn",
		JSONName:   "userdn",
	})
	fd := &framework.FieldData{
		Schema:map[string]*framework.FieldSchema{
			"url": {
				Type: framework.TypeString,
			},
			"user_dn": {
				Type: framework.TypeString,
			},
			"bind_dn": {
				Type: framework.TypeString,
			},
			"case_sensitive_names": {
				Type: framework.TypeBool,
			},
		},
		Raw: map[string]interface{}{
			"url": "http://foo.com",
			"user_dn": "some-user-dn",
			"bind_dn": "some-bind-dn",
			"case_sensitive_names": false,
		},
	}
	newConf, err := testConfParser.Parse(&testConf{}, logical.UpdateOperation, fd)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%+v\n", newConf)
}
