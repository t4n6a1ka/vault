package fielddata

import (
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

func TestParser(t *testing.T) {
	fd := &framework.FieldData{
		Schema:ConfigFields(),
		Raw: map[string]interface{}{
			"user_dn": "some-user-dn",
			"binddn": "some-bind-dn",
			"case_sensitive_names": false,
		},
	}
	firstResult := Parse(nil, logical.CreateOperation, fd)
	fmt.Printf("%+v\n", firstResult)

	firstConf := &testConf{}
	// We tend to avoid using mapstructure in many places because it's too
	// easy to return fields that shouldn't be returned. However, here it's
	// not being used in such a situation.
	if err := mapstructure.Decode(firstResult, firstConf); err != nil {
		t.Fatal(err)
	}

	fd.Raw["binddn"] = "new"
	secondResult := Parse(firstResult, logical.UpdateOperation, fd)

	secondConf := &testConf{}
	if err := mapstructure.Decode(secondResult, secondConf); err != nil {
		t.Fatal(err)
	}
	fmt.Println(secondConf)
}

func ConfigFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"url": {
			Type:        framework.TypeString,
			Default:     "ldap://127.0.0.1",
			Description: "LDAP URL to connect to (default: ldap://127.0.0.1). Multiple URLs can be specified by concatenating them with commas; they will be tried in-order.",
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "URL",
			},
		},

		"userdn": {
			Type:        framework.TypeString,
			Description: "LDAP domain to use for users (eg: ou=People,dc=example,dc=org)",
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "User DN",
			},
		},

		"binddn": {
			Type:        framework.TypeString,
			Description: "LDAP DN for searching for the user DN (optional)",
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "Name of Object to bind (binddn)",
			},
		},

		"bindpass": {
			Type:        framework.TypeString,
			Description: "LDAP password for searching for the user DN (optional)",
			DisplayAttrs: &framework.DisplayAttributes{
				Sensitive: true,
			},
		},

		"groupdn": {
			Type:        framework.TypeString,
			Description: "LDAP search base to use for group membership search (eg: ou=Groups,dc=example,dc=org)",
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "Group DN",
			},
		},

		"groupfilter": {
			Type:    framework.TypeString,
			Default: "(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))",
			Description: `Go template for querying group membership of user (optional)
The template can access the following context variables: UserDN, Username
Example: (&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))
Default: (|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))`,
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "Group Filter",
			},
		},

		"groupattr": {
			Type:    framework.TypeString,
			Default: "cn",
			Description: `LDAP attribute to follow on objects returned by <groupfilter>
in order to enumerate user group membership.
Examples: "cn" or "memberOf", etc.
Default: cn`,
			DisplayAttrs: &framework.DisplayAttributes{
				Name:  "Group Attribute",
				Value: "cn",
			},
		},

		"upndomain": {
			Type:        framework.TypeString,
			Description: "Enables userPrincipalDomain login with [username]@UPNDomain (optional)",
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "User Principal (UPN) Domain",
			},
		},

		"userattr": {
			Type:        framework.TypeString,
			Default:     "cn",
			Description: "Attribute used for users (default: cn)",
			DisplayAttrs: &framework.DisplayAttributes{
				Name:  "User Attribute",
				Value: "cn",
			},
		},

		"certificate": {
			Type:        framework.TypeString,
			Description: "CA certificate to use when verifying LDAP server certificate, must be x509 PEM encoded (optional)",
		},

		"discoverdn": {
			Type:        framework.TypeBool,
			Description: "Use anonymous bind to discover the bind DN of a user (optional)",
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "Discover DN",
			},
		},

		"insecure_tls": {
			Type:        framework.TypeBool,
			Description: "Skip LDAP server SSL Certificate verification - VERY insecure (optional)",
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "Insecure TLS",
			},
		},

		"starttls": {
			Type:        framework.TypeBool,
			Description: "Issue a StartTLS command after establishing unencrypted connection (optional)",
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "Issue StartTLS",
			},
		},

		"tls_min_version": {
			Type:        framework.TypeString,
			Default:     "tls12",
			Description: "Minimum TLS version to use. Accepted values are 'tls10', 'tls11' or 'tls12'. Defaults to 'tls12'",
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "Minimum TLS Version",
			},
			AllowedValues: []interface{}{"tls10", "tls11", "tls12"},
		},

		"tls_max_version": {
			Type:        framework.TypeString,
			Default:     "tls12",
			Description: "Maximum TLS version to use. Accepted values are 'tls10', 'tls11' or 'tls12'. Defaults to 'tls12'",
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "Maximum TLS Version",
			},
			AllowedValues: []interface{}{"tls10", "tls11", "tls12"},
		},

		"deny_null_bind": {
			Type:        framework.TypeBool,
			Default:     true,
			Description: "Denies an unauthenticated LDAP bind request if the user's password is empty; defaults to true",
		},

		"case_sensitive_names": {
			Type:        framework.TypeBool,
			Description: "If true, case sensitivity will be used when comparing usernames and groups for matching policies.",
		},

		"use_token_groups": {
			Type:        framework.TypeBool,
			Default:     false,
			Description: "If true, use the Active Directory tokenGroups constructed attribute of the user to find the group memberships. This will find all security groups including nested ones.",
		},
	}
}

type testConf struct {
	Url            string `json:"url"`
	UserDN         string `json:"userdn"`
	GroupDN        string `json:"groupdn"`
	GroupFilter    string `json:"groupfilter"`
	GroupAttr      string `json:"groupattr"`
	UPNDomain      string `json:"upndomain"`
	UserAttr       string `json:"userattr"`
	Certificate    string `json:"certificate"`
	InsecureTLS    bool   `json:"insecure_tls"`
	StartTLS       bool   `json:"starttls"`
	BindDN         string `json:"binddn"`
	BindPassword   string `json:"bindpass"`
	DenyNullBind   bool   `json:"deny_null_bind"`
	DiscoverDN     bool   `json:"discoverdn"`
	TLSMinVersion  string `json:"tls_min_version"`
	TLSMaxVersion  string `json:"tls_max_version"`
	UseTokenGroups bool   `json:"use_token_groups"`

	// This json tag deviates from snake case because there was a past issue
	// where the tag was being ignored, causing it to be jsonified as "CaseSensitiveNames".
	// To continue reading in users' previously stored values,
	// we chose to carry that forward.
	CaseSensitiveNames *bool `json:"CaseSensitiveNames,omitempty"`
}
