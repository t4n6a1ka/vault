package userpass

import (
	"context"
	"fmt"
	"strings"
	"time"

	sockaddr "github.com/hashicorp/go-sockaddr"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathUsersList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "users/?",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathUserList,
		},

		HelpSynopsis:    pathUserHelpSyn,
		HelpDescription: pathUserHelpDesc,
	}
}

func pathUsers(b *backend) *framework.Path {
	p := &framework.Path{
		Pattern: "users/" + framework.GenericNameRegex("username"),
		Fields: map[string]*framework.FieldSchema{
			"username": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Username for this user.",
			},

			"password": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Password for this user.",
			},

			"policies": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: tokenutil.DeprecationText("token_policies"),
				Deprecated:  true,
			},

			"ttl": &framework.FieldSchema{
				Type:        framework.TypeDurationSecond,
				Description: tokenutil.DeprecationText("token_ttl"),
				Deprecated:  true,
			},

			"max_ttl": &framework.FieldSchema{
				Type:        framework.TypeDurationSecond,
				Description: tokenutil.DeprecationText("token_max_ttl"),
				Deprecated:  true,
			},

			"bound_cidrs": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: tokenutil.DeprecationText("token_bound_cidrs"),
				Deprecated:  true,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: b.pathUserDelete,
			logical.ReadOperation:   b.pathUserRead,
			logical.UpdateOperation: b.pathUserWrite,
			logical.CreateOperation: b.pathUserWrite,
		},

		ExistenceCheck: b.userExistenceCheck,

		HelpSynopsis:    pathUserHelpSyn,
		HelpDescription: pathUserHelpDesc,
	}

	tokenutil.AddTokenFields(p.Fields)
	return p
}

func (b *backend) userExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	userEntry, err := b.user(ctx, req.Storage, d.Get("username").(string))
	if err != nil {
		return false, err
	}

	return userEntry != nil, nil
}

func (b *backend) user(ctx context.Context, s logical.Storage, username string) (*UserEntry, error) {
	if username == "" {
		return nil, fmt.Errorf("missing username")
	}

	entry, err := s.Get(ctx, "user/"+strings.ToLower(username))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result UserEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	if result.TokenTTL == 0 && result.TTL > 0 {
		result.TokenTTL = result.TTL
	}
	if result.TokenMaxTTL == 0 && result.MaxTTL > 0 {
		result.TokenMaxTTL = result.MaxTTL
	}
	if len(result.TokenPolicies) == 0 && len(result.Policies) > 0 {
		result.TokenPolicies = result.Policies
	}
	if len(result.TokenBoundCIDRs) == 0 && len(result.BoundCIDRs) > 0 {
		result.TokenBoundCIDRs = result.BoundCIDRs
	}

	return &result, nil
}

func (b *backend) setUser(ctx context.Context, s logical.Storage, username string, userEntry *UserEntry) error {
	entry, err := logical.StorageEntryJSON("user/"+username, userEntry)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func (b *backend) pathUserList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	users, err := req.Storage.List(ctx, "user/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(users), nil
}

func (b *backend) pathUserDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "user/"+strings.ToLower(d.Get("username").(string)))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathUserRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	user, err := b.user(ctx, req.Storage, strings.ToLower(d.Get("username").(string)))
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	data := map[string]interface{}{}
	user.PopulateTokenData(data)

	// Add backwards compat data
	if user.TTL > 0 {
		data["ttl"] = int64(user.TTL.Seconds())
	}
	if user.MaxTTL > 0 {
		data["max_ttl"] = int64(user.MaxTTL.Seconds())
	}
	if len(user.Policies) > 0 {
		data["policies"] = data["token_policies"]
	}
	if len(user.BoundCIDRs) > 0 {
		data["bound_cidrs"] = user.BoundCIDRs
	}

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) userCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := strings.ToLower(d.Get("username").(string))
	userEntry, err := b.user(ctx, req.Storage, username)
	if err != nil {
		return nil, err
	}
	// Due to existence check, user will only be nil if it's a create operation
	if userEntry == nil {
		userEntry = &UserEntry{}
	}

	if err := userEntry.ParseTokenFields(req, d); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	if _, ok := d.GetOk("password"); ok {
		userErr, intErr := b.updateUserPassword(req, d, userEntry)
		if intErr != nil {
			return nil, err
		}
		if userErr != nil {
			return logical.ErrorResponse(userErr.Error()), logical.ErrInvalidRequest
		}
	}

	// handle upgrade cases
	{
		policiesRaw, ok := d.GetOk("token_policies")
		if !ok {
			policiesRaw, ok = d.GetOk("policies")
			if ok {
				userEntry.Policies = policyutil.ParsePolicies(policiesRaw)
				userEntry.TokenPolicies = nil
			}
		} else {
			_, ok = d.GetOk("policies")
			if ok {
				userEntry.Policies = userEntry.TokenPolicies
			} else {
				userEntry.Policies = nil
			}
		}

		ttlRaw, ok := d.GetOk("token_ttl")
		if !ok {
			ttlRaw, ok = d.GetOk("ttl")
			if ok {
				userEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
				userEntry.TokenTTL = 0
			}
		} else {
			_, ok = d.GetOk("ttl")
			if ok {
				userEntry.TTL = userEntry.TokenTTL
			} else {
				userEntry.TTL = 0
			}
		}

		maxTTLRaw, ok := d.GetOk("token_max_ttl")
		if !ok {
			maxTTLRaw, ok = d.GetOk("max_ttl")
			if ok {
				userEntry.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
				userEntry.TokenMaxTTL = 0
			}
		} else {
			_, ok = d.GetOk("max_ttl")
			if ok {
				userEntry.MaxTTL = userEntry.TokenMaxTTL
			} else {
				userEntry.MaxTTL = 0
			}
		}

		boundCIDRsRaw, ok := d.GetOk("token_bound_cidrs")
		if !ok {
			boundCIDRsRaw, ok = d.GetOk("bound_cidrs")
			if ok {
				boundCIDRs, err := parseutil.ParseAddrs(boundCIDRsRaw)
				if err != nil {
					return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
				}
				userEntry.BoundCIDRs = boundCIDRs
				userEntry.TokenBoundCIDRs = nil
			}
		} else {
			_, ok = d.GetOk("bound_cidrs")
			if ok {
				userEntry.BoundCIDRs = userEntry.TokenBoundCIDRs
			} else {
				userEntry.BoundCIDRs = nil
			}
		}
	}

	return nil, b.setUser(ctx, req.Storage, username, userEntry)
}

func (b *backend) pathUserWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	password := d.Get("password").(string)
	if req.Operation == logical.CreateOperation && password == "" {
		return logical.ErrorResponse("missing password"), logical.ErrInvalidRequest
	}
	return b.userCreateUpdate(ctx, req, d)
}

type UserEntry struct {
	tokenutil.TokenParams

	// Password is deprecated in Vault 0.2 in favor of
	// PasswordHash, but is retained for backwards compatibility.
	Password string

	// PasswordHash is a bcrypt hash of the password. This is
	// used instead of the actual password in Vault 0.2+.
	PasswordHash []byte

	Policies []string

	// Duration after which the user will be revoked unless renewed
	TTL time.Duration

	// Maximum duration for which user can be valid
	MaxTTL time.Duration

	BoundCIDRs []*sockaddr.SockAddrMarshaler
}

const pathUserHelpSyn = `
Manage users allowed to authenticate.
`

const pathUserHelpDesc = `
This endpoint allows you to create, read, update, and delete users
that are allowed to authenticate.

Deleting a user will not revoke auth for prior authenticated users
with that name. To do this, do a revoke on "login/<username>" for
the username you want revoked. If you don't need to revoke login immediately,
then the next renew will cause the lease to expire.
`
