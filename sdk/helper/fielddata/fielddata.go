package fielddata

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func Parse(previousValues map[string]interface{}, operation logical.Operation, fieldData *framework.FieldData) map[string]interface{} {
	if previousValues == nil {
		// This could be provided as nil for convenience if there's no previous value.
		// It will likely be untouched, but populate it just to be defensive
		// against nil pointers.
		previousValues = make(map[string]interface{})
	}
	// Return newValues as a separate map so if the caller needs to compare
	// before/after, they can.
	newValues := make(map[string]interface{})
	for schemaName, _ := range fieldData.Schema {
		switch operation {
		case logical.CreateOperation:
			// Get the value the user set, or its default.
			newValues[schemaName] = fieldData.Get(schemaName)
		case logical.UpdateOperation:
			// Only change the value if it was actually sent by the user.
			if raw, ok := fieldData.GetOk(schemaName); ok {
				newValues[schemaName] = raw
			} else {
				newValues[schemaName] = previousValues[schemaName]
			}
		}
	}
	return newValues
}
