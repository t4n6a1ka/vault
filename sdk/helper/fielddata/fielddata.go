package fielddata

import (
	"fmt"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func Parse(previousValues map[string]interface{}, operation logical.Operation, fieldData *framework.FieldData) (map[string]interface{}, error) {
	if previousValues == nil {
		// This could be provided as nil for convenience if there's no previous value.
		// It will likely be untouched, but populate it just to be defensive
		// against nil pointers.
		previousValues = make(map[string]interface{})
	}
	// Return newValues as a separate map so if the caller needs to compare
	// before/after, they can.
	newValues := make(map[string]interface{})
	var result error
	for schemaName, schema := range fieldData.Schema {
		raw, ok := fieldData.GetOk(schemaName)
		switch operation {
		case logical.CreateOperation:
			if ok {
				// Use the value the user stated.
				newValues[schemaName] = raw
			} else {
				if schema.Required {
					result = multierror.Append(result, fmt.Errorf("%q is required but not provided", schemaName))
				}
				// Use the default value held in the schema.
				// (raw holds a nil value so Get is required to pull the default.)
				newValues[schemaName] = fieldData.Get(schemaName)
			}
		case logical.UpdateOperation:
			if ok {
				// Use the value the user stated.
				newValues[schemaName] = raw
			} else {
				// Retain the previous value.
				newValues[schemaName] = previousValues[schemaName]
			}
		}
	}
	return newValues, result
}
