package fielddata

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func NewParser(differences ...*NameDifference) *Parser {
	return &Parser{
		differences:differences,
	}
}

type Parser struct {
	differences []*NameDifference
}

func (p *Parser) Parse(stronglyTypedObject interface{}, operation logical.Operation, fieldData *framework.FieldData) (interface{}, error) {
	if stronglyTypedObject == nil {
		// We need the original object, rather than nil, so we can return the result
		// as that type of object.
		return nil, errors.New("original object is required")
	}
	objJson, err := json.Marshal(stronglyTypedObject)
	if err != nil {
		return nil, err
	}
	objAsJsonMap := make(map[string]interface{})
	if err := json.NewDecoder(bytes.NewBuffer(objJson)).Decode(&objAsJsonMap); err != nil {
		return nil, err
	}

	// TODO sort the field schema and the differences so matches are found more quickly?
	for schemaName, _ := range fieldData.Schema {
		jsonName := schemaName
		for _, difference := range p.differences {
			if difference.SchemaName == schemaName {
				jsonName = difference.JSONName
				break // TODO ensure this is only breaking the inner loop
			}
		}
		switch operation {
		case logical.CreateOperation:
			// Get a value that's set or default to the schema's value.
			objAsJsonMap[jsonName] = fieldData.Get(schemaName)
		case logical.UpdateOperation:
			// Only change the value if it was actually sent.
			if raw, ok := fieldData.GetOk(schemaName); ok {
				objAsJsonMap[jsonName] = raw
			}
		default:
			return nil, errors.New("unsupported operation")
		}
	}
	objJson, err = json.Marshal(objAsJsonMap)
	if err != nil {
		return nil, err
	}
	if err := json.NewDecoder(bytes.NewReader(objJson)).Decode(stronglyTypedObject); err != nil {
		return nil, err
	}
	return stronglyTypedObject, nil
}

type NameDifference struct {
	SchemaName string
	JSONName   string
}
