package domain

import "encoding/json"

// EmptyRaw returns an empty JSON object for raw_json.
func EmptyRaw() json.RawMessage {
	return json.RawMessage("{}")
}

// MarshalRaw serializes named string blobs into raw_json.
func MarshalRaw(blobs map[string]string) (json.RawMessage, error) {
	if len(blobs) == 0 {
		return EmptyRaw(), nil
	}
	data, err := json.Marshal(blobs)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}
