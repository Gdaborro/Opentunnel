package serverpool

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// DecodeStrict accepts one unambiguous, non-null JSON value with exact field
// names. encoding/json alone accepts duplicate keys and case-insensitive field
// aliases; neither is appropriate for trust state or enrollment credentials.
// Callers must bound raw before calling. Only explicit structs/slices are used
// by the pool contract, and nesting is bounded independently of input size.
func DecodeStrict(raw []byte, dst any) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON must be valid UTF-8")
	}
	t := reflect.TypeOf(dst)
	if t == nil || t.Kind() != reflect.Pointer {
		return errors.New("JSON destination must be a pointer")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := validateJSON(dec, t.Elem(), 0); err != nil {
		return errors.New("JSON schema is ambiguous or invalid")
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("JSON must contain exactly one value")
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("JSON field value is invalid")
	}
	return nil
}

func validateJSON(dec *json.Decoder, t reflect.Type, depth int) error {
	if depth > 8 {
		return errors.New("JSON nesting limit")
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	tok, err := dec.Token()
	if err != nil || tok == nil {
		return errors.New("null or incomplete JSON")
	}
	switch t.Kind() {
	case reflect.Struct:
		if tok != json.Delim('{') {
			return errors.New("JSON object required")
		}
		fields := make(map[string]reflect.Type, t.NumField())
		for i := range t.NumField() {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue
			}
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name != "" && name != "-" {
				fields[name] = f.Type
			}
		}
		seen := make(map[string]bool, len(fields))
		for dec.More() {
			key, err := dec.Token()
			name, ok := key.(string)
			field, exists := fields[name]
			if err != nil || !ok || !exists || seen[name] {
				return errors.New("unknown or duplicate JSON field")
			}
			seen[name] = true
			if err := validateJSON(dec, field, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("incomplete JSON object")
		}
	case reflect.Slice, reflect.Array:
		if tok != json.Delim('[') {
			return errors.New("JSON array required")
		}
		for dec.More() {
			if err := validateJSON(dec, t.Elem(), depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("incomplete JSON array")
		}
	case reflect.String:
		if _, ok := tok.(string); !ok {
			return errors.New("JSON string required")
		}
	case reflect.Bool:
		if _, ok := tok.(bool); !ok {
			return errors.New("JSON boolean required")
		}
	case reflect.Int, reflect.Int64, reflect.Int32, reflect.Uint, reflect.Uint64, reflect.Float64:
		if _, ok := tok.(json.Number); !ok {
			return errors.New("JSON number required")
		}
	default:
		return errors.New("unsupported JSON schema type")
	}
	return nil
}
