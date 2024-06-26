// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// CoseV001Schema cose v0.0.1 Schema
//
// # Schema for cose object
//
// swagger:model coseV001Schema
type CoseV001Schema struct {

	// data
	Data *CoseV001SchemaData `json:"data,omitempty"`

	// The COSE Sign1 Message
	// Format: byte
	Message strfmt.Base64 `json:"message,omitempty"`

	// The public key that can verify the signature
	// Required: true
	// Format: byte
	PublicKey *strfmt.Base64 `json:"publicKey"`
}

// Validate validates this cose v001 schema
func (m *CoseV001Schema) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateData(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePublicKey(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CoseV001Schema) validateData(formats strfmt.Registry) error {
	if swag.IsZero(m.Data) { // not required
		return nil
	}

	if m.Data != nil {
		if err := m.Data.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("data")
			}
			return err
		}
	}

	return nil
}

func (m *CoseV001Schema) validatePublicKey(formats strfmt.Registry) error {

	if err := validate.Required("publicKey", "body", m.PublicKey); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this cose v001 schema based on the context it is used
func (m *CoseV001Schema) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CoseV001Schema) contextValidateData(ctx context.Context, formats strfmt.Registry) error {

	if m.Data != nil {

		if swag.IsZero(m.Data) { // not required
			return nil
		}

		if err := m.Data.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("data")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *CoseV001Schema) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CoseV001Schema) UnmarshalBinary(b []byte) error {
	var res CoseV001Schema
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// CoseV001SchemaData Information about the content associated with the entry
//
// swagger:model CoseV001SchemaData
type CoseV001SchemaData struct {

	// Specifies the additional authenticated data required to verify the signature
	// Format: byte
	Aad strfmt.Base64 `json:"aad,omitempty"`

	// envelope hash
	EnvelopeHash *CoseV001SchemaDataEnvelopeHash `json:"envelopeHash,omitempty"`

	// payload hash
	PayloadHash *CoseV001SchemaDataPayloadHash `json:"payloadHash,omitempty"`
}

// Validate validates this cose v001 schema data
func (m *CoseV001SchemaData) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEnvelopeHash(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePayloadHash(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CoseV001SchemaData) validateEnvelopeHash(formats strfmt.Registry) error {
	if swag.IsZero(m.EnvelopeHash) { // not required
		return nil
	}

	if m.EnvelopeHash != nil {
		if err := m.EnvelopeHash.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("data" + "." + "envelopeHash")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("data" + "." + "envelopeHash")
			}
			return err
		}
	}

	return nil
}

func (m *CoseV001SchemaData) validatePayloadHash(formats strfmt.Registry) error {
	if swag.IsZero(m.PayloadHash) { // not required
		return nil
	}

	if m.PayloadHash != nil {
		if err := m.PayloadHash.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("data" + "." + "payloadHash")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("data" + "." + "payloadHash")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this cose v001 schema data based on the context it is used
func (m *CoseV001SchemaData) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateEnvelopeHash(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePayloadHash(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CoseV001SchemaData) contextValidateEnvelopeHash(ctx context.Context, formats strfmt.Registry) error {

	if m.EnvelopeHash != nil {

		if swag.IsZero(m.EnvelopeHash) { // not required
			return nil
		}

		if err := m.EnvelopeHash.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("data" + "." + "envelopeHash")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("data" + "." + "envelopeHash")
			}
			return err
		}
	}

	return nil
}

func (m *CoseV001SchemaData) contextValidatePayloadHash(ctx context.Context, formats strfmt.Registry) error {

	if m.PayloadHash != nil {

		if swag.IsZero(m.PayloadHash) { // not required
			return nil
		}

		if err := m.PayloadHash.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("data" + "." + "payloadHash")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("data" + "." + "payloadHash")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *CoseV001SchemaData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CoseV001SchemaData) UnmarshalBinary(b []byte) error {
	var res CoseV001SchemaData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// CoseV001SchemaDataEnvelopeHash Specifies the hash algorithm and value for the COSE envelope
//
// swagger:model CoseV001SchemaDataEnvelopeHash
type CoseV001SchemaDataEnvelopeHash struct {

	// The hashing function used to compute the hash value
	// Required: true
	// Enum: [sha256]
	Algorithm *string `json:"algorithm"`

	// The hash value for the envelope
	// Required: true
	Value *string `json:"value"`
}

// Validate validates this cose v001 schema data envelope hash
func (m *CoseV001SchemaDataEnvelopeHash) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAlgorithm(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateValue(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var coseV001SchemaDataEnvelopeHashTypeAlgorithmPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["sha256"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		coseV001SchemaDataEnvelopeHashTypeAlgorithmPropEnum = append(coseV001SchemaDataEnvelopeHashTypeAlgorithmPropEnum, v)
	}
}

const (

	// CoseV001SchemaDataEnvelopeHashAlgorithmSha256 captures enum value "sha256"
	CoseV001SchemaDataEnvelopeHashAlgorithmSha256 string = "sha256"
)

// prop value enum
func (m *CoseV001SchemaDataEnvelopeHash) validateAlgorithmEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, coseV001SchemaDataEnvelopeHashTypeAlgorithmPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *CoseV001SchemaDataEnvelopeHash) validateAlgorithm(formats strfmt.Registry) error {

	if err := validate.Required("data"+"."+"envelopeHash"+"."+"algorithm", "body", m.Algorithm); err != nil {
		return err
	}

	// value enum
	if err := m.validateAlgorithmEnum("data"+"."+"envelopeHash"+"."+"algorithm", "body", *m.Algorithm); err != nil {
		return err
	}

	return nil
}

func (m *CoseV001SchemaDataEnvelopeHash) validateValue(formats strfmt.Registry) error {

	if err := validate.Required("data"+"."+"envelopeHash"+"."+"value", "body", m.Value); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this cose v001 schema data envelope hash based on the context it is used
func (m *CoseV001SchemaDataEnvelopeHash) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// MarshalBinary interface implementation
func (m *CoseV001SchemaDataEnvelopeHash) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CoseV001SchemaDataEnvelopeHash) UnmarshalBinary(b []byte) error {
	var res CoseV001SchemaDataEnvelopeHash
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// CoseV001SchemaDataPayloadHash Specifies the hash algorithm and value for the content
//
// swagger:model CoseV001SchemaDataPayloadHash
type CoseV001SchemaDataPayloadHash struct {

	// The hashing function used to compute the hash value
	// Required: true
	// Enum: [sha256]
	Algorithm *string `json:"algorithm"`

	// The hash value for the content
	// Required: true
	Value *string `json:"value"`
}

// Validate validates this cose v001 schema data payload hash
func (m *CoseV001SchemaDataPayloadHash) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAlgorithm(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateValue(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var coseV001SchemaDataPayloadHashTypeAlgorithmPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["sha256"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		coseV001SchemaDataPayloadHashTypeAlgorithmPropEnum = append(coseV001SchemaDataPayloadHashTypeAlgorithmPropEnum, v)
	}
}

const (

	// CoseV001SchemaDataPayloadHashAlgorithmSha256 captures enum value "sha256"
	CoseV001SchemaDataPayloadHashAlgorithmSha256 string = "sha256"
)

// prop value enum
func (m *CoseV001SchemaDataPayloadHash) validateAlgorithmEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, coseV001SchemaDataPayloadHashTypeAlgorithmPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *CoseV001SchemaDataPayloadHash) validateAlgorithm(formats strfmt.Registry) error {

	if err := validate.Required("data"+"."+"payloadHash"+"."+"algorithm", "body", m.Algorithm); err != nil {
		return err
	}

	// value enum
	if err := m.validateAlgorithmEnum("data"+"."+"payloadHash"+"."+"algorithm", "body", *m.Algorithm); err != nil {
		return err
	}

	return nil
}

func (m *CoseV001SchemaDataPayloadHash) validateValue(formats strfmt.Registry) error {

	if err := validate.Required("data"+"."+"payloadHash"+"."+"value", "body", m.Value); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this cose v001 schema data payload hash based on the context it is used
func (m *CoseV001SchemaDataPayloadHash) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// MarshalBinary interface implementation
func (m *CoseV001SchemaDataPayloadHash) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CoseV001SchemaDataPayloadHash) UnmarshalBinary(b []byte) error {
	var res CoseV001SchemaDataPayloadHash
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
