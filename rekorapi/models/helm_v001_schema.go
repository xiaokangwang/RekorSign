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

// HelmV001Schema Helm v0.0.1 Schema
//
// # Schema for Helm object
//
// swagger:model helmV001Schema
type HelmV001Schema struct {

	// chart
	// Required: true
	Chart *HelmV001SchemaChart `json:"chart"`

	// public key
	// Required: true
	PublicKey *HelmV001SchemaPublicKey `json:"publicKey"`
}

// Validate validates this helm v001 schema
func (m *HelmV001Schema) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateChart(formats); err != nil {
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

func (m *HelmV001Schema) validateChart(formats strfmt.Registry) error {

	if err := validate.Required("chart", "body", m.Chart); err != nil {
		return err
	}

	if m.Chart != nil {
		if err := m.Chart.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("chart")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("chart")
			}
			return err
		}
	}

	return nil
}

func (m *HelmV001Schema) validatePublicKey(formats strfmt.Registry) error {

	if err := validate.Required("publicKey", "body", m.PublicKey); err != nil {
		return err
	}

	if m.PublicKey != nil {
		if err := m.PublicKey.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("publicKey")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("publicKey")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this helm v001 schema based on the context it is used
func (m *HelmV001Schema) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateChart(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePublicKey(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *HelmV001Schema) contextValidateChart(ctx context.Context, formats strfmt.Registry) error {

	if m.Chart != nil {

		if err := m.Chart.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("chart")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("chart")
			}
			return err
		}
	}

	return nil
}

func (m *HelmV001Schema) contextValidatePublicKey(ctx context.Context, formats strfmt.Registry) error {

	if m.PublicKey != nil {

		if err := m.PublicKey.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("publicKey")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("publicKey")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *HelmV001Schema) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *HelmV001Schema) UnmarshalBinary(b []byte) error {
	var res HelmV001Schema
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// HelmV001SchemaChart Information about the Helm chart associated with the entry
//
// swagger:model HelmV001SchemaChart
type HelmV001SchemaChart struct {

	// hash
	Hash *HelmV001SchemaChartHash `json:"hash,omitempty"`

	// provenance
	// Required: true
	Provenance *HelmV001SchemaChartProvenance `json:"provenance"`
}

// Validate validates this helm v001 schema chart
func (m *HelmV001SchemaChart) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateHash(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProvenance(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *HelmV001SchemaChart) validateHash(formats strfmt.Registry) error {
	if swag.IsZero(m.Hash) { // not required
		return nil
	}

	if m.Hash != nil {
		if err := m.Hash.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("chart" + "." + "hash")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("chart" + "." + "hash")
			}
			return err
		}
	}

	return nil
}

func (m *HelmV001SchemaChart) validateProvenance(formats strfmt.Registry) error {

	if err := validate.Required("chart"+"."+"provenance", "body", m.Provenance); err != nil {
		return err
	}

	if m.Provenance != nil {
		if err := m.Provenance.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("chart" + "." + "provenance")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("chart" + "." + "provenance")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this helm v001 schema chart based on the context it is used
func (m *HelmV001SchemaChart) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateHash(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateProvenance(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *HelmV001SchemaChart) contextValidateHash(ctx context.Context, formats strfmt.Registry) error {

	if m.Hash != nil {

		if swag.IsZero(m.Hash) { // not required
			return nil
		}

		if err := m.Hash.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("chart" + "." + "hash")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("chart" + "." + "hash")
			}
			return err
		}
	}

	return nil
}

func (m *HelmV001SchemaChart) contextValidateProvenance(ctx context.Context, formats strfmt.Registry) error {

	if m.Provenance != nil {

		if err := m.Provenance.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("chart" + "." + "provenance")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("chart" + "." + "provenance")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *HelmV001SchemaChart) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *HelmV001SchemaChart) UnmarshalBinary(b []byte) error {
	var res HelmV001SchemaChart
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// HelmV001SchemaChartHash Specifies the hash algorithm and value for the chart
//
// swagger:model HelmV001SchemaChartHash
type HelmV001SchemaChartHash struct {

	// The hashing function used to compute the hash value
	// Required: true
	// Enum: [sha256]
	Algorithm *string `json:"algorithm"`

	// The hash value for the chart
	// Required: true
	Value *string `json:"value"`
}

// Validate validates this helm v001 schema chart hash
func (m *HelmV001SchemaChartHash) Validate(formats strfmt.Registry) error {
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

var helmV001SchemaChartHashTypeAlgorithmPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["sha256"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		helmV001SchemaChartHashTypeAlgorithmPropEnum = append(helmV001SchemaChartHashTypeAlgorithmPropEnum, v)
	}
}

const (

	// HelmV001SchemaChartHashAlgorithmSha256 captures enum value "sha256"
	HelmV001SchemaChartHashAlgorithmSha256 string = "sha256"
)

// prop value enum
func (m *HelmV001SchemaChartHash) validateAlgorithmEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, helmV001SchemaChartHashTypeAlgorithmPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *HelmV001SchemaChartHash) validateAlgorithm(formats strfmt.Registry) error {

	if err := validate.Required("chart"+"."+"hash"+"."+"algorithm", "body", m.Algorithm); err != nil {
		return err
	}

	// value enum
	if err := m.validateAlgorithmEnum("chart"+"."+"hash"+"."+"algorithm", "body", *m.Algorithm); err != nil {
		return err
	}

	return nil
}

func (m *HelmV001SchemaChartHash) validateValue(formats strfmt.Registry) error {

	if err := validate.Required("chart"+"."+"hash"+"."+"value", "body", m.Value); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this helm v001 schema chart hash based on the context it is used
func (m *HelmV001SchemaChartHash) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// MarshalBinary interface implementation
func (m *HelmV001SchemaChartHash) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *HelmV001SchemaChartHash) UnmarshalBinary(b []byte) error {
	var res HelmV001SchemaChartHash
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// HelmV001SchemaChartProvenance The provenance entry associated with the signed Helm Chart
//
// swagger:model HelmV001SchemaChartProvenance
type HelmV001SchemaChartProvenance struct {

	// Specifies the content of the provenance file inline within the document
	// Format: byte
	Content strfmt.Base64 `json:"content,omitempty"`

	// signature
	Signature *HelmV001SchemaChartProvenanceSignature `json:"signature,omitempty"`
}

// Validate validates this helm v001 schema chart provenance
func (m *HelmV001SchemaChartProvenance) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSignature(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *HelmV001SchemaChartProvenance) validateSignature(formats strfmt.Registry) error {
	if swag.IsZero(m.Signature) { // not required
		return nil
	}

	if m.Signature != nil {
		if err := m.Signature.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("chart" + "." + "provenance" + "." + "signature")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("chart" + "." + "provenance" + "." + "signature")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this helm v001 schema chart provenance based on the context it is used
func (m *HelmV001SchemaChartProvenance) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateSignature(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *HelmV001SchemaChartProvenance) contextValidateSignature(ctx context.Context, formats strfmt.Registry) error {

	if m.Signature != nil {

		if swag.IsZero(m.Signature) { // not required
			return nil
		}

		if err := m.Signature.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("chart" + "." + "provenance" + "." + "signature")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("chart" + "." + "provenance" + "." + "signature")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *HelmV001SchemaChartProvenance) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *HelmV001SchemaChartProvenance) UnmarshalBinary(b []byte) error {
	var res HelmV001SchemaChartProvenance
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// HelmV001SchemaChartProvenanceSignature Information about the included signature in the provenance file
//
// swagger:model HelmV001SchemaChartProvenanceSignature
type HelmV001SchemaChartProvenanceSignature struct {

	// Specifies the signature embedded within the provenance file
	// Required: true
	// Read Only: true
	// Format: byte
	Content strfmt.Base64 `json:"content"`
}

// Validate validates this helm v001 schema chart provenance signature
func (m *HelmV001SchemaChartProvenanceSignature) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateContent(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *HelmV001SchemaChartProvenanceSignature) validateContent(formats strfmt.Registry) error {

	if err := validate.Required("chart"+"."+"provenance"+"."+"signature"+"."+"content", "body", strfmt.Base64(m.Content)); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this helm v001 schema chart provenance signature based on the context it is used
func (m *HelmV001SchemaChartProvenanceSignature) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateContent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *HelmV001SchemaChartProvenanceSignature) contextValidateContent(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.ReadOnly(ctx, "chart"+"."+"provenance"+"."+"signature"+"."+"content", "body", strfmt.Base64(m.Content)); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *HelmV001SchemaChartProvenanceSignature) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *HelmV001SchemaChartProvenanceSignature) UnmarshalBinary(b []byte) error {
	var res HelmV001SchemaChartProvenanceSignature
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// HelmV001SchemaPublicKey The public key that can verify the package signature
//
// swagger:model HelmV001SchemaPublicKey
type HelmV001SchemaPublicKey struct {

	// Specifies the content of the public key inline within the document
	// Required: true
	// Format: byte
	Content *strfmt.Base64 `json:"content"`
}

// Validate validates this helm v001 schema public key
func (m *HelmV001SchemaPublicKey) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateContent(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *HelmV001SchemaPublicKey) validateContent(formats strfmt.Registry) error {

	if err := validate.Required("publicKey"+"."+"content", "body", m.Content); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this helm v001 schema public key based on context it is used
func (m *HelmV001SchemaPublicKey) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *HelmV001SchemaPublicKey) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *HelmV001SchemaPublicKey) UnmarshalBinary(b []byte) error {
	var res HelmV001SchemaPublicKey
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
