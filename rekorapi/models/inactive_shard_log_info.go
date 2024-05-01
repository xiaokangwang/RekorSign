// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// InactiveShardLogInfo inactive shard log info
//
// swagger:model InactiveShardLogInfo
type InactiveShardLogInfo struct {

	// The current hash value stored at the root of the merkle tree
	// Required: true
	// Pattern: ^[0-9a-fA-F]{64}$
	RootHash *string `json:"rootHash"`

	// The current signed tree head
	// Required: true
	SignedTreeHead *string `json:"signedTreeHead"`

	// The current treeID
	// Required: true
	// Pattern: ^[0-9]+$
	TreeID *string `json:"treeID"`

	// The current number of nodes in the merkle tree
	// Required: true
	// Minimum: 1
	TreeSize *int64 `json:"treeSize"`
}

// Validate validates this inactive shard log info
func (m *InactiveShardLogInfo) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRootHash(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSignedTreeHead(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTreeID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTreeSize(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *InactiveShardLogInfo) validateRootHash(formats strfmt.Registry) error {

	if err := validate.Required("rootHash", "body", m.RootHash); err != nil {
		return err
	}

	if err := validate.Pattern("rootHash", "body", *m.RootHash, `^[0-9a-fA-F]{64}$`); err != nil {
		return err
	}

	return nil
}

func (m *InactiveShardLogInfo) validateSignedTreeHead(formats strfmt.Registry) error {

	if err := validate.Required("signedTreeHead", "body", m.SignedTreeHead); err != nil {
		return err
	}

	return nil
}

func (m *InactiveShardLogInfo) validateTreeID(formats strfmt.Registry) error {

	if err := validate.Required("treeID", "body", m.TreeID); err != nil {
		return err
	}

	if err := validate.Pattern("treeID", "body", *m.TreeID, `^[0-9]+$`); err != nil {
		return err
	}

	return nil
}

func (m *InactiveShardLogInfo) validateTreeSize(formats strfmt.Registry) error {

	if err := validate.Required("treeSize", "body", m.TreeSize); err != nil {
		return err
	}

	if err := validate.MinimumInt("treeSize", "body", *m.TreeSize, 1, false); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this inactive shard log info based on context it is used
func (m *InactiveShardLogInfo) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *InactiveShardLogInfo) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *InactiveShardLogInfo) UnmarshalBinary(b []byte) error {
	var res InactiveShardLogInfo
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
