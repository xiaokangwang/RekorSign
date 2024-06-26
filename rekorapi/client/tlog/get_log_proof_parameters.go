// Code generated by go-swagger; DO NOT EDIT.

package tlog

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// NewGetLogProofParams creates a new GetLogProofParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetLogProofParams() *GetLogProofParams {
	return &GetLogProofParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetLogProofParamsWithTimeout creates a new GetLogProofParams object
// with the ability to set a timeout on a request.
func NewGetLogProofParamsWithTimeout(timeout time.Duration) *GetLogProofParams {
	return &GetLogProofParams{
		timeout: timeout,
	}
}

// NewGetLogProofParamsWithContext creates a new GetLogProofParams object
// with the ability to set a context for a request.
func NewGetLogProofParamsWithContext(ctx context.Context) *GetLogProofParams {
	return &GetLogProofParams{
		Context: ctx,
	}
}

// NewGetLogProofParamsWithHTTPClient creates a new GetLogProofParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetLogProofParamsWithHTTPClient(client *http.Client) *GetLogProofParams {
	return &GetLogProofParams{
		HTTPClient: client,
	}
}

/*
GetLogProofParams contains all the parameters to send to the API endpoint

	for the get log proof operation.

	Typically these are written to a http.Request.
*/
type GetLogProofParams struct {

	/* FirstSize.

	   The size of the tree that you wish to prove consistency from (1 means the beginning of the log) Defaults to 1 if not specified


	   Default: 1
	*/
	FirstSize *int64

	/* LastSize.

	   The size of the tree that you wish to prove consistency to
	*/
	LastSize int64

	/* TreeID.

	   The tree ID of the tree that you wish to prove consistency for
	*/
	TreeID *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get log proof params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetLogProofParams) WithDefaults() *GetLogProofParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get log proof params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetLogProofParams) SetDefaults() {
	var (
		firstSizeDefault = int64(1)
	)

	val := GetLogProofParams{
		FirstSize: &firstSizeDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get log proof params
func (o *GetLogProofParams) WithTimeout(timeout time.Duration) *GetLogProofParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get log proof params
func (o *GetLogProofParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get log proof params
func (o *GetLogProofParams) WithContext(ctx context.Context) *GetLogProofParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get log proof params
func (o *GetLogProofParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get log proof params
func (o *GetLogProofParams) WithHTTPClient(client *http.Client) *GetLogProofParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get log proof params
func (o *GetLogProofParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFirstSize adds the firstSize to the get log proof params
func (o *GetLogProofParams) WithFirstSize(firstSize *int64) *GetLogProofParams {
	o.SetFirstSize(firstSize)
	return o
}

// SetFirstSize adds the firstSize to the get log proof params
func (o *GetLogProofParams) SetFirstSize(firstSize *int64) {
	o.FirstSize = firstSize
}

// WithLastSize adds the lastSize to the get log proof params
func (o *GetLogProofParams) WithLastSize(lastSize int64) *GetLogProofParams {
	o.SetLastSize(lastSize)
	return o
}

// SetLastSize adds the lastSize to the get log proof params
func (o *GetLogProofParams) SetLastSize(lastSize int64) {
	o.LastSize = lastSize
}

// WithTreeID adds the treeID to the get log proof params
func (o *GetLogProofParams) WithTreeID(treeID *string) *GetLogProofParams {
	o.SetTreeID(treeID)
	return o
}

// SetTreeID adds the treeId to the get log proof params
func (o *GetLogProofParams) SetTreeID(treeID *string) {
	o.TreeID = treeID
}

// WriteToRequest writes these params to a swagger request
func (o *GetLogProofParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.FirstSize != nil {

		// query param firstSize
		var qrFirstSize int64

		if o.FirstSize != nil {
			qrFirstSize = *o.FirstSize
		}
		qFirstSize := swag.FormatInt64(qrFirstSize)
		if qFirstSize != "" {

			if err := r.SetQueryParam("firstSize", qFirstSize); err != nil {
				return err
			}
		}
	}

	// query param lastSize
	qrLastSize := o.LastSize
	qLastSize := swag.FormatInt64(qrLastSize)
	if qLastSize != "" {

		if err := r.SetQueryParam("lastSize", qLastSize); err != nil {
			return err
		}
	}

	if o.TreeID != nil {

		// query param treeID
		var qrTreeID string

		if o.TreeID != nil {
			qrTreeID = *o.TreeID
		}
		qTreeID := qrTreeID
		if qTreeID != "" {

			if err := r.SetQueryParam("treeID", qTreeID); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
