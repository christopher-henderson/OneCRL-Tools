package onecrl

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/ccadb"

	"github.com/pkg/errors"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/utils"

	"github.com/mozilla/OneCRL-Tools/kinto"
	"github.com/mozilla/OneCRL-Tools/kinto/api"
	"github.com/mozilla/OneCRL-Tools/kinto/api/buckets"
	"github.com/mozilla/OneCRL-Tools/kinto/api/collections"
)

var Production = kinto.NewClient("https", "firefox.settings.services.mozilla.com", "/v1")
var Staging = kinto.NewClient("https", "settings.stage.mozaws.net", "/v1")

func NewOneCRL() *OneCRL {
	return &OneCRL{
		Collection: collections.NewCollection(buckets.NewBucket("security-state"), "onecrl"),
		Data:       []*Record{},
	}
}

type OneCRL struct {
	*collections.Collection `json:"-"`
	Data                    []*Record `json:"data"`
}

type Record struct {
	CCADB        *ccadb.Certificate `json:"-"`
	Schema       int                `json:"schema"`
	Details      Details            `json:"details"`
	Enabled      bool               `json:"enabled"`
	IssuerName   string             `json:"issuerName,omitempty"`
	SerialNumber string             `json:"serialNumber,omitempty"`
	Subject      string             `json:"subject,omitempty"`
	PubKeyHash   string             `json:"pubKeyHash,omitempty"`
	*api.Record
}

type Details struct {
	Bug     string `json:"bug"`
	Who     string `json:"who"`
	Why     string `json:"why"`
	Name    string `json:"name"`
	Created string `json:"created"`
}

type Type int

const (
	IssuerSerial Type = iota
	SubjectKeyHash
)

func (r *Record) Type() Type {
	if r.PubKeyHash != "" {
		return SubjectKeyHash
	} else {
		return IssuerSerial
	}
}

func (r *Record) ParseSubject() (*pkix.RDNSequence, error) {
	if r.Type() != SubjectKeyHash {
		return nil, fmt.Errorf("attempted parse a subject from a non SubjectKeyHash onecrl entry, got %d", r.Type())
	}
	subject, err := parseRDNS(r.Subject)
	if err != nil {
		return nil, errors.Wrap(err, "OneCRL subject name parsing error")
	}
	return subject, nil
}

func (r *Record) ParseIssuer() (*pkix.RDNSequence, error) {
	if r.Type() != IssuerSerial {
		return nil, fmt.Errorf("attempted to parse an issuer from a non IssuerSerial onecrl entry, got %d", r.Type())
	}
	issuer, err := parseRDNS(r.IssuerName)
	if err != nil {
		return nil, errors.Wrap(err, "OneCRL issuer name parsing error")
	}
	return issuer, nil
}

type Comparison struct {
	OneCRL string
	CCADB  string
}

type IssuerSerialComparison struct {
	Issuer Comparison `json:"issuer"`
	Serial Comparison `json:"serial"`
}

type SubjectKeyHashComparison struct {
	Subject Comparison `json:"subject"`
	Keyhash Comparison `json:"keyHash"`
}

func (r *Record) ToComparison() (interface{}, error) {
	switch r.Type() {
	case IssuerSerial:
		return IssuerSerialComparison{
			Issuer: Comparison{
				OneCRL: r.IssuerName,
				CCADB:  r.CCADB.CertificateIssuerName,
			},
			Serial: Comparison{
				OneCRL: r.SerialNumber,
				CCADB:  r.CCADB.CertificateSerialNumber,
			},
		}, nil
	case SubjectKeyHash:
		subject, err := r.ParseSubject()
		if err != nil {
			return nil, err
		}
		raw, err := utils.B64Decode(r.PubKeyHash)
		if err != nil {
			return nil, err
		}
		return SubjectKeyHashComparison{
			Subject: Comparison{
				OneCRL: r.Subject,
				CCADB:  subject.String(),
			},
			Keyhash: Comparison{
				OneCRL: r.PubKeyHash,
				CCADB:  fmt.Sprintf("%X", raw),
			},
		}, nil
	default:
		panic("non-exhaustive switch")
	}
}

func FromCCADB(c *ccadb.Certificate) (*Record, error) {
	cert, err := c.ParseCertificate()
	if err != nil {
		return nil, err
	}
	record := &Record{
		CCADB: c,
		Details: Details{
			Bug:     "",
			Who:     "",
			Why:     "",
			Name:    "",
			Created: "",
		},
		Enabled:      false,
		IssuerName:   utils.B64Encode(cert.RawIssuer),
		SerialNumber: utils.B64Encode(cert.SerialNumber.Bytes()),
		Subject:      "",
		PubKeyHash:   "",
	}
	return record, nil
}

func parseRDNS(rdns string) (*pkix.RDNSequence, error) {
	i, err := utils.B64Decode(rdns)
	if err != nil {
		return nil, errors.Wrap(err, "OneCRL RDNS b64 decode error")
	}
	r := &pkix.RDNSequence{}
	_, err = asn1.Unmarshal(i, r)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("OneCRL RDNS asn1 decode error for '%s'", rdns))
	}
	return r, nil
}
