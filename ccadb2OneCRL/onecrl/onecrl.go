package onecrl

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"

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
	Schema       int     `json:"schema"`
	Details      Details `json:"details"`
	Enabled      bool    `json:"enabled"`
	IssuerName   string  `json:"issuerName,omitempty"`
	SerialNumber string  `json:"serialNumber,omitempty"`
	Subject      string  `json:"subject,omitempty"`
	PubKeyHash   string  `json:"pubKeyHash,omitempty"`
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

func (r *Record) IssuerSerial() (string, error) {
	if r.IssuerName == "" && r.SerialNumber == "" {
		return "", nil
	}
	issuer, err := base64.StdEncoding.DecodeString(r.IssuerName)
	if err != nil {
		return "", err
	}
	serial, err := base64.StdEncoding.DecodeString(r.SerialNumber)
	if err != nil {
		return "", err
	}
	i := &pkix.RDNSequence{}
	_, err = asn1.Unmarshal(issuer, i)
	if err != nil {
		return "", err
	}
	utils.Normalize(i)
	s := big.NewInt(0).SetBytes(serial)
	return string(append([]byte(i.String()), s.Bytes()...)), nil
}

func (r *Record) SubjectKeyHash() (string, error) {
	// The returned CSV is not so reliable on
	// having these fields, but they are certainly
	// in the certificate.
	//
	// The CCADB puts single quotes inside double quotes, which
	// breaks the parseability of the PEM.
	subjectBytes, err := base64.StdEncoding.DecodeString(r.Subject)
	if err != nil {
		return "", err
	}
	subject := pkix.RDNSequence{}
	_, err = asn1.Unmarshal(subjectBytes, &subject)
	if err != nil {
		return "", nil
	}
	utils.Normalize(&subject)
	hasher := sha256.New()
	//hasher.Write(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(hasher.Sum([]byte(subject.String()))), nil
}

type IssuerSerialSet map[string]*Record

func (iss IssuerSerialSet) Put(r *Record) error {
	is, err := r.IssuerSerial()
	if err != nil {
		return err
	}
	iss[is] = r
	return nil
}

func (iss IssuerSerialSet) Contains(is string) bool {
	_, ok := iss[is]
	return ok
}

func (iss IssuerSerialSet) Union(other IssuerSerialSet) IssuerSerialSet {
	union := IssuerSerialSet{}
	for k, v := range iss {
		union[k] = v
	}
	for k, v := range other {
		union[k] = v
	}
	return union
}

type PubKeyhashSet map[string]*Record

func (sks PubKeyhashSet) Put(r *Record) error {
	sks[r.PubKeyHash] = r
	return nil
}

func (sks PubKeyhashSet) Contains(pkhash string) bool {
	_, ok := sks[pkhash]
	return ok
}

func (sks PubKeyhashSet) Union(other PubKeyhashSet) PubKeyhashSet {
	union := PubKeyhashSet{}
	for k, v := range sks {
		union[k] = v
	}
	for k, v := range other {
		union[k] = v
	}
	return union
}

type OneCRLSet struct {
	issuerSerial IssuerSerialSet
	pubkeyHash   PubKeyhashSet
}

func NewOneCRLSet(oneCRL *OneCRL) (OneCRLSet, error) {
	set := OneCRLSet{
		issuerSerial: IssuerSerialSet{},
		pubkeyHash:   PubKeyhashSet{},
	}
	for _, record := range oneCRL.Data {
		if record.IssuerName != "" && record.SerialNumber != "" {
			set.issuerSerial.Put(record)
		} else {
			set.pubkeyHash.Put(record)
		}
	}
	return set, nil
}

func (o *OneCRLSet) Contains(identifier string) bool {
	return o.issuerSerial.Contains(identifier) || o.pubkeyHash.Contains(identifier)
}
