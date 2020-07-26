/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package ccadb

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/pkg/errors"

	"github.com/gocarina/gocsv"
)

const source = "https://ccadb-public.secure.force.com/mozilla/PublicInterCertsReadyToAddToOneCRLPEMCSV"

type CCADB = []*Certificate

type Certificate struct {
	CAOwner                        string `csv:"CA Owner"`
	RevocationStatus               string `csv:"Revocation Status"`
	ReasonCode                     string `csv:"RFC 5280 Revocation Reason Code"`
	DateOfRevocation               string `csv:"Date of Revocation"`
	OneCRLStatus                   string `csv:"OneCRL Status"`
	OneCRLBugNumber                string `csv:"OneCRL Bug Number"`
	CertificateSerialNumber        string `csv:"Certificate Serial Number"`
	CaOwnerName                    string `csv:"CA Owner/Certificate Name"`
	CertificateIssuerName          string `csv:"Certificate Issuer Common Name"`
	CertificateIssuerOrganization  string `csv:"Certificate Issuer Organization"`
	CertificateSubjectCommonName   string `csv:"Certificate Subject Common Name"`
	CertificateSubjectOrganization string `csv:"Certificate Subject Organization"`
	Fingerprint                    string `csv:"SHA-256 Fingerprint"`
	SubjectSPKIHash                string `csv:"Subject + SPKI SHA256"`
	NotBefore                      string `csv:"Valid From [GMT]"`
	NotAfter                       string `csv:"Valid To [GMT]"`
	KeyAlgorithm                   string `csv:"Public Key Algorithm"`
	SignatureAlgorithm             string `csv:"Signature Hash Algorithm"`
	CRLs                           string `csv:"CRL URL(s)"`
	AlternativeCRL                 string `csv:"Alternate CRL"`
	Comments                       string `csv:"Comments"`
	PemInfo                        string `csv:"PEM Info"`
}

func Default() ([]*Certificate, error) {
	return FromURL(source)
}

func FromURL(url string) ([]*Certificate, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return FromReader(resp.Body)
}

func FromReader(reader io.Reader) ([]*Certificate, error) {
	report := make([]*Certificate, 0)
	return report, gocsv.Unmarshal(reader, &report)
}

func (c *Certificate) HasCertificate() bool {
	return strings.Trim(c.PemInfo, "'") != ""
}

func (c *Certificate) ParseCertificate() (*x509.Certificate, error) {
	p := c.PEM()
	if p == "" {
		return nil, errors.New("CCADB record does not have a certificate")
	}
	b, _ := pem.Decode([]byte(p))
	if b == nil {
		return nil, fmt.Errorf("fail to decode pem from CCADB: '%s'", c.PemInfo)
	}
	return x509.ParseCertificate(b.Bytes)
}

// The CCADB has the habit of double encoding strings with inner single quotes.
func (c *Certificate) PEM() string {
	return strings.TrimSpace(strings.Trim(c.PemInfo, "'"))
}
