/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package collections

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"fmt"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/utils"

	"github.com/pkg/errors"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/ccadb"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/onecrl"
)

type IssuerSerial string

func NewIssuerSerial(issuer *pkix.RDNSequence, serial []byte) IssuerSerial {
	return IssuerSerial(fmt.Sprintf("%s,%s", issuer.String(), utils.B64Encode(serial)))
}

type SubjectKeyHash string

func NewSubjectKeyHash(subject *pkix.RDNSequence, hash []byte) SubjectKeyHash {
	return SubjectKeyHash(NewIssuerSerial(subject, hash))
}

func IssuerSerialFromCCADB(record *ccadb.Certificate) (IssuerSerial, error) {
	if !record.HasCertificate() {
		return "", nil
	}
	cert, err := record.ParseCertificate()
	if err != nil {
		return "", errors.Wrap(err, "failed to parse certificate for an IssuerSerial entry from the CCADB.")
	}
	issuer := cert.Issuer.ToRDNSequence()
	utils.Normalize(&issuer)
	return NewIssuerSerial(&issuer, cert.SerialNumber.Bytes()), nil
}

func IssuerSerialFromOneCRL(record *onecrl.Record) (IssuerSerial, error) {
	issuer, err := record.ParseIssuer()
	if err != nil {
		return "", err
	}
	utils.Normalize(issuer)
	// Decoding and re-encoding the string coerces everyone to the same b64 standard.
	// That is, those without padding get forced into having padding.
	serial, err := utils.B64Decode(record.SerialNumber)
	if err != nil {
		return "", errors.Wrap(err, "OneCRL serial b64 name decode error")
	}
	return NewIssuerSerial(issuer, serial), nil
}

func SubjectKeyHashFromCCADB(record *ccadb.Certificate) (SubjectKeyHash, error) {
	if !record.HasCertificate() {
		return "", nil
	}
	cert, err := record.ParseCertificate()
	if err != nil {
		return "", errors.Wrap(err, "failed to parse certificate for an IssuerSerial entry from the CCADB.")
	}
	subject := cert.Subject.ToRDNSequence()
	utils.Normalize(&subject)
	hasher := sha256.New()
	hasher.Write(cert.RawSubjectPublicKeyInfo)
	hash := hasher.Sum(nil)
	return NewSubjectKeyHash(&subject, hash), nil
}

func SubjectKeyHashFromOneCRL(record *onecrl.Record) (SubjectKeyHash, error) {
	subject, err := record.ParseSubject()
	if err != nil {
		return "", err
	}
	utils.Normalize(subject)
	// Decoding and re-encoding the string coerces everyone to the same b64 standard.
	// That is, those without padding get forced into having padding.
	hash, err := utils.B64Decode(record.PubKeyHash)
	if err != nil {
		return "", err
	}
	return NewSubjectKeyHash(subject, hash), nil
}
