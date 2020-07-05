package collections

import (
	"fmt"
	"log"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/ccadb"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/onecrl"
)

type MapOfOneCRL struct {
	issuerSerial    map[IssuerSerial]*onecrl.Record
	subjectKeyHash2 map[SubjectKeyHash]*onecrl.Record
}

func NewMapOfOneCRLFrom(records []*onecrl.Record) *MapOfOneCRL {
	m := &MapOfOneCRL{
		issuerSerial:    map[IssuerSerial]*onecrl.Record{},
		subjectKeyHash2: map[SubjectKeyHash]*onecrl.Record{},
	}
	if records == nil {
		return m
	}
	for _, record := range records {
		if err := m.Add(record); err != nil {
			log.Println(err)
		}
	}
	return m
}

func (m *MapOfOneCRL) Add(record *onecrl.Record) error {
	switch record.Type() {
	case onecrl.IssuerSerial:
		is, err := IssuerSerialFromOneCRL(record)
		if err != nil {
			return err
		}
		m.issuerSerial[is] = record
	case onecrl.SubjectKeyHash:
		skh, err := SubjectKeyHashFromOneCRL(record)
		if err != nil {
			return err
		}
		m.subjectKeyHash2[skh] = record
	default:
		return fmt.Errorf(
			"non-exhaustive switch, we only know about %d and %d but got %d",
			onecrl.IssuerSerial, onecrl.SubjectKeyHash, record.Type())
	}
	return nil
}

func (m *MapOfOneCRL) Union(other *MapOfOneCRL) *MapOfOneCRL {
	union := NewMapOfOneCRLFrom(nil)
	for k, v := range m.issuerSerial {
		union.issuerSerial[k] = v
	}
	for k, v := range other.issuerSerial {
		union.issuerSerial[k] = v
	}
	for k, v := range m.subjectKeyHash2 {
		union.subjectKeyHash2[k] = v
	}
	for k, v := range other.subjectKeyHash2 {
		union.subjectKeyHash2[k] = v
	}
	return other
}

func (m *MapOfOneCRL) Contains(record *ccadb.Certificate) bool {
	is, err := IssuerSerialFromCCADB(record)
	if err != nil {
		log.Println(err)
	}
	if _, ok := m.issuerSerial[is]; ok {
		return true
	}
	skh, err := SubjectKeyHashFromCCADB(record)
	if err != nil {
		log.Println(err)
		return false
	}
	if _, ok := m.subjectKeyHash2[skh]; ok {
		return true
	}
	return false
}
