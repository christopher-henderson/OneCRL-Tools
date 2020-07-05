package collections

import (
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/ccadb"
)

type SetOfCCADB map[*ccadb.Certificate]bool

func SetOfCCADBFrom(records ccadb.CCADB) SetOfCCADB {
	s := SetOfCCADB{}
	if records == nil {
		return s
	}
	for _, record := range records {
		s.Add(record)
	}
	return s
}

func (s SetOfCCADB) Add(record *ccadb.Certificate) {
	s[record] = true
}

func (s SetOfCCADB) Difference(onecrl *MapOfOneCRL) SetOfCCADB {
	difference := SetOfCCADB{}
	for cert, _ := range s {
		if !onecrl.Contains(cert) {
			difference[cert] = true
		}
	}
	return difference
}
