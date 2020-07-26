package collections

import (
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/ccadb"
)

type SetOfCCADB ccadb.CCADB

func SetOfCCADBFrom(records ccadb.CCADB) SetOfCCADB {
	if records == nil {
		return SetOfCCADB{}
	}
	return records
}

func (s SetOfCCADB) Difference(onecrl *MapOfOneCRL) SetOfCCADB {
	// Since this method makes reference to another type in this
	// package AND makes reference to the ccadb pacakge, if we
	// attached it to the ccadb.CCADB type then that would
	// generate an import cycle. So we use a new-type pattern
	// to attach this behavior.
	difference := SetOfCCADB{}
	for _, cert := range s {
		if !onecrl.Contains(cert) {
			difference = append(difference, cert)
		}
	}
	return difference
}
