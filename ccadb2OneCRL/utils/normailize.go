package utils

import (
	"crypto/x509/pkix"
	"sort"
)

func Normalize(rdn *pkix.RDNSequence) {
	for _, set := range *rdn {
		sort.Slice(set, func(i, j int) bool {
			if len(set[i].Type) < len(set[j].Type) {
				return true
			}
			for index, value := range set[i].Type {
				if value < set[j].Type[index] {
					return true
				}
			}
			return false
		})
	}
}
