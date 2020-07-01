package main // import "github.com/mozilla/OneCRL-Tools/ccadb2OneCRL"
import (
	"fmt"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/ccadb"
)

func main() {
	certs, err := ccadb.Default()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%v\n", certs)
}
