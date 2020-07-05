module github.com/mozilla/OneCRL-Tools/ccadb2OneCRL

go 1.14

require (
	github.com/gocarina/gocsv v0.0.0-20200330101823-46266ca37bd3
	github.com/mozilla/OneCRL-Tools/kinto v0.0.0
	github.com/pkg/errors v0.9.1
)

replace github.com/mozilla/OneCRL-Tools/kinto => ../kinto
