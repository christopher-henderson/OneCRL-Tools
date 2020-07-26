module github.com/mozilla/OneCRL-Tools/ccadb2OneCRL

go 1.14

require (
	github.com/gocarina/gocsv v0.0.0-20200330101823-46266ca37bd3
	github.com/mozilla/OneCRL-Tools/bugzilla v0.0.0
	github.com/mozilla/OneCRL-Tools/kinto v0.0.0
	github.com/mozilla/OneCRL-Tools/transaction v0.0.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.6.0
)

replace (
	github.com/mozilla/OneCRL-Tools/bugzilla => ../bugzilla
	github.com/mozilla/OneCRL-Tools/kinto => ../kinto
	github.com/mozilla/OneCRL-Tools/transaction => ../transaction
)
