package main

import (
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/ccadb"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/collections"

	"github.com/mozilla/OneCRL-Tools/kinto/api/batch"

	"github.com/mozilla/OneCRL-Tools/kinto"

	"github.com/mozilla/OneCRL-Tools/kinto/api/auth"

	"github.com/mozilla/OneCRL-Tools/kinto/api/authz"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/onecrl"
)

func TestIntegration(t *testing.T) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	/////////
	production := onecrl.NewOneCRL()
	err := onecrl.Production.AllRecords(production)
	if err != nil {
		t.Fatal(err)
	}
	prodMap := collections.NewMapOfOneCRLFrom(production.Data)
	/////////
	staging := onecrl.NewOneCRL()
	err = onecrl.Staging.AllRecords(staging)
	if err != nil {
		t.Fatal(err)
	}
	stagMap := collections.NewMapOfOneCRLFrom(staging.Data)
	//////
	union := prodMap.Union(stagMap)
	//////
	cRecords, err := ccadb.Default()
	if err != nil {
		t.Fatal(err)
	}
	c := collections.SetOfCCADBFrom(cRecords)
	//////
	diff := c.Difference(union)
	t.Log(len(diff))
}

func TestSyncing(t *testing.T) {
	setup()
	production := onecrl.NewOneCRL()
	err := onecrl.Production.AllRecords(production)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]interface{}, len(production.Data))
	for i, v := range production.Data {
		data[i] = v
	}
	max, err := local.BatchMaxRequests()
	if err != nil {
		t.Fatal(err)
	}
	batches := batch.NewBatches(data, max, devRW, http.MethodPost, production.Get())
	for _, b := range batches {
		err = local.Batch(b)
		if err != nil {
			t.Fatal(err)
		}
	}
}

var dev = &auth.User{
	Username: "superDev",
	Password: "password",
}
var admin = &auth.User{
	Username: "admin",
	Password: "password",
}
var local = kinto.NewClient("http", "localhost:8888", "/v1").WithAuthenticator(dev)

var devRW = &authz.Permissions{
	Read:  []string{"account:superDev"},
	Write: []string{"account:superDev"},
}

func setup() {
	dir := "/home/chris/OneCRL-Tools/kinto/local"
	down := exec.Command("docker-compose", "down")
	down.Dir = dir
	out, err := down.CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("KINTO_TESTDIR: '%s', Output: '%s', Error:'%v'", dir, string(out), err))
	}
	up := exec.Command("docker-compose", "up")
	up.Dir = dir
	err = up.Start()
	if err != nil {
		panic(err)
	}
	start := time.Now()
	for !local.Alive() {
		time.Sleep(time.Millisecond * 200)
		if time.Now().Sub(start) > time.Minute {
			panic("took more than ten seconds to docker-compose up")
		}
	}
	local.WithAuthenticator(&auth.Unauthenticated{})
	err = local.NewAdmin(admin.Password)
	if err != nil {
		panic(err)
	}
	local.WithAuthenticator(admin)
	err = local.NewAccount(dev)
	if err != nil {
		panic(err)
	}
	oneCRL := onecrl.NewOneCRL()
	err = local.NewBucketWithPermissions(oneCRL.Bucket, devRW)
	if err != nil {
		panic(err)
	}
	err = local.NewCollectionWithPermissions(oneCRL.Collection, devRW)
	if err != nil {
		panic(err)
	}
	//copyProd()
	//
	//signer := buckets.NewBucket("to_sign")
	//err = local.NewBucketWithPermissions(signer, devRW)
	//if err != nil {
	//	panic(err)
	//}
	//signedOnecrl := collections.NewCollection(signer, "signedOnecrl")
	//err = local.NewCollectionWithPermissions(signedOnecrl, devRW)
	//if err != nil {
	//	panic(err)
	//}
	//
	//signed := buckets.NewBucket("signed")
	//err = local.NewBucketWithPermissions(signed, devRW)
	//if err != nil {
	//	panic(err)
	//}
	//signedOnecrl = collections.NewCollection(signed, "signedOnecrl")
	//err = local.NewCollectionWithPermissions(signedOnecrl, devRW)
	//if err != nil {
	//	panic(err)
	//}
}

func copyProd() {
	oneCRL := onecrl.NewOneCRL()
	err := onecrl.Production.AllRecords(oneCRL)
	if err != nil {
		panic(err)
	}
	records := make([]interface{}, len(oneCRL.Data))
	for i, record := range oneCRL.Data {
		records[i] = record
	}
	max, err := local.BatchMaxRequests()
	if err != nil {
		panic(err)
	}
	batches := batch.NewBatches(records, max, devRW, http.MethodPost, oneCRL.Get())
	for _, b := range batches {
		err = local.Batch(b)
		if err != nil {
			panic(err)
		}
	}
	l := onecrl.NewOneCRL()
	p := onecrl.NewOneCRL()
	err = local.AllRecords(l)
	if err != nil {
		panic(err)
	}
	err = onecrl.Production.AllRecords(p)
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(l.Data, p.Data) {
		panic(fmt.Sprintf("production and local did not match each other.\ngot: %v\nwant: %v", l.Data, p.Data))
	}
}
