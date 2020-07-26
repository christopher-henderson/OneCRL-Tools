package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/mozilla/OneCRL-Tools/kinto/api/authz"

	"github.com/mozilla/OneCRL-Tools/kinto/api/auth"
	"github.com/mozilla/OneCRL-Tools/kinto/api/batch"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/onecrl"
	"github.com/mozilla/OneCRL-Tools/kinto"
)

func TestE2E(t *testing.T) {
	setup()
	os.Setenv("ONECRL_STAGING", "http://localhost:8888/v1")
	os.Setenv("ONECRL_STAGING_USER", "superDev")
	os.Setenv("ONECRL_STAGING_PASSWORD", "password")
	os.Setenv("BUGZILLA", "https://bugzilla-dev.allizom.org")
	os.Setenv("BUGZILLA_API_KEY", os.Getenv("BUGZILLA_DEV_API_KEY"))
	// We copy over prod into a special test on your local.
	os.Setenv("ONECRL_PRODUCTION", "http://localhost:8888/v1")
	os.Setenv("ONECRL_PRODUCTION_USER", "superDev")
	os.Setenv("ONECRL_PRODUCTION_PASSWORD", "password")
	os.Setenv("ONECRL_PRODUCTION_BUCKET", "production-security-state")
	os.Setenv("ONECRL_PRODUCTION_COLLECTION", "onecrl")
	main()
}

var dev = &auth.User{
	Username: "superDev",
	Password: "password",
}
var admin = &auth.User{
	Username: "admin",
	Password: "password",
}

var devRW = &authz.Permissions{
	Write: []string{"account:superDev"},
	Read:  []string{"system.Everyone"},
}

var local = kinto.NewClient("http", "localhost:8888", "/v1").WithAuthenticator(dev)
var staging = kinto.NewClient("https", "settings.stage.mozaws.net", "/v1")
var production = kinto.NewClient("https", "firefox.settings.services.mozilla.com", "/v1")

func setup() {
	makeLocal()
	syncStaging()
	syncProduction()
}

func syncStaging() {
	dataA := onecrl.NewOneCRL()
	if err := staging.AllRecords(dataA); err != nil {
		panic(err)
	}
	d := make([]interface{}, len(dataA.Data))
	for i, v := range dataA.Data {
		d[i] = v
	}
	max, err := local.BatchMaxRequests()
	if err != nil {
		panic(err)
	}
	batches := batch.NewBatches(d, max, nil, http.MethodPost, dataA.Get())
	for _, b := range batches {
		if err := local.Batch(b); err != nil {
			panic(err)
		}
	}
}

func syncProduction() {
	dataA := onecrl.NewOneCRL()
	if err := production.AllRecords(dataA); err != nil {
		panic(err)
	}
	d := make([]interface{}, len(dataA.Data))
	for i, v := range dataA.Data {
		d[i] = v
	}
	max, err := local.BatchMaxRequests()
	if err != nil {
		panic(err)
	}
	dataA.Bucket.ID = "production-security-state"
	batches := batch.NewBatches(d, max, nil, http.MethodPost, dataA.Get())
	for _, b := range batches {
		if err := local.Batch(b); err != nil {
			panic(err)
		}
	}
}

func makeLocal() {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	dir := filepath.Join(filepath.Dir(cwd), "kinto", "local")
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
	oneCRL.Bucket.ID = "production-security-state"
	err = local.NewBucketWithPermissions(oneCRL.Bucket, devRW)
	if err != nil {
		panic(err)
	}
	err = local.NewCollectionWithPermissions(oneCRL.Collection, devRW)
	if err != nil {
		panic(err)
	}
}
