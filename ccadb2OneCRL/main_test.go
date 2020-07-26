package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/mozilla/OneCRL-Tools/kinto/api/authz"

	bugzAuth "github.com/mozilla/OneCRL-Tools/bugzilla/api/auth"
	bugzilla "github.com/mozilla/OneCRL-Tools/bugzilla/client"
	"github.com/mozilla/OneCRL-Tools/kinto/api/auth"
	"github.com/mozilla/OneCRL-Tools/kinto/api/batch"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/onecrl"
	"github.com/mozilla/OneCRL-Tools/kinto"
)

//func TestE2E(t *testing.T) {
//
//	err := NewUpdate(
//		local,
//		Production,
//		bugzillaDev()).Update()
//	if err != nil {
//		log.Fatal(err)
//	}
//}

func TestMMMM(t *testing.T) {
	setup(
		kinto.NewClient("http", "localhost:8888", "/v1").WithAuthenticator(dev),
		kinto.NewClient("https", "settings.stage.mozaws.net", "/v1"))
	os.Setenv("ONECRL_STAGING", "http://localhost:8888/v1")
	os.Setenv("ONECRL_STAGING_USER", "superDev")
	os.Setenv("ONECRL_STAGING_PASSWORD", "password")
	os.Setenv("BUGZILLA", "https://bugzilla-dev.allizom.org")
	os.Setenv("BUGZILLA_API_KEY", "PcKr3LgH6bL0WDXlPuC0wLhFTUuhT8UJSvPKF0UQ")
	os.Setenv("TESTING", "yessir")
	main()
}

func bugzillaDev() *bugzilla.Client {
	os.Setenv("BUGZILLA_DEV_HOST", "https://bugzilla-dev.allizom.org")
	os.Setenv("BUGZILLA_DEV_API_KEY", "PcKr3LgH6bL0WDXlPuC0wLhFTUuhT8UJSvPKF0UQ")
	// A good goto is https://bugzilla-dev.allizom.org
	return bugzilla.NewClient(os.Getenv("BUGZILLA_DEV_HOST")).
		// Create an account in your target Bugzilla, head
		// to preferences, and generate an API key for yourself.
		WithAuth(&bugzAuth.ApiKey{os.Getenv("BUGZILLA_DEV_API_KEY")})
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

func setup(local, staging *kinto.Client) {
	makeLocal(local)
	sync(staging, local)
}

func sync(a, b *kinto.Client) {
	dataA := onecrl.NewOneCRL()
	if err := a.AllRecords(dataA); err != nil {
		panic(err)
	}
	d := make([]interface{}, len(dataA.Data))
	for i, v := range dataA.Data {
		d[i] = v
	}
	max, err := b.BatchMaxRequests()
	if err != nil {
		panic(err)
	}
	batches := batch.NewBatches(d, max, nil, http.MethodPost, dataA.Get())
	for _, batch := range batches {
		if err := b.Batch(batch); err != nil {
			panic(err)
		}
	}
}

func makeLocal(local *kinto.Client) {
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
}

//func TestIntegration(t *testing.T) {
//	log.SetFlags(log.LstdFlags | log.Lshortfile)
//	/////////
//	production := onecrl.NewOneCRL()
//	err := onecrl.Production.AllRecords(production)
//	if err != nil {
//		t.Fatal(err)
//	}
//	prodMap := collections.NewMapOfOneCRLFrom(production.Data)
//	/////////
//	staging := onecrl.NewOneCRL()
//	err = onecrl.Staging.AllRecords(staging)
//	if err != nil {
//		t.Fatal(err)
//	}
//	stagMap := collections.NewMapOfOneCRLFrom(staging.Data)
//	//////
//	union := prodMap.Union(stagMap)
//	//////
//	cRecords, err := ccadb.Default()
//	if err != nil {
//		t.Fatal(err)
//	}
//	c := collections.SetOfCCADBFrom(cRecords)
//	//////
//	diff := c.Difference(union)
//	t.Log(len(diff))
//}
//
//func TestBuild(t *testing.T) {}
//
////func bugzillaDev() *client.Client {
////	os.Setenv("BUGZILLA_DEV_HOST", "https://bugzilla-dev.allizom.org")
////	os.Setenv("BUGZILLA_DEV_API_KEY", "PcKr3LgH6bL0WDXlPuC0wLhFTUuhT8UJSvPKF0UQ")
////	// A good goto is https://bugzilla-dev.allizom.org
////	return client.NewClient(os.Getenv("BUGZILLA_DEV_HOST")).
////		// Create an account in your target Bugzilla, head
////		// to preferences, and generate an API key for yourself.
////		WithAuth(&bugzAuth.ApiKey{os.Getenv("BUGZILLA_DEV_API_KEY")})
////}
//
//func TestSyncing(t *testing.T) {
//	log.SetFlags(log.LstdFlags | log.Lshortfile)
//	// Copy staging to local
//	setup()
//	// Sync production to staging step, but staging is actually local.
//	sync(onecrl.Production, local)
//	// Pull staging, which now also includes production.
//	staging := onecrl.NewOneCRL()
//	err := local.AllRecords(staging)
//	if err != nil {
//		t.Fatal(err)
//	}
//	stagMap := collections.NewMapOfOneCRLFrom(staging.Data)
//	//////
//	cRecords, err := ccadb.Default()
//	if err != nil {
//		t.Fatal(err)
//	}
//	c := collections.SetOfCCADBFrom(cRecords)
//	//////
//	diff := c.Difference(stagMap)
//	t.Log(len(diff))
//	bugz := bugzillaDev()
//	comment := ""
//	records := make([]*onecrl.Record, len(diff))
//	for i, d := range diff {
//		r, err := d.IntoOneCRLRecord(*staging.Data[0])
//		if err != nil {
//			t.Fatal(err)
//		}
//		records[i] = r
//		comment += fmt.Sprintf("issuer: %s serial %s\n", r.IssuerName, r.SerialNumber)
//	}
//	bug := &bugs.Create{
//		Product:   "Toolkit",
//		Component: "Blocklist Policy Requests",
//		Summary:   fmt.Sprintf("CCADB entries generated %s", time.Now().UTC().Format(time.RFC3339)),
//		Version:   "unspecified",
//		Severity:  "normal",
//		Type:      "enhancement",
//	}
//	resp, err := bugz.CreateBug(bug)
//	if err != nil {
//		t.Fatal(err)
//	}
//	t.Log(resp.Id)
//	_, err = bugz.CreateAttachment((&attachments.Create{
//		BugId:       resp.Id,
//		Data:        []byte(comment),
//		FileName:    "BugData.txt",
//		Summary:     "This is just a tribute!",
//		ContentType: "text/plain",
//	}).AddBug(resp.Id))
//	if err != nil {
//		t.Fatal(err)
//	}
//	for _, r := range records {
//		r.Details.Bug = strconv.Itoa(resp.Id)
//		err = local.NewRecordWithPermissions(staging, r, devRW)
//		if err != nil {
//			t.Fatal(err)
//		}
//	}
//}

//var dev = &auth.User{
//	Username: "superDev",
//	Password: "password",
//}
//var admin = &auth.User{
//	Username: "admin",
//	Password: "password",
//}
//var local = kinto.NewClient("http", "localhost:8888", "/v1").WithAuthenticator(dev)
//
//var devRW = &authz.Permissions{
//	Read:  []string{"account:superDev"},
//	Write: []string{"account:superDev"},
//}
//
//func setup() {
//	makeLocal()
//	sync(onecrl.Staging, local)
//}
//
//func sync(a, b *kinto.Client) {
//	dataA := onecrl.NewOneCRL()
//	if err := a.AllRecords(dataA); err != nil {
//		panic(err)
//	}
//	d := make([]interface{}, len(dataA.Data))
//	for i, v := range dataA.Data {
//		d[i] = v
//	}
//	max, err := b.BatchMaxRequests()
//	if err != nil {
//		panic(err)
//	}
//	batches := batch.NewBatches(d, max, devRW, http.MethodPost, dataA.Get())
//	for _, batch := range batches {
//		if err := b.Batch(batch); err != nil {
//			panic(err)
//		}
//	}
//}
//
//func makeLocal() {
//	dir := "/home/chris/OneCRL-Tools/kinto/local"
//	down := exec.Command("docker-compose", "down")
//	down.Dir = dir
//	out, err := down.CombinedOutput()
//	if err != nil {
//		panic(fmt.Sprintf("KINTO_TESTDIR: '%s', Output: '%s', Error:'%v'", dir, string(out), err))
//	}
//	up := exec.Command("docker-compose", "up")
//	up.Dir = dir
//	err = up.Start()
//	if err != nil {
//		panic(err)
//	}
//	start := time.Now()
//	for !local.Alive() {
//		time.Sleep(time.Millisecond * 200)
//		if time.Now().Sub(start) > time.Minute {
//			panic("took more than ten seconds to docker-compose up")
//		}
//	}
//	local.WithAuthenticator(&auth.Unauthenticated{})
//	err = local.NewAdmin(admin.Password)
//	if err != nil {
//		panic(err)
//	}
//	local.WithAuthenticator(admin)
//	err = local.NewAccount(dev)
//	if err != nil {
//		panic(err)
//	}
//	oneCRL := onecrl.NewOneCRL()
//	err = local.NewBucketWithPermissions(oneCRL.Bucket, devRW)
//	if err != nil {
//		panic(err)
//	}
//	err = local.NewCollectionWithPermissions(oneCRL.Collection, devRW)
//	if err != nil {
//		panic(err)
//	}
//}

//func copyProd() {
//	oneCRL := onecrl.NewOneCRL()
//	err := onecrl.Production.AllRecords(oneCRL)
//	if err != nil {
//		panic(err)
//	}
//	records := make([]interface{}, len(oneCRL.Data))
//	for i, record := range oneCRL.Data {
//		records[i] = record
//	}
//	max, err := local.BatchMaxRequests()
//	if err != nil {
//		panic(err)
//	}
//	batches := batch.NewBatches(records, max, devRW, http.MethodPost, oneCRL.Get())
//	for _, b := range batches {
//		err = local.Batch(b)
//		if err != nil {
//			panic(err)
//		}
//	}
//	l := onecrl.NewOneCRL()
//	p := onecrl.NewOneCRL()
//	err = local.AllRecords(l)
//	if err != nil {
//		panic(err)
//	}
//	err = onecrl.Production.AllRecords(p)
//	if err != nil {
//		panic(err)
//	}
//	if !reflect.DeepEqual(l.Data, p.Data) {
//		panic(fmt.Sprintf("production and local did not match each other.\ngot: %v\nwant: %v", l.Data, p.Data))
//	}
//}

func TestSlice(t *testing.T) {
	r := make([]*onecrl.Record, 20)
	t.Log(r[0])
}
