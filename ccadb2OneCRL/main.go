/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main // import "github.com/mozilla/OneCRL-Tools/ccadb2OneCRL"
import (
	"encoding/json"
	"fmt"
	"strings"

	"os"
	"time"

	"github.com/mozilla/OneCRL-Tools/kinto/api/auth"

	bugzAuth "github.com/mozilla/OneCRL-Tools/bugzilla/api/auth"

	"github.com/pkg/errors"

	"github.com/mozilla/OneCRL-Tools/bugzilla/api/attachments"

	bugzilla "github.com/mozilla/OneCRL-Tools/bugzilla/client"

	"github.com/mozilla/OneCRL-Tools/bugzilla/api/bugs"

	"github.com/mozilla/OneCRL-Tools/transaction"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/collections"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/onecrl"
	"github.com/mozilla/OneCRL-Tools/kinto"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/ccadb"
	log "github.com/sirupsen/logrus"
)

func Production() (*kinto.Client, error) {
	production := "https://firefox.settings.services.mozilla.com/v1"
	if os.Getenv("ONECRL_PRODUCTION") != "" {
		production = os.Getenv("ONECRL_PRODUCTION")
	}
	c, err := kinto.NewClientFromStr(production)
	if err != nil {
		return nil, errors.Wrap(err, "failed to construct OneCRL production client from URL")
	}
	principal, err := KintoPrincipal(
		os.Getenv("ONECRL_PRODUCTION_USER"),
		os.Getenv("ONECRL_PRODUCTION_PASSWORD"),
		os.Getenv("ONECRL_PRODUCTION_TOKEN"))
	if err != nil {
		return nil, errors.Wrap(err, "failed to set OneCRL production credentials")
	}
	return c.WithAuthenticator(principal), nil
}

func Staging() (*kinto.Client, error) {
	staging := "https://settings.stage.mozaws.net/v1"
	if os.Getenv("ONECRL_STAGING") != "" {
		staging = os.Getenv("ONECRL_STAGING")
	}
	c, err := kinto.NewClientFromStr(staging)
	if err != nil {
		return nil, errors.Wrap(err, "failed to construct OneCRL staging client from URL")
	}
	principal, err := KintoPrincipal(
		os.Getenv("ONECRL_STAGING_USER"),
		os.Getenv("ONECRL_STAGING_PASSWORD"),
		os.Getenv("ONECRL_STAGING_TOKEN"))
	if err != nil {
		return nil, errors.Wrap(err, "failed to set OneCRL staging credentials")
	}
	return c.WithAuthenticator(principal), nil
}

func ProductionCollection() *onecrl.OneCRL {
	return Collection(os.Getenv("ONECRL_PRODUCTION_BUCKET"), os.Getenv("ONECRL_PRODUCTION_COLLECTION"))
}

func StagingCollection() *onecrl.OneCRL {
	return Collection(os.Getenv("ONECRL_STAGING_BUCKET"), os.Getenv("ONECRL_STAGING_COLLECTION"))
}

func Collection(bucket, collection string) *onecrl.OneCRL {
	o := onecrl.NewOneCRL()
	if bucket != "" {
		o.Bucket.ID = bucket
	}
	if collection != "" {
		o.ID = collection
	}
	return o
}

func KintoPrincipal(user, password, token string) (auth.Authenticator, error) {
	if user == "" && password == "" && token == "" {
		return &auth.Unauthenticated{}, nil
	}
	if user != "" && password != "" && token != "" ||
		user == "" && password != "" ||
		user != "" && password == "" {
		return nil, fmt.Errorf("an invalid combination of 'user', 'password', and 'token' was set")
	}
	if token != "" {
		return &auth.Token{Token: token}, nil
	}
	return &auth.User{Username: user, Password: password}, nil
}

func Bugzilla() *bugzilla.Client {
	bugz := "https://bugzilla.mozilla.org"
	if os.Getenv("BUGZILLA") != "" {
		bugz = os.Getenv("BUGZILLA")
	}
	return bugzilla.NewClient(bugz).
		WithAuth(&bugzAuth.ApiKey{os.Getenv("BUGZILLA_API_KEY")})
}

func main() {
	log.SetReportCaller(true)
	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&log.JSONFormatter{PrettyPrint: true})
	production, err := Production()
	if err != nil {
		log.WithError(err).Fatal("failed to construct OneCRL production client")
	}
	staging, err := Staging()
	if err != nil {
		log.WithError(err).Fatal("failed to construct OneCRL staging client")
	}
	bugz := Bugzilla()
	updater := NewUpdate(staging, production, bugz)
	err = updater.Update()
	if err != nil {
		log.WithError(err).Error("update failed")
		os.Exit(1)
	}
}

type Updater struct {
	records    []*onecrl.Record
	bugID      int
	staging    *kinto.Client
	production *kinto.Client
	bugzilla   *bugzilla.Client
}

func NewUpdate(staging, production *kinto.Client, bugz *bugzilla.Client) *Updater {
	return &Updater{
		staging:    staging,
		production: production,
		bugzilla:   bugz,
	}
}

func (u *Updater) Update() error {
	err := u.TryAuth()
	if err != nil {
		return err
	}
	err = u.FindDiffs()
	if err != nil {
		return err
	}
	if u.NoDiffs() {
		return nil
	}
	inReview, err := u.StagingIsInReview()
	if err != nil {
		return err
	}
	if inReview {
		// @TODO send emails
		log.Info("Staging is in review.")
		return nil
	}
	err = transaction.Start().
		Then(u.PushToStaging()).
		Then(u.OpenBug()).
		Then(u.UpdateRecordsWithBugID()).
		Then(u.PutStagingIntoReview()).
		Then(u.PushToProduction()).
		AutoRollbackOnError(true).
		AutoClose(true).
		Commit()
	if err == nil {
		log.WithField("bugzilla", u.bugzilla.ShowBug(u.bugID)).Info("successfully completed update")
	}
	return err
}

func (u *Updater) TryAuth() error {
	var err error = nil
	ok, e := u.staging.TryAuth()
	if e != nil {
		err = e
	} else if !ok {
		err = fmt.Errorf("authentication for staging Kinto failed")
	}
	ok, e = u.production.TryAuth()
	if e != nil {
		if err != nil {
			err = errors.Wrap(err, e.Error())
		} else {
			err = e
		}
	} else if !ok {
		if err != nil {
			err = errors.Wrap(err, "authentication for production Kinto failed")
		} else {
			err = fmt.Errorf("authentication for production Kinto failed")
		}
	}
	return errors.WithStack(err)
}

func (u *Updater) FindDiffs() error {
	/////////
	production := ProductionCollection()
	err := u.production.AllRecords(production)
	if err != nil {
		return errors.WithStack(err)
	}
	prodMap := collections.NewMapOfOneCRLFrom(production.Data)
	/////////
	staging := StagingCollection()
	err = u.staging.AllRecords(staging)
	if err != nil {
		return errors.WithStack(err)
	}
	stagMap := collections.NewMapOfOneCRLFrom(staging.Data)
	//////
	union := prodMap.Union(stagMap)
	//////
	cRecords, err := ccadb.Default()
	if err != nil {
		return errors.WithStack(err)
	}
	c := collections.SetOfCCADBFrom(cRecords)
	//////
	diffs := c.Difference(union)
	u.records = make([]*onecrl.Record, 0)
	for _, diff := range diffs {
		record, err := onecrl.FromCCADB(diff)
		if err != nil {
			return errors.WithStack(err)
		}
		u.records = append(u.records, record)
	}
	return nil
}

func (u *Updater) NoDiffs() bool {
	return len(u.records) == 0
}

func (u *Updater) StagingIsInReview() (bool, error) {
	resp, err := u.staging.SignerStatusFor(StagingCollection())
	if err != nil {
		return false, errors.WithStack(err)
	}
	return resp.InReview(), nil
}

func (u *Updater) PushToStaging() transaction.Transactor {
	committed := 0
	return transaction.NewTransaction().WithCommit(func() error {
		collection := StagingCollection()
		for _, record := range u.records {
			err := u.staging.NewRecord(collection, record)
			if err != nil {
				return errors.WithStack(err)
			}
			committed += 1
		}
		return nil
	}).WithRollback(func(_ error) error {
		var err error = nil
		collection := StagingCollection()
		for i := 0; i < committed; i++ {
			_, e := u.staging.Delete(collection, u.records[i])
			if e != nil {
				if err == nil {
					err = e
				} else {
					err = errors.Wrap(err, e.Error())
				}
			}
		}
		return errors.WithStack(err)
	})
}

const attachmentWarning = "received an error while uploading an attachment to Bugzilla, however " +
	"a 'Failed to fetch attachment ID <ID> from S3' error always occurs when attaching a bug. This is " +
	"likely just a synchronization bug wherein Bugzilla saves a record to S3 and then immediately attempts " +
	"to retrieve it, however S3 has not published the ID yet. If that is this error, then please " +
	"ignore it."

func (u *Updater) OpenBug() transaction.Transactor {
	u.bugID = -1
	return transaction.NewTransaction().WithCommit(func() error {
		comment := ""
		proposedAdditions := make([]*onecrl.Record, 0)
		for _, record := range u.records {
			comment += fmt.Sprintf("issuer: %s serial %s\n", record.IssuerName, record.SerialNumber)
			proposedAdditions = append(proposedAdditions, record)
		}
		bug := &bugs.Create{
			Product:   "Toolkit",
			Component: "Blocklist Policy Requests",
			Summary:   fmt.Sprintf("CCADB entries generated %s", time.Now().UTC().Format(time.RFC3339)),
			Version:   "unspecified",
			Severity:  "normal",
			Type:      "enhancement",
		}
		resp, err := u.bugzilla.CreateBug(bug)
		if err != nil {
			return errors.WithStack(err)
		}
		u.bugID = resp.Id
		for _, record := range u.records {
			record.Details.Bug = u.bugzilla.ShowBug(u.bugID)
		}
		_, err = u.bugzilla.CreateAttachment((&attachments.Create{
			BugId:       resp.Id,
			Data:        []byte(comment),
			FileName:    "BugData.txt",
			Summary:     "Line delimited issuer/serial pairs",
			ContentType: "text/plain",
		}).AddBug(resp.Id))
		if err != nil {
			log.WithError(err).WithField("attachment", "BugData.txt").Warn(attachmentWarning)
		}
		additions, err := json.MarshalIndent(proposedAdditions, "", "  ")
		if err != nil {
			return errors.WithStack(err)
		}
		_, err = u.bugzilla.CreateAttachment((&attachments.Create{
			BugId:       resp.Id,
			Data:        additions,
			FileName:    "OneCRLAdditions.txt",
			Summary:     "The additions to OneCRL proposed by this bug.",
			ContentType: "text/plain",
		}).AddBug(resp.Id))
		if err != nil {
			log.WithError(err).WithField("attachment", "OneCRLAdditions.txt").Warn(attachmentWarning)
		}
		decodes := make([]interface{}, 0)
		for _, record := range u.records {
			d, err := record.ToComparison()
			if err != nil {
				return errors.WithStack(err)
			}
			decodes = append(decodes, d)
		}
		d, err := json.MarshalIndent(decodes, "", "  ")
		if err != nil {
			return errors.WithStack(err)
		}
		_, err = u.bugzilla.CreateAttachment((&attachments.Create{
			BugId:       resp.Id,
			Data:        d,
			FileName:    "DecodedEntries.txt",
			Summary:     "Entries with their names decoded to plain text and hexadecimal serials/hashes.",
			ContentType: "text/plain",
		}).AddBug(resp.Id))
		if err != nil {
			log.WithError(err).WithField("attachment", "DecodedEntries.txt").Warn(attachmentWarning)
		}
		return nil
	}).WithRollback(func(cause error) error {
		if u.bugID == -1 {
			return nil
		}
		report := &strings.Builder{}
		logger := log.New()
		logger.SetFormatter(&log.JSONFormatter{PrettyPrint: true})
		logger.SetOutput(report)
		logger.WithError(cause).
			WithField("stacktrace", fmt.Sprintf("%+v", cause)). // "%+v" gets us a stack trace printed out
			Error("This tool experienced a fatal error downstream of posting this bug. This bug will be " +
				"closed. Please review the provided cause and call site of the cause for more information.")
		log.WithError(cause).WithField("bugzilla", u.bugzilla.ShowBug(u.bugID)).Error("closing the listed " +
			"bug due to a critical failure")
		_, err := u.bugzilla.UpdateBug(bugs.Invalidate(u.bugID, report.String()))
		return errors.WithStack(err)
	})
}

func (u *Updater) UpdateRecordsWithBugID() transaction.Transactor {
	return transaction.NewTransaction().WithCommit(func() error {
		collection := StagingCollection()
		for _, record := range u.records {
			if record == nil {
				continue
			}
			err := u.staging.UpdateRecord(collection, record)
			if err != nil {
				return errors.WithStack(err)
			}
		}
		return errors.WithStack(u.staging.ToSign(collection))
	}).WithRollback(func(_ error) error {
		// Upstream transactions are going to delete these records
		// anyways, so I don't really see much of anything to do here.
		return nil
	})
}

func (u *Updater) PutStagingIntoReview() transaction.Transactor {
	return transaction.NewTransaction().WithCommit(func() error {
		return errors.WithStack(u.staging.ToReview(StagingCollection()))
	}).WithRollback(func(_ error) error {
		return errors.WithStack(u.staging.ToRollBack(StagingCollection()))
	})
}

func (u *Updater) PushToProduction() transaction.Transactor {
	return transaction.NewTransaction().WithCommit(func() error {
		collection := ProductionCollection()
		for _, record := range u.records {
			// If we do not set the ID back to default then production will
			// end up having IDs that were generated by staging rather than itself.
			record.Id = ""
			err := u.production.NewRecord(collection, record)
			if err != nil {
				return errors.WithStack(err)
			}
		}
		return nil
	})
}
