/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package api

// A Resourcer returns the REST API resource for accessing
// a given endpoint. The returned string should fulfill
// all paths BEYOND the base path and "rest" resource (proto>://<hostname>/rest).
//
// E.G. If we are accessing a bug at "https://bugzilla-dev.allizom.org" then
// this method should return "/bug/<id>"
type Resourcer interface {
	Resource() string
}
