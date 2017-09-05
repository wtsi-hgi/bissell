// Copyright (c) 2017 Genome Research Ltd.
// Author: Joshua C. Randall <jcrandall@alum.mit.edu>
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation; either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/golang/gddo/httputil"
	"github.com/gorilla/mux"
)

const (
	ConfigDefaultListen = ":5000"
)

const (
	ContentTypeData     = "application/octet-stream"
	ContentTypeMetadata = "application/vnd.irobot.metadata+json"
)

type HttpError struct {
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Description string `json:"description"`
}

type Status struct {
	AuthenticatedUser string            `json:"authenticated_user"`
	Connections       StatusConnections `json:"connections"`
	Precache          StatusPrecache    `json:"precache"`
	Irods             StatusIrods       `json:"irods"`
}

type StatusConnections struct {
	Active int       `json:"active"`
	Total  int       `json:"total"`
	Since  time.Time `json:"since"`
}

type StatusPrecache struct {
	Commitment   int        `json:"commitment"`
	ChecksumRate StatusRate `json:"checksum_rate"`
}

type StatusRate struct {
	Average int `json:"average"`
	Stderr  int `json:"stderr"`
}

type StatusIrods struct {
	Active       int        `json:"active"`
	DownloadRate StatusRate `json:"download_rate"`
}

type ManifestEntry struct {
	Path         string                    `json:"path"`
	Availability ManifestEntryAvailability `json:"availability"`
	LastAccessed time.Time                 `json:"last_accessed"`
	Contention   int                       `json:"contention"`
}

type ManifestEntryAvailability struct {
	Data      string `json:"data"`
	Metadata  string `json:"metadata"`
	Checksums string `json:"checksums"`
}

type Metadata struct {
	Checksum string              `json:"checksum"`
	Size     int                 `json:"size"`
	Created  time.Time           `json:"created"`
	Modified time.Time           `json:"modified"`
	AVUs     []map[string]string `json:"avus"`
}

func HandleError(w http.ResponseWriter, req *http.Request, code int, reason string, desc string) {
	status := http.StatusText(code)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if req.Method == http.MethodGet {
		httpErr := HttpError{Status: status, Reason: reason, Description: desc}
		json.NewEncoder(w).Encode(httpErr)
	}
}

func GetHeadStatusEndpoint(w http.ResponseWriter, req *http.Request) {
	status := Status{AuthenticatedUser: "username", Connections: StatusConnections{}, Precache: StatusPrecache{}, Irods: StatusIrods{}}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if req.Method == http.MethodGet {
		json.NewEncoder(w).Encode(status)
	}
}

func GetHeadConfigEndpoint(w http.ResponseWriter, req *http.Request) {
	HandleError(w, req, http.StatusNotImplemented, "config endpoint is not implemented", "nothing to see here.")
}

func GetHeadManifestEndpoint(w http.ResponseWriter, req *http.Request) {
	manifest := []ManifestEntry{}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if req.Method == http.MethodGet {
		json.NewEncoder(w).Encode(manifest)
	}
}

func GetHeadDataObject(w http.ResponseWriter, req *http.Request) {
	acceptable := []string{ContentTypeData, ContentTypeMetadata}
	contentType := httputil.NegotiateContentType(req, acceptable, ContentTypeData)
	switch contentType {
	case ContentTypeData:
		GetHeadDataObjectData(w, req)
	case ContentTypeMetadata:
		GetHeadDataObjectMetadata(w, req)
	default:
		HandleError(w, req, http.StatusNotAcceptable, fmt.Sprintf("Please accept one of the supported content types: %v", acceptable), "You specified an Accept header that does not include any of the supported content types.")
	}
}

func GetHeadDataObjectData(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", ContentTypeData)
	if req.Method == http.MethodGet {
		switch path.Ext(req.URL.Path) {
		case ".cram":
			w.Header().Set("ETag", "15af103abfc18fbe9d45d78e98b36b64")
			http.ServeFile(w, req, "test.cram")
		case ".crai":
			w.Header().Set("ETag", "c00265295b381d1d6c1359d748558fc9")
			http.ServeFile(w, req, "test.cram.crai")
		default:
			HandleError(w, req, http.StatusNotFound, fmt.Sprintf("File not found: %v", req.URL.Path), "The requested file was not found. This server is currently only able to return test data, and only for files ending in .cram or .crai")
		}
	}
}

func GetHeadDataObjectMetadata(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", ContentTypeMetadata)
	w.WriteHeader(http.StatusOK)
	metadata := Metadata{}
	if req.Method == http.MethodGet {
		json.NewEncoder(w).Encode(metadata)
	}
}

func PostDataObject(w http.ResponseWriter, req *http.Request) {
	HandleError(w, req, http.StatusInsufficientStorage, "Precache not implemented", "Precache/cache management functionality not implemented in this server. Please proceed with request without explicit caching.")
}

func DeleteDataObject(w http.ResponseWriter, req *http.Request) {
	HandleError(w, req, http.StatusNotFound, "Precache not implemented", "Precache/cache management functionality not implemented in this server, so there is no need to explicitly delete anything.")
}

func arvadosAuth(r *http.Request) (apiToken string, ok bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return
	}
	const prefix = "Arvados "
	if !strings.HasPrefix(auth, prefix) {
		return
	}
	apiToken = auth[len(prefix):]
	ok = true
	return
}

func iRobotAuthHandler(nextHandler http.Handler, basicRealm string, arvadosRealm string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		validApiToken := "testtoken"
		validUsername := "testuser"
		validPassword := "testpass"
		apiToken, ok := arvadosAuth(req)
		if ok {
			if subtle.ConstantTimeCompare([]byte(apiToken), []byte(validApiToken)) == 1 {
				nextHandler.ServeHTTP(w, req)
				return
			}
		}
		username, password, ok := req.BasicAuth()
		if ok {
			if subtle.ConstantTimeCompare([]byte(username), []byte(validUsername)) == 1 && subtle.ConstantTimeCompare([]byte(password), []byte(validPassword)) == 1 {
				nextHandler.ServeHTTP(w, req)
				return
			}
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s", Arvados realm="%s"`, basicRealm, arvadosRealm))
		HandleError(w, req, http.StatusUnauthorized, "Unauthorized", "Please provide valid credentials.")
		return
	})
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/status", GetHeadStatusEndpoint).Methods("GET", "HEAD")
	router.HandleFunc("/config", GetHeadConfigEndpoint).Methods("GET", "HEAD")
	router.HandleFunc("/manifest", GetHeadConfigEndpoint).Methods("GET", "HEAD")
	router.PathPrefix("/").HandlerFunc(GetHeadDataObject).Methods("GET", "HEAD")
	router.PathPrefix("/").HandlerFunc(PostDataObject).Methods("POST")
	router.PathPrefix("/").HandlerFunc(DeleteDataObject).Methods("DELETE")
	log.Fatal(http.ListenAndServe(ConfigDefaultListen, iRobotAuthHandler(router, "basic username/password", "arvados api token")))
}
