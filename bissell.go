package main
 
import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "path"
    "time"

    "github.com/golang/gddo/httputil"
    "github.com/gorilla/mux"
)

const (
	ConfigDefaultListen = ":5000"
)

const (
	ContentTypeData = "application/octet-stream"
	ContentTypeMetadata = "application/vnd.irobot.metadata+json"
)

type HttpError struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
	Description string `json:"description"`
}

type Status struct {
	AuthenticatedUser string `json:"authenticated_user"`
	Connections StatusConnections `json:"connections"`
	Precache StatusPrecache `json:"precache"`
	Irods StatusIrods `json:"irods"`
}

type StatusConnections struct {
	Active int `json:"active"`
	Total int `json:"total"`
	Since time.Time `json:"since"`
}

type StatusPrecache struct {
	Commitment int `json:"commitment"`
	ChecksumRate StatusRate `json:"checksum_rate"`
}

type StatusRate struct {
	Average int `json:"average"`
	Stderr int `json:"stderr"`
}

type StatusIrods struct {
	Active int `json:"active"`
	DownloadRate StatusRate `json:"download_rate"`
}

type ManifestEntry struct {
	Path string `json:"path"`
	Availability ManifestEntryAvailability `json:"availability"`
	LastAccessed time.Time `json:"last_accessed"`
	Contention int `json:"contention"`
}

type ManifestEntryAvailability struct {
	Data string `json:"data"`
	Metadata string `json:"metadata"`
	Checksums string `json:"checksums"`
}

type Metadata struct {
	Checksum string `json:"checksum"`
	Size int `json:"size"`
	Created time.Time `json:"created"`
	Modified time.Time `json:"modified"`
	AVUs []map[string]string `json:"avus"`
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
	contentType := httputil.NegotiateContentType(req, acceptable, "")
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
			http.ServeFile(w, req, "test.cram")
		case ".crai":
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


func main() {
	router := mux.NewRouter()
	router.HandleFunc("/status", GetHeadStatusEndpoint).Methods("GET", "HEAD")
	router.HandleFunc("/config", GetHeadConfigEndpoint).Methods("GET", "HEAD")
	router.HandleFunc("/manifest", GetHeadConfigEndpoint).Methods("GET", "HEAD")
	router.PathPrefix("/").HandlerFunc(GetHeadDataObject).Methods("GET", "HEAD")
	router.PathPrefix("/").HandlerFunc(PostDataObject).Methods("POST")
	router.PathPrefix("/").HandlerFunc(DeleteDataObject).Methods("DELETE")
	log.Fatal(http.ListenAndServe(ConfigDefaultListen, router))
}
