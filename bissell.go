package main
 
import (
    "encoding/json"
    "log"
    "net/http"
    "time"

    "github.com/gorilla/mux"
)

type Error struct {
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

var status Status

func GetStatusEndpoint(w http.ResponseWriter, req *http.Request) {
	json.NewEncoder(w).Encode(status)
}

func main() {
	router := mux.NewRouter()
	status = Status{AuthenticatedUser: "username", Connections: StatusConnections{}, Precache: StatusPrecache{}, Irods: StatusIrods{}}
	router.HandleFunc("/status", GetStatusEndpoint).Methods("GET")
	log.Fatal(http.ListenAndServe(":5000", router))
}
