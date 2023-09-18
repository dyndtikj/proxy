package http

import (
	"encoding/json"
	"net/http"
)

func SendJSON(w http.ResponseWriter, r *http.Request, status int, dataStruct any) {
	dataJSON, err := json.Marshal(dataStruct)
	if err != nil {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_, err = w.Write(dataJSON)
	if err != nil {
		return
	}
}
