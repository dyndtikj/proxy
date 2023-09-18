package http

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

type Error struct {
	err string
}

func HandleError(w http.ResponseWriter, r *http.Request, err error, code int) {
	log.Error(err)
	errStruct := Error{err.Error()}
	SendJSON(w, r, code, errStruct)
}
