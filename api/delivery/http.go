package delivery

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"proxy/api/repository"
	"proxy/goproxy"
	pkgHttp "proxy/goproxy/pkg/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

type Handlers struct {
	repo *repository.ProxyDB
	prx  *goproxy.Proxy
}

func NewHandlers(r *repository.ProxyDB, p *goproxy.Proxy) Handlers {
	return Handlers{repo: r, prx: p}
}

// GetRequests path: /requests
func (h *Handlers) GetRequests(w http.ResponseWriter, r *http.Request) {
	response, err := h.repo.GetRequests()
	if err != nil {
		pkgHttp.HandleError(w, r, err, 500)
		return
	}
	pkgHttp.SendJSON(w, r, http.StatusOK, response)
}

// GetRequest path: /request/{id}
func (h *Handlers) GetRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	requestId, ok := vars["id"]
	if !ok {
		pkgHttp.HandleError(w, r, errors.New("ErrInvalidURL, expected /request/{id}"), 400)
		return
	}

	response, err := h.repo.GetRequestByID(requestId)
	if err != nil {
		pkgHttp.HandleError(w, r, err, 500)
		return
	}
	if response == nil {
		pkgHttp.HandleError(w, r, errors.New("request not found"), 404)
		return
	}

	pkgHttp.SendJSON(w, r, http.StatusOK, response)
}

// GetReqsponses path: /responses
func (h *Handlers) GetResponses(w http.ResponseWriter, r *http.Request) {
	response, err := h.repo.GetResponses()
	if err != nil {
		pkgHttp.HandleError(w, r, err, 500)
		return
	}
	pkgHttp.SendJSON(w, r, http.StatusOK, response)
}

// GetResponse path: /response?req_id
func (h *Handlers) GetResponse(w http.ResponseWriter, r *http.Request) {
	requestId := r.URL.Query().Get("req_id")
	if requestId == "" {
		pkgHttp.HandleError(w, r, errors.New("ErrInvalidURL, expected /response?req_id"), 400)
		return
	}

	response, err := h.repo.GetResponseByReqID(requestId)
	if err != nil {
		pkgHttp.HandleError(w, r, err, 500)
		return
	}
	if response == nil {
		pkgHttp.HandleError(w, r, errors.New("request not found"), 404)
		return
	}

	pkgHttp.SendJSON(w, r, http.StatusOK, response)
}

// Repeat request path: /repeat/{id}
func (h *Handlers) Repeat(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	requestId, ok := vars["id"]
	if !ok {
		pkgHttp.HandleError(w, r, errors.New("ErrInvalidURL, expected /request/{id}"), 400)
		return
	}

	response, err := h.repo.GetRequestByID(requestId)
	if err != nil {
		pkgHttp.HandleError(w, r, err, 500)
		return
	}
	if response == nil {
		pkgHttp.HandleError(w, r, errors.New("request not found"), 404)
		return
	}

	cookies := ""
	for k, v := range response.Cookies {
		cookies += fmt.Sprintf(" %s=%s;", k, v)
	}

	if len(cookies) != 0 {
		cookies = cookies[:len(cookies)-1] // delete trailing ";"
		response.Headers["Cookie"] = []string{cookies}
	}
	reqUrl, err := url.Parse(response.Path)
	if err != nil {
		pkgHttp.HandleError(w, r, errors.Wrap(err, "failed parse stored url"), 500)
		return
	}
	req := &http.Request{
		Method:   response.Method,
		URL:      reqUrl,
		Header:   response.Headers,
		PostForm: response.PostParams,
		Body:     io.NopCloser(strings.NewReader(response.Body)),
	}

	q := url.Values{}
	for k, v := range response.GetParams {
		for _, param := range v {
			q.Add(k, param)
		}
	}

	req.URL.RawQuery = q.Encode()
	fmt.Println(req)

	proxyUrl, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		pkgHttp.HandleError(w, r, errors.Wrap(err, "failed parse proxy url"), 500)
		return
	}
	httpClient := http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyUrl),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			TLSNextProto:    make(map[string]func(string, *tls.Conn) http.RoundTripper),
		},
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		pkgHttp.HandleError(w, r, errors.Wrap(err, "failed repeat request"), 500)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		pkgHttp.HandleError(w, r, errors.Wrap(err, "failed read response body"), 500)
		return
	}

	for k, v := range resp.Header {
		for _, par := range v {
			w.Header().Set(k, par)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func (h *Handlers) ScanXXE(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	requestId, ok := vars["id"]
	if !ok {
		pkgHttp.HandleError(w, r, errors.New("ErrInvalidURL, expected /scan/{id}"), 400)
		return
	}

	xmlXXE := `<!DOCTYPE foo [
	<!ELEMENT foo ANY >
	<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
	<foo>&xxe;</foo>`

	response, err := h.repo.GetRequestByID(requestId)
	if err != nil {
		pkgHttp.HandleError(w, r, err, 500)
		return
	}
	if response == nil {
		pkgHttp.HandleError(w, r, errors.New("request not found"), 404)
		return
	}

	if strings.Contains(response.Body, "xml") {
		pkgHttp.HandleError(w, r, errors.New("its not a xml request"), 400)
		return
	}

	cookies := ""
	for k, v := range response.Cookies {
		cookies += fmt.Sprintf(" %s=%s;", k, v)
	}

	if len(cookies) != 0 {
		cookies = cookies[:len(cookies)-1] // delete trailing ";"
		response.Headers["Cookie"] = []string{cookies}
	}
	reqUrl, err := url.Parse(response.Path)
	if err != nil {
		pkgHttp.HandleError(w, r, errors.Wrap(err, "failed parse stored url"), 500)
		return
	}

	req := &http.Request{
		Method:   response.Method,
		URL:      reqUrl,
		Header:   response.Headers,
		PostForm: response.PostParams,
		Body:     io.NopCloser(strings.NewReader(xmlXXE)),
	}

	q := url.Values{}
	for k, v := range response.GetParams {
		for _, param := range v {
			q.Add(k, param)
		}
	}

	req.URL.RawQuery = q.Encode()
	fmt.Println(req)

	proxyUrl, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		pkgHttp.HandleError(w, r, errors.Wrap(err, "failed parse proxy url"), 500)
		return
	}
	httpClient := http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyUrl),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			TLSNextProto:    make(map[string]func(string, *tls.Conn) http.RoundTripper),
		},
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		pkgHttp.HandleError(w, r, errors.Wrap(err, "failed repeat request"), 500)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		pkgHttp.HandleError(w, r, errors.Wrap(err, "failed read response body"), 500)
		return
	}

	for k, v := range resp.Header {
		for _, par := range v {
			w.Header().Set(k, par)
		}
	}

	type scanResponse struct {
		ScanResult string
	}
	res := scanResponse{}
	if strings.Contains(string(body), "root:") {
		res.ScanResult = "NOT SAFETY REQUEST, XXE DETECTED"
	} else {
		res.ScanResult = "all is OK, XXE not detected"
	}

	pkgHttp.SendJSON(w, r, http.StatusOK, res)
}
