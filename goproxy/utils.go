package goproxy

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Library specific errors.
var (
	ErrPanic                       = NewError("panic")
	ErrResponseWrite               = NewError("response write")
	ErrRequestRead                 = NewError("request read")
	ErrNotSupportHijacking         = NewError("hijacking not supported")
	ErrTLSSignHost                 = NewError("TLS sign host")
	ErrInternalNoSigner            = NewError("No signer provided to serve tls")
	ErrTLSHandshake                = NewError("TLS handshake")
	ErrAbsURLAfterCONNECT          = NewError("absolute URL after CONNECT")
	ErrRoundTrip                   = NewError("round trip")
	ErrUnsupportedTransferEncoding = NewError("unsupported transfer encoding")
	ErrNotSupportHTTPVer           = NewError("http version not supported")
)

var chunkedSeparator = []byte("\r\n")

type Error struct {
	ErrString string
}

func NewError(errString string) *Error {
	return &Error{errString}
}

// Error implements error interface.
func (e *Error) Error() string {
	return e.ErrString
}

func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	i := 0
	var newerr = &err
	for opError, ok := (*newerr).(*net.OpError); ok && i < 10; {
		i++
		newerr = &opError.Err
		if syscallError, ok := (*newerr).(*os.SyscallError); ok {
			if syscallError.Err == syscall.EPIPE || syscallError.Err == syscall.ECONNRESET || syscallError.Err == syscall.EPROTOTYPE {
				return true
			}
		}
	}
	return false
}

func CreateResponse(code int, header http.Header, body []byte) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	st := http.StatusText(code)
	if st != "" {
		st = " " + st
	}
	var bodyReadCloser io.ReadCloser
	var bodyContentLength = int64(0)
	if body != nil {
		bodyReadCloser = ioutil.NopCloser(bytes.NewBuffer(body))
		bodyContentLength = int64(len(body))
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d%s", code, st),
		StatusCode:    code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          bodyReadCloser,
		ContentLength: bodyContentLength,
	}
}

func ServeResponse(w http.ResponseWriter, resp *http.Response) error {
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	h := w.Header()
	for k, v := range resp.Header {
		for _, v1 := range v {
			h.Add(k, v1)
		}
	}
	if h.Get("Date") == "" {
		h.Set("Date", time.Now().UTC().Format("Mon, 2 Jan 2006 15:04:05")+" GMT")
	}
	if h.Get("Content-Type") == "" && resp.ContentLength != 0 {
		h.Set("Content-Type", "text/plain; charset=utf-8")
	}
	if resp.ContentLength >= 0 {
		h.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	} else {
		h.Del("Content-Length")
	}
	h.Del("Transfer-Encoding")
	te := ""
	if len(resp.TransferEncoding) > 0 {
		if len(resp.TransferEncoding) > 1 {
			return ErrUnsupportedTransferEncoding
		}
		te = resp.TransferEncoding[0]
	}
	h.Del("Connection")
	clientConnection := ""
	if resp.Request != nil {
		clientConnection = resp.Request.Header.Get("Connection")
	}
	switch clientConnection {
	case "close":
		h.Set("Connection", "close")
	case "keep-alive":
		if h.Get("Content-Length") != "" || te == "chunked" {
			h.Set("Connection", "keep-alive")
		} else {
			h.Set("Connection", "close")
		}
	default:
		if te == "chunked" {
			h.Set("Connection", "close")
		}
	}
	switch te {
	case "":
		w.WriteHeader(resp.StatusCode)
		if resp.Body != nil {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			// Restore the io.ReadCloser to it's original state
			resp.Body = io.NopCloser(bytes.NewBuffer(body))
			w.Write(body)
		}
	case "chunked":
		h.Set("Transfer-Encoding", "chunked")
		w.WriteHeader(resp.StatusCode)
		chW := httputil.NewChunkedWriter(w)
		if resp.Body != nil {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			// Restore the io.ReadCloser to it's original state
			resp.Body = io.NopCloser(bytes.NewBuffer(body))
			chW.Write(body)
		}
		if err := chW.Close(); err != nil {
			return err
		}
		if _, err := w.Write(chunkedSeparator); err != nil {
			return err
		}
	default:
		return ErrUnsupportedTransferEncoding
	}
	return nil
}

func ServeInMemory(w http.ResponseWriter, code int, header http.Header, body []byte) error {
	return ServeResponse(w, CreateResponse(code, header, body))
}

var hasPort = regexp.MustCompile(`:\d+$`)

func stripPort(s string) string {
	ix := strings.IndexRune(s, ':')
	if ix == -1 {
		return s
	}
	return s[:ix]
}

func hash(s string) *big.Int {
	rv := new(big.Int)
	h := sha1.New()
	h.Write([]byte(s))
	rv.SetBytes(h.Sum(nil))
	return rv
}
