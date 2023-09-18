package goproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
)

// Context keeps context of each proxy request.
type Context struct {
	Prx       *Proxy
	SessionNo int64
	// Sub session number of processing remote connection.
	SubSessionNo int64
	// Original Proxy request.
	Req *http.Request
	// Original Proxy request, if proxy request method is CONNECT.
	ConnectReq *http.Request
	// Action of after the CONNECT, if proxy request method is CONNECT.
	ConnectAction ConnectAction
	// Remote host, if proxy request method is CONNECT.
	ConnectHost string
	// User data to use free.
	UserData     interface{}
	HijTLSConn   *tls.Conn
	hijTLSReader *bufio.Reader
	ReqID        string
}

func (ctx *Context) onAccept(w http.ResponseWriter, r *http.Request) bool {
	return ctx.Prx.OnAccept(ctx, w, r)
}

func (ctx *Context) onConnect(host string) (ConnectAction ConnectAction,
	newHost string) {
	return ctx.Prx.OnConnect(ctx, host)
}

func (ctx *Context) onRequest(req *http.Request) (resp *http.Response) {
	return ctx.Prx.OnRequest(ctx, req)
}

func (ctx *Context) onResponse(req *http.Request, resp *http.Response) {
	ctx.Prx.OnResponse(ctx, req, resp)
}

func (ctx *Context) DoError(where string, err *Error, opErr error) {
	if ctx.Prx.OnError == nil {
		return
	}
	ctx.Prx.OnError(ctx, where, err, opErr)
}

func (ctx *Context) DoAccept(w http.ResponseWriter, r *http.Request) bool {
	ctx.Req = r
	if !r.ProtoAtLeast(1, 0) || r.ProtoAtLeast(2, 0) {
		if r.Body != nil {
			defer r.Body.Close()
		}
		ctx.DoError("Accept", ErrNotSupportHTTPVer, nil)
		return true
	}
	if ctx.Prx.OnAccept != nil && ctx.onAccept(w, r) {
		if r.Body != nil {
			defer r.Body.Close()
		}
		return true
	}
	return false
}

func (ctx *Context) DoConnect(w http.ResponseWriter, r *http.Request) (b bool) {
	b = true
	if r.Method != "CONNECT" {
		b = false
		return
	}
	hij, ok := w.(http.Hijacker)
	if !ok {
		if r.Body != nil {
			defer r.Body.Close()
		}
		ctx.DoError("Connect", ErrNotSupportHijacking, nil)
		return
	}
	conn, _, err := hij.Hijack()
	if err != nil {
		if r.Body != nil {
			defer r.Body.Close()
		}
		ctx.DoError("Connect", ErrNotSupportHijacking, err)
		return
	}
	hijConn := conn
	ctx.ConnectReq = r
	ctx.ConnectAction = ConnectMitm
	host := r.URL.Host
	if !hasPort.MatchString(host) {
		host += ":80"
	}
	if ctx.Prx.OnConnect != nil {
		var newHost string
		ctx.ConnectAction, newHost = ctx.onConnect(host)
		if newHost != "" {
			host = newHost
		}
	}
	if !hasPort.MatchString(host) {
		host += ":80"
	}
	ctx.ConnectHost = host
	switch ctx.ConnectAction {
	case ConnectMitm:
		tlsConfig := &tls.Config{}
		if ctx.Prx.signer == nil {
			hijConn.Close()
			ctx.DoError("Connect", ErrInternalNoSigner, err)
			return
		}
		cert := ctx.Prx.signer.SignHost(host)
		if cert == nil {
			hijConn.Close()
			ctx.DoError("Connect", ErrTLSSignHost, err)
			return
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, *cert)
		if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			hijConn.Close()
			if !isConnectionClosed(err) {
				ctx.DoError("Connect", ErrResponseWrite, err)
			}
			return
		}
		ctx.HijTLSConn = tls.Server(hijConn, tlsConfig)
		if err := ctx.HijTLSConn.Handshake(); err != nil {
			ctx.HijTLSConn.Close()
			if !isConnectionClosed(err) {
				ctx.DoError("Connect", ErrTLSHandshake, err)
			}
			return
		}
		ctx.hijTLSReader = bufio.NewReader(ctx.HijTLSConn)
		b = false
	default:
		hijConn.Close()
	}
	return
}

func (ctx *Context) DoMitm() (w http.ResponseWriter, r *http.Request) {
	req, err := http.ReadRequest(ctx.hijTLSReader)
	if err != nil {
		if !isConnectionClosed(err) {
			ctx.DoError("Request", ErrRequestRead, err)
		}
		return
	}
	if strings.Contains(req.URL.String(), "marks") {
		fmt.Println(req)
		fmt.Println(req.PostForm)
		fmt.Println(req.Form)
	}
	req.RemoteAddr = ctx.ConnectReq.RemoteAddr
	if req.URL.IsAbs() {
		ctx.DoError("Request", ErrAbsURLAfterCONNECT, nil)
		return
	}
	req.URL.Scheme = "https"
	req.URL.Host = ctx.ConnectHost
	w = NewConnResponseWriter(ctx.HijTLSConn)
	r = req
	return
}

func (ctx *Context) DoRequest(w http.ResponseWriter, r *http.Request) (bool, error) {
	if !r.URL.IsAbs() {
		if r.Body != nil {
			defer r.Body.Close()
		}
		err := ServeInMemory(w, 500, nil, []byte("This is a proxy server. Does not respond to non-proxy requests."))
		if err != nil && !isConnectionClosed(err) {
			ctx.DoError("Request", ErrResponseWrite, err)
		}
		return true, err
	}
	r.RequestURI = r.URL.String()
	if ctx.Prx.OnRequest == nil {
		return false, nil
	}
	resp := ctx.onRequest(r)
	if resp == nil {
		return false, nil
	}
	if r.Body != nil {
		defer r.Body.Close()
	}
	resp.Request = r
	resp.TransferEncoding = nil
	if ctx.ConnectAction == ConnectMitm && ctx.Prx.MitmChunked {
		resp.TransferEncoding = []string{"chunked"}
	}
	err := ServeResponse(w, resp)
	if err != nil && !isConnectionClosed(err) {
		ctx.DoError("Request", ErrResponseWrite, err)
	}
	return true, err
}

func (ctx *Context) DoResponse(w http.ResponseWriter, r *http.Request) error {
	if r.Body != nil {
		defer r.Body.Close()
	}
	resp, err := ctx.Prx.Rt.RoundTrip(r)
	if err != nil {
		if err != context.Canceled && !isConnectionClosed(err) {
			ctx.DoError("Response", ErrRoundTrip, err)
		}
		err := ServeInMemory(w, 404, nil, nil)
		if err != nil && !isConnectionClosed(err) {
			ctx.DoError("Response", ErrResponseWrite, err)
		}
		return err
	}
	if ctx.Prx.OnResponse != nil {
		ctx.onResponse(r, resp)
	}
	resp.Request = r
	resp.TransferEncoding = nil
	if ctx.ConnectAction == ConnectMitm && ctx.Prx.MitmChunked {
		resp.TransferEncoding = []string{"chunked"}
	}
	err = ServeResponse(w, resp)
	if err != nil && !isConnectionClosed(err) {
		ctx.DoError("Response", ErrResponseWrite, err)
	}
	return err
}
