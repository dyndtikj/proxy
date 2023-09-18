package goproxy

import (
	"crypto/tls"
	"net/http"
	"sync/atomic"
	"time"
)

type ConnectAction int

const (
	ConnectNone = ConnectAction(iota)
	ConnectMitm
)

type Proxy struct {
	// Session number of last proxy request.
	SessionNo int64

	// RoundTripper interface to obtain remote response.
	// By default, it uses &http.Transport{}.
	Rt http.RoundTripper

	// Certificate key pair.
	Ca tls.Certificate

	// User data to use free.
	UserData interface{}

	// Error callback.
	OnError func(ctx *Context, where string, err *Error, opErr error)

	// Accept callback. It greets proxy request like ServeHTTP function of
	// http.Handler.
	// If it returns true, stops processing proxy request.
	OnAccept func(ctx *Context, w http.ResponseWriter, r *http.Request) bool

	// Connect callback. It sets connect action and new host.
	// If len(newhost) > 0, host changes.
	OnConnect func(ctx *Context, host string) (ConnectAction ConnectAction,
		newHost string)

	// Request callback. It greets remote request.
	// If it returns non-nil response, stops processing remote request.
	OnRequest func(ctx *Context, req *http.Request) (resp *http.Response)

	// Response callback. It greets remote response.
	// Remote response sends after this callback.
	OnResponse func(ctx *Context, req *http.Request, resp *http.Response)

	// If ConnectAction is ConnectMitm, it sets chunked to Transfer-Encoding.
	// By default, true.
	MitmChunked bool

	signer *CaSigner
}

// NewProxy returns a new Proxy has default CA certificate and key.
func NewProxy() (*Proxy, error) {
	prx := &Proxy{
		Rt: &http.Transport{TLSClientConfig: &tls.Config{},
			Proxy: http.ProxyFromEnvironment},
		MitmChunked: true,
		OnConnect: func(ctx *Context, host string) (ConnectAction ConnectAction, newHost string) {
			return ConnectNone, host // In this case we cant serve CONNECT request ( in this case proxy closes )
		},
	}
	return prx, nil
}

// NewProxyTLS returns a new Proxy given CA certificate and key.
func NewProxyTLS(caCert, caKey []byte) (*Proxy, error) {
	prx := &Proxy{
		Rt: &http.Transport{TLSClientConfig: &tls.Config{},
			Proxy: http.ProxyFromEnvironment},
		MitmChunked: true,
		signer:      NewCaSignerCache(time.Hour*10, time.Minute*10),
	}
	prx.signer.Ca = &prx.Ca
	var err error
	prx.Ca, err = tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return nil, err
	}
	return prx, nil
}

// ServeHTTP implements http.Handler.
func (prx *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := &Context{Prx: prx, SessionNo: atomic.AddInt64(&prx.SessionNo, 1)}

	defer func() {
		rec := recover()
		if rec != nil {
			if err, ok := rec.(error); ok && prx.OnError != nil {
				prx.OnError(ctx, "ServeHTTP", ErrPanic, err)
			}
			panic(rec)
		}
	}()

	if ctx.DoAccept(w, r) {
		return
	}

	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")

	if b := ctx.DoConnect(w, r); b {
		return
	}

	for {
		var w2 = w
		var r2 = r
		var cyclic = false
		switch ctx.ConnectAction {
		case ConnectMitm:
			if prx.MitmChunked {
				cyclic = true
			}
			w2, r2 = ctx.DoMitm()
		}
		if w2 == nil || r2 == nil {
			break
		}
		ctx.SubSessionNo++
		if b, err := ctx.DoRequest(w2, r2); err != nil {
			break
		} else {
			if b {
				if !cyclic {
					break
				} else {
					continue
				}
			}
		}
		if err := ctx.DoResponse(w2, r2); err != nil || !cyclic {
			break
		}
	}

	if ctx.HijTLSConn != nil {
		ctx.HijTLSConn.Close()
	}
}
