package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"os/signal"
	"proxy/api"
	"proxy/api/delivery"
	"proxy/api/repository"
	logger "proxy/goproxy/pkg/log"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/gorilla/mux"
	"github.com/klauspost/compress/gzip"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"proxy/goproxy"
)

var globalLogger = logger.Init(log.InfoLevel, true, "proxy",
	"2006-01-02_15:04:05_MST", "proxy", "logs/app")

func OnError(ctx *goproxy.Context, where string,
	err *goproxy.Error, opErr error) {
	globalLogger.Errorf("%s: %s [%s]", where, err, opErr)
}

func OnConnect(ctx *goproxy.Context, host string) (
	ConnectAction goproxy.ConnectAction, newHost string) {
	globalLogger.Info("CONNECT host:", host)
	return goproxy.ConnectMitm, host
}

func OnRequest(ctx *goproxy.Context, req *http.Request) (
	resp *http.Response) {
	globalLogger.Infof("REQUEST Proxy sess: %d sub: %d: method: %s url: %s",
		ctx.SessionNo, ctx.SubSessionNo, req.Method, req.URL.String())

	savedReq, err := saveReq(req)
	if err != nil {
		globalLogger.Error("failed save request", err)
		return
	}
	ctx.ReqID = savedReq
	return
}

func OnResponse(ctx *goproxy.Context, req *http.Request,
	resp *http.Response) {

	err := saveResp(ctx, resp)
	if err != nil {
		globalLogger.Error("failed save response", err)
		return
	}
}

var repo *repository.ProxyDB

func main() {
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://127.0.0.1:27017"))
	// for docker run
	//client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://172.28.0.2:27017"))
	if err != nil {
		log.Println("failed connect")
		log.Fatal(err)
	}
	defer client.Disconnect(context.TODO())

	db := client.Database("proxy")
	repo = repository.New(db)

	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, os.Interrupt, os.Kill, syscall.SIGTERM)

	certBlock, err := os.ReadFile("cert_data/cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	keyBlock, err := os.ReadFile("cert_data/key.pem")
	if err != nil {
		log.Fatal(err)
	}

	prx, err := goproxy.NewProxyTLS(certBlock, keyBlock)
	if err != nil {
		log.Fatal(err)
	}

	prx.OnError = OnError
	prx.OnConnect = OnConnect
	prx.OnRequest = OnRequest
	prx.OnResponse = OnResponse

	server := &http.Server{
		Addr:         ":8080",
		Handler:      prx,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	listenErrChan := make(chan error)
	go func() {
		listenErrChan <- server.ListenAndServe()
	}()
	log.Printf("Proxy listening HTTP %s", server.Addr)

	apiHandlers := delivery.NewHandlers(repo, prx)

	apiRouter := mux.NewRouter()
	apiRouter.HandleFunc("/api/v1/requests", apiHandlers.GetRequests).Methods(http.MethodGet)
	apiRouter.HandleFunc("/api/v1/request/{id}", apiHandlers.GetRequest).Methods(http.MethodGet)
	apiRouter.HandleFunc("/api/v1/responses", apiHandlers.GetResponses).Methods(http.MethodGet)
	apiRouter.HandleFunc("/api/v1/response", apiHandlers.GetResponse).Methods(http.MethodGet)
	apiRouter.HandleFunc("/api/v1/repeat/{id}", apiHandlers.Repeat).Methods(http.MethodGet)

	apiServer := &http.Server{
		Addr:         ":80",
		Handler:      apiRouter,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		listenErrChan <- apiServer.ListenAndServe()
	}()
	log.Printf("Api listening HTTP %s", apiServer.Addr)

mainloop:
	for {
		select {
		case <-sigChan:
			break mainloop
		case listenErr := <-listenErrChan:
			if listenErr != nil && listenErr == http.ErrServerClosed {
				break mainloop
			}
			log.Fatal(listenErr)
		}
	}

	shutdown := func(srv *http.Server, wg *sync.WaitGroup) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		srv.SetKeepAlivesEnabled(false)
		if err := srv.Shutdown(ctx); err == context.DeadlineExceeded {
			log.Printf("Force shutdown %s", srv.Addr)
		} else {
			log.Printf("Graceful shutdown %s", srv.Addr)
		}
		wg.Done()
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go shutdown(server, wg)
	wg.Add(1)
	go shutdown(apiServer, wg)
	wg.Wait()

	log.Println("Finished")
}

func saveReq(req *http.Request) (string, error) {
	path := req.URL.String()
	queryIdx := strings.Index(path, "?")
	if queryIdx != -1 {
		path = path[:queryIdx]
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		globalLogger.Error("failed read request body", err)
		return "", err
	}
	// Restore the io.ReadCloser to it's original state
	req.Body = io.NopCloser(bytes.NewBuffer(body))
	dbReq := api.Request{
		Method:    req.Method,
		Path:      path,
		GetParams: req.URL.Query(),
		Headers:   make(map[string][]string),
		Cookies:   make(map[string]string),
		Body:      string(body),
	}

	for _, cookie := range req.Cookies() {
		dbReq.Cookies[cookie.Name] = cookie.Value
	}

	for k, v := range req.Header {
		if k != "Cookie" {
			dbReq.Headers[k] = v
		}
	}

	if req.Method == http.MethodPost {
		_ = req.ParseForm()
		dbReq.PostParams = req.Form
		// Restore the io.ReadCloser to it's original state
		req.Body = io.NopCloser(bytes.NewBuffer(body))
	}

	savedReq, err := repo.AddReq(dbReq)
	if err != nil {
		globalLogger.Error("failed save request", err)
		return "", err
	}

	return savedReq, nil
}

func saveResp(ctx *goproxy.Context, resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		globalLogger.Error("failed read response body", err)
		return err
	}
	// Restore the io.ReadCloser to it's original state
	resp.Body = io.NopCloser(bytes.NewBuffer(body))
	var resBody interface{}

	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		globalLogger.Infof("ENC %s", enc)

		switch enc {
		case "gzip":
			r, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				globalLogger.Error("cant decode gzip:", err)
				return err
			}
			body, _ = io.ReadAll(r)
		case "br":
			r := brotli.NewReader(bytes.NewReader(body))
			body, _ = io.ReadAll(r)
		default:
			globalLogger.Error("cant decode body enc:", enc)
			return err
		}
	}

	b := utf8.Valid(body)
	if b {
		resBody = string(body)
	} else {
		resBody = body
	}

	globalLogger.Infof("RESPONSE %s", ctx.Req.Host)
	dbResp := api.Response{
		Code:    uint32(resp.StatusCode),
		ReqID:   ctx.ReqID,
		Message: resp.Status,
		Headers: resp.Header,
		Body:    resBody,
	}
	_, err = repo.AddResp(dbResp)
	if err != nil {
		globalLogger.Error("failed save response", err)
		return err
	}
	return nil
}
