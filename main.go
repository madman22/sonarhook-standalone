package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"crypto/tls"
)

func main() {
	start := time.Now()
	sh := NewSonarHookService()
	sh.configTLS()

	if err := sh.Start(context.Background()); err != nil {
		panic(err.Error())
	}
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-signalChan:
		if err := sh.Stop(); err != nil {
			panic(err.Error())
		}
		time.Sleep(1 * time.Second)
		fmt.Println("Runtime:", time.Since(start).String())
		break
	}
}

type SonarHook struct {
	started time.Time
	runmux  sync.RWMutex
	ctx     context.Context
	cancel  context.CancelFunc
	srv     *http.Server
	tls     *tls.Config
}

func NewSonarHookService() *SonarHook {
	return &SonarHook{}
}


// config tls parameters
func (sh *SonarHook) configTLS() {
	sh.tls = &tls.Config{
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}




func (sh *SonarHook) Start(ctx context.Context) error {
	sh.runmux.Lock()
	defer sh.runmux.Unlock()
	if !sh.started.IsZero() {
		return errors.New("Already running")
	}
	sh.ctx, sh.cancel = context.WithCancel(ctx)
	sh.started = time.Now()

	ip := ""
	port := "443"

	sh.srv = &http.Server{
		Addr:           ip + ":" + port,
		TLSConfig:		sh.tls,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	sh.srv.Handler = http.HandlerFunc(sh.ServeHTTP)

	go func() {
		if err := sh.srv.ListenAndServeTLS("./webhook.crt","./webhook.key"); err != nil {
			fmt.Println(err.Error())
		}
	}()

	go func() {
		select {

		case <-sh.ctx.Done():
			sh.runmux.Lock()
			sh.started = time.Time{}
			sh.runmux.Unlock()
			if err := sh.srv.Shutdown(context.Background()); err != nil {
				fmt.Println(err.Error())
			}
		}
	}()
	return nil
}

func (sh *SonarHook) Stop() error {
	sh.runmux.RLock()
	if sh.started.IsZero() {
		sh.runmux.RUnlock()
		return errors.New("Not running")
	} else {
		sh.runmux.RUnlock()
	}
	sh.cancel()
	return nil
}

type SonarEvent struct {
	Event     string                 `json:"event"`
	ID        int                    `json:"object_id"`
	Data      map[string]interface{} `json:"metadata"`
	Timestamp string                 `json:"entered_at"`
}

func (sh *SonarHook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.WriteHeader(http.StatusOK)
		return
	case "POST":
		sh.servePOST(w, r)
		return
	default:
		// checking enable and jamming save first does a webhook check from the sonar instance
		//the little code snippet below greenlights it.
		if (r.Host == "instancename.sonar.software") && (r.RequestURI == "/") {
			fmt.Printf("You're Mr Lebowski, I'm the dude..\n")
			w.WriteHeader(http.StatusOK)
		} else {
			http.Error(w, "Bad Method", http.StatusBadRequest)
		}
		return
	}
}

func (sh *SonarHook) servePOST(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if r.Method != "POST" {
		http.Error(w, "NOT POST!", http.StatusBadRequest)
		return
	}
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var se SonarEvent
	if err := json.Unmarshal(data, &se); err != nil {
		fmt.Println("Cannot parse data", err.Error(), string(data))
		http.Error(w, "Cannot parse data!", http.StatusBadRequest)
		return
	} else {
		fmt.Println("Parsed SonarEvent:", se, r.URL.RequestURI(), string(data), r.Header, r.Form)
	}
	w.WriteHeader(http.StatusOK)
	go sh.parseEvent(se)
}

func (sh *SonarHook) parseEvent(se SonarEvent) {
	switch se.Event {
	case "webhooktest.updated":
		fmt.Println("Received WebHook Test Event:", se)
	default:
		fmt.Println("Event not implemented", se)
	}
}

