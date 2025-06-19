package main

import (
	"binance-tss-mpc-server/tss/go-tss/keyresharing"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"binance-tss-mpc-server/tss/go-tss/keygen"
	"binance-tss-mpc-server/tss/go-tss/keysign"
	"binance-tss-mpc-server/tss/go-tss/tss"
)

// TssHttpServer provide http endpoint for tss server
type TssHttpServer struct {
	logger    zerolog.Logger
	tssServer tss.Server
	s         *http.Server
}

// NewTssHttpServer should only listen to the loopback
func NewTssHttpServer(tssAddr string, t tss.Server) *TssHttpServer {
	hs := &TssHttpServer{
		logger:    log.With().Str("module", "http").Logger(),
		tssServer: t,
	}
	s := &http.Server{
		Addr:    tssAddr,
		Handler: hs.tssNewHandler(),
	}
	hs.s = s
	return hs
}

// NewHandler registers the API routes and returns a new HTTP handler
func (t *TssHttpServer) tssNewHandler() http.Handler {
	router := mux.NewRouter()
	router.Handle("/keygen", http.HandlerFunc(t.keygenHandler)).Methods(http.MethodPost)
	router.Handle("/keyresharing", http.HandlerFunc(t.keyResharingHandler)).Methods(http.MethodPost)
	router.Handle("/keysign", http.HandlerFunc(t.keySignHandler)).Methods(http.MethodPost)
	router.Handle("/ping", http.HandlerFunc(t.pingHandler)).Methods(http.MethodGet)
	router.Handle("/p2pid", http.HandlerFunc(t.getP2pIDHandler)).Methods(http.MethodGet)
	router.Handle("/nodekey", http.HandlerFunc(t.nodeKeyHandler)).Methods(http.MethodGet)
	router.Handle("/metrics", promhttp.Handler())
	router.Use(logMiddleware())
	return router
}

func (t *TssHttpServer) keygenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer func() {
		if err := r.Body.Close(); nil != err {
			t.logger.Error().Err(err).Msg("fail to close request body")
		}
	}()
	t.logger.Info().Msg("receive key gen request")
	decoder := json.NewDecoder(r.Body)
	var keygenReq keygen.Request
	if err := decoder.Decode(&keygenReq); nil != err {
		t.logger.Error().Err(err).Msg("fail to decode keygen request")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	resp, err := t.tssServer.Keygen(keygenReq)
	if err != nil {
		t.logger.Error().Err(err).Msg("fail to key gen")
	}
	t.logger.Debug().Msgf("resp:%+v", resp)
	buf, err := json.Marshal(resp)
	if err != nil {
		t.logger.Error().Err(err).Msg("fail to marshal response to json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, err = w.Write(buf)
	if err != nil {
		t.logger.Error().Err(err).Msg("fail to write to response")
	}
}

func (t *TssHttpServer) keyResharingHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer func() {
		if err := r.Body.Close(); nil != err {
			t.logger.Error().Err(err).Msg("fail to close request body")
		}
	}()
	t.logger.Info().Msg("receive key resharing request")
	decoder := json.NewDecoder(r.Body)
	var keygenReq keyresharing.Request
	if err := decoder.Decode(&keygenReq); nil != err {
		t.logger.Error().Err(err).Msg("fail to decode key resharing request")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	resp, err := t.tssServer.KeyResharing(keygenReq)
	if err != nil {
		t.logger.Error().Err(err).Msg("fail to key resharing")
	}
	t.logger.Debug().Msgf("resp:%+v", resp)
	buf, err := json.Marshal(resp)
	if err != nil {
		t.logger.Error().Err(err).Msg("fail to marshal response to json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, err = w.Write(buf)
	if err != nil {
		t.logger.Error().Err(err).Msg("fail to write to response")
	}
}

func (t *TssHttpServer) keySignHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer func() {
		if err := r.Body.Close(); nil != err {
			t.logger.Error().Err(err).Msg("fail to close request body")
		}
	}()
	t.logger.Info().Msg("receive key sign request")

	var keySignReq keysign.Request
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&keySignReq); nil != err {
		t.logger.Error().Err(err).Msg("fail to decode key sign request")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	t.logger.Info().Msgf("request:%+v", keySignReq)
	signResp, err := t.tssServer.KeySign(keySignReq)
	if err != nil {
		t.logger.Error().Err(err).Msg("fail to key sign")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	jsonResult, err := json.MarshalIndent(signResp, "", "	")
	if err != nil {
		t.logger.Error().Err(err).Msg("fail to marshal response to json message")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, err = w.Write(jsonResult)
	if err != nil {
		t.logger.Error().Err(err).Msg("fail to write response")
	}
}

func (t *TssHttpServer) nodeKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer func() {
		if err := r.Body.Close(); nil != err {
			t.logger.Error().Err(err).Msg("fail to close request body")
		}
	}()
	t.logger.Info().Msg("receive node secret key request")

	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)
	priHexBytes := base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(randomBytes)))
	w.Write([]byte(priHexBytes))

	return
}

func (t *TssHttpServer) Start() error {
	if t.s == nil {
		return errors.New("invalid http server instance")
	}
	if err := t.tssServer.Start(); err != nil {
		return fmt.Errorf("fail to start tss server: %w", err)
	}
	if err := t.s.ListenAndServe(); err != nil {
		if err != http.ErrServerClosed {
			return fmt.Errorf("fail to start http server: %w", err)
		}
	}

	return nil
}

func logMiddleware() mux.MiddlewareFunc {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Debug().
				Str("route", r.URL.Path).
				Str("port", r.URL.Port()).
				Str("method", r.Method).
				Msg("HTTP request received")

			handler.ServeHTTP(w, r)
		})
	}
}

func (t *TssHttpServer) Stop() error {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := t.s.Shutdown(c)
	if err != nil {
		log.Error().Err(err).Msg("Failed to shutdown the Tss server gracefully")
	}
	t.tssServer.Stop()
	return err
}

func (t *TssHttpServer) pingHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (t *TssHttpServer) getP2pIDHandler(w http.ResponseWriter, _ *http.Request) {
	localPeerID := t.tssServer.GetLocalPeerID()
	_, err := w.Write([]byte(localPeerID))
	if err != nil {
		t.logger.Error().Err(err).Msg("fail to write to response")
	}
}
