package httpwrapper

import (
	"context"
	"encoding/json"
	"github.com/go-jose/go-jose/v3"
	x_oidc "github.com/xslasd/x-oidc"
	"github.com/xslasd/x-oidc/log"
	"github.com/xslasd/x-oidc/model"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

type HttpWrapper struct {
	handler *http.ServeMux
	addr    string
	logger  log.Logger
}

func NewHttpHandler(addr string) *HttpWrapper {
	return &HttpWrapper{handler: http.DefaultServeMux, addr: addr}
}
func (h *HttpWrapper) SetLogger(logger log.Logger) {
	h.logger = logger
}

func (h *HttpWrapper) ListenAndServe() error {
	h.login()
	var err error
	srv := &http.Server{
		Addr:    h.addr,
		Handler: h.handler,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	done := make(chan error)
	go func() {
		h.logger.Infof("Starting server on %s", srv.Addr)
		err = srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			done <- err
		}
	}()
	select {
	case <-ctx.Done():
		h.logger.Info("Shutting down server...")
		stop()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err = srv.Shutdown(ctx); err != nil {
			return err
		}
		return err
	case err = <-done:
		h.logger.Info("Starting server err ")
		return err
	}
}

func (h *HttpWrapper) DiscoveryJWKs(jwksEndpoint string, handler func() (*jose.JSONWebKeySet, error)) {
	h.handler.HandleFunc(jwksEndpoint, func(w http.ResponseWriter, r *http.Request) {
		data, err := handler()
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			return
		}
		w.WriteHeader(200)
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(data)
	})
}

func (h *HttpWrapper) DiscoveryConfig(discoveryEndpoint string, handler func(req *x_oidc.DiscoveryConfigReq) *model.DiscoveryConfiguration) {
	h.handler.HandleFunc(discoveryEndpoint, func(w http.ResponseWriter, r *http.Request) {
		data := handler(&x_oidc.DiscoveryConfigReq{
			RegistrationEndpoint:         "",
			OPPolicyEndpoint:             "",
			OPTermsOfServiceEndpoint:     "",
			ServiceDocumentationEndpoint: "",
		})
		w.WriteHeader(200)
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(data)
	})
}

func (h *HttpWrapper) Authorize(authorizationEndpoint string, handler func(ctx context.Context, req *x_oidc.AuthRequestReq) (string, error)) {
	h.handler.HandleFunc(authorizationEndpoint, func(w http.ResponseWriter, r *http.Request) {
		var authRequestReq x_oidc.AuthRequestReq
		if r.Method == "GET" {
			r.ParseForm()
			max_age := r.Form.Get("max_age")
			var maxAge int64
			var err error
			if max_age != "" {
				maxAge, err = strconv.ParseInt(r.Form.Get("max_age"), 10, 64)
				if err != nil {
					w.WriteHeader(500)
					w.Write([]byte(err.Error()))
					return
				}
			}
			authRequestReq = x_oidc.AuthRequestReq{
				Scopes:              r.Form.Get("scope"),
				ResponseType:        r.Form.Get("response_type"),
				ClientID:            r.Form.Get("client_id"),
				RedirectURI:         r.Form.Get("redirect_uri"),
				State:               r.Form.Get("state"),
				Nonce:               r.Form.Get("nonce"),
				ResponseMode:        r.Form.Get("response_mode"),
				Display:             r.Form.Get("display"),
				Prompt:              r.Form.Get("prompt"),
				MaxAge:              maxAge,
				UILocales:           r.Form.Get("ui_locales"),
				LoginHint:           r.Form.Get("login_hint"),
				ACRValues:           r.Form.Get("acr_values"),
				CodeChallenge:       r.Form.Get("code_challenge"),
				CodeChallengeMethod: r.Form.Get("code_challenge_method"),
				RequestParam:        r.Form.Get("request"),
				IDTokenHint:         r.Form.Get("id_token_hint"),
			}
		} else {
			return
		}
		loginUrl, err := handler(r.Context(), &authRequestReq)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			return
		}
		http.Redirect(w, r, loginUrl, http.StatusFound)
	})
}

func (h *HttpWrapper) EndSession(endSessionEndpoint string, handler func(ctx context.Context, req *x_oidc.EndSessionReq) (string, error)) {
	h.handler.HandleFunc(endSessionEndpoint, func(w http.ResponseWriter, r *http.Request) {
		var endSessionReq x_oidc.EndSessionReq
		r.ParseForm()
		if r.Method == "GET" {
			endSessionReq = x_oidc.EndSessionReq{
				IdTokenHint:           r.PostForm.Get("id_token_hint"),
				ClientID:              r.PostForm.Get("client_id"),
				PostLogoutRedirectURI: r.PostForm.Get("post_logout_redirect_uri"),
				State:                 r.PostForm.Get("state"),
				UILocales:             r.PostForm.Get("ui_locales"),
			}
		} else {
			endSessionReq = x_oidc.EndSessionReq{
				IdTokenHint:           r.PostForm.Get("id_token_hint"),
				ClientID:              r.PostForm.Get("client_id"),
				PostLogoutRedirectURI: r.PostForm.Get("post_logout_redirect_uri"),
				State:                 r.PostForm.Get("state"),
				UILocales:             r.PostForm.Get("ui_locales"),
			}
		}

		endSessionUrl, err := handler(r.Context(), &endSessionReq)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			return
		}
		http.Redirect(w, r, endSessionUrl, http.StatusFound)
	})
}

func (h *HttpWrapper) Introspect(introspectionEndpoint string, handler func(ctx context.Context, req *x_oidc.IntrospectionReq, r *http.Request) (*model.IntrospectionModel, error)) {
	h.handler.HandleFunc(introspectionEndpoint, func(w http.ResponseWriter, r *http.Request) {
		var introspectionReq x_oidc.IntrospectionReq
		r.ParseForm()
		if r.Method == "GET" {
			introspectionReq = x_oidc.IntrospectionReq{
				OAuthClientReq: &x_oidc.OAuthClientReq{
					ClientID:            r.Form.Get("client_id"),
					ClientSecret:        r.Form.Get("client_secret"),
					ClientAssertion:     r.Form.Get("client_assertion"),
					ClientAssertionType: r.Form.Get("client_assertion_type"),
				},
				Token:         r.Form.Get("token"),
				TokenTypeHint: r.Form.Get("token_type_hint"),
			}
		} else {
			introspectionReq = x_oidc.IntrospectionReq{
				OAuthClientReq: &x_oidc.OAuthClientReq{
					ClientID:            r.PostForm.Get("client_id"),
					ClientSecret:        r.PostForm.Get("client_secret"),
					ClientAssertion:     r.PostForm.Get("client_assertion"),
					ClientAssertionType: r.PostForm.Get("client_assertion_type"),
				},
				Token:         r.PostForm.Get("token"),
				TokenTypeHint: r.PostForm.Get("token_type_hint"),
			}
		}
		data, err := handler(r.Context(), &introspectionReq, r)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			return
		}
		w.WriteHeader(200)
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(data)
	})
}

func (h *HttpWrapper) RevokeToken(revocationEndpoint string, handler func(ctx context.Context, req *x_oidc.RevokeTokenReq, r *http.Request) error) {
	h.handler.HandleFunc(revocationEndpoint, func(w http.ResponseWriter, r *http.Request) {
		var revokeTokenReq x_oidc.RevokeTokenReq
		r.ParseForm()
		if r.Method == "GET" {
			revokeTokenReq = x_oidc.RevokeTokenReq{
				OAuthClientReq: &x_oidc.OAuthClientReq{
					ClientID:            r.Form.Get("client_id"),
					ClientSecret:        r.Form.Get("client_secret"),
					ClientAssertion:     r.Form.Get("client_assertion"),
					ClientAssertionType: r.Form.Get("client_assertion_type"),
				},
				Token:         r.Form.Get("token"),
				TokenTypeHint: r.Form.Get("token_type_hint"),
			}
		} else {
			revokeTokenReq = x_oidc.RevokeTokenReq{
				OAuthClientReq: &x_oidc.OAuthClientReq{
					ClientID:            r.PostForm.Get("client_id"),
					ClientSecret:        r.PostForm.Get("client_secret"),
					ClientAssertion:     r.PostForm.Get("client_assertion"),
					ClientAssertionType: r.PostForm.Get("client_assertion_type"),
				},
				Token:         r.PostForm.Get("token"),
				TokenTypeHint: r.PostForm.Get("token_type_hint"),
			}
		}
		err := handler(r.Context(), &revokeTokenReq, r)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			return
		}
		w.WriteHeader(200)
		w.Header().Set("content-type", "application/json")
		w.Write([]byte("ok"))
	})
}

func (h *HttpWrapper) TokenExchange(tokenExchangeEndpoint string, handler func(ctx context.Context, req *x_oidc.TokenExchangeReq, r *http.Request) (interface{}, error)) {
	h.handler.HandleFunc(tokenExchangeEndpoint, func(w http.ResponseWriter, r *http.Request) {
		var tokenExchangeReq x_oidc.TokenExchangeReq
		r.ParseForm()
		if r.Method == "GET" {
			tokenExchangeReq = x_oidc.TokenExchangeReq{
				OAuthClientReq: &x_oidc.OAuthClientReq{
					ClientID:            r.Form.Get("client_id"),
					ClientSecret:        r.Form.Get("client_secret"),
					ClientAssertion:     r.Form.Get("client_assertion"),
					ClientAssertionType: r.Form.Get("client_assertion_type"),
				},
				GrantType:    r.Form.Get("grant_type"),
				Code:         r.Form.Get("code"),
				RedirectURI:  r.Form.Get("redirect_uri"),
				CodeVerifier: r.Form.Get("code_verifier"),

				RefreshToken: r.Form.Get("refresh_token"),
				Scopes:       r.Form.Get("scope"),

				Assertion: r.Form.Get("assertion"),

				SubjectToken:       r.Form.Get("subject_token"),
				SubjectTokenType:   r.Form.Get("subject_token_type"),
				ActorToken:         r.Form.Get("actor_token"),
				ActorTokenType:     r.Form.Get("actor_token_type"),
				Resource:           r.Form.Get("resource"),
				Audience:           r.Form.Get("audience"),
				RequestedTokenType: r.Form.Get("requested_token_type"),
			}
		} else {
			tokenExchangeReq = x_oidc.TokenExchangeReq{
				OAuthClientReq: &x_oidc.OAuthClientReq{
					ClientID:            r.Form.Get("client_id"),
					ClientSecret:        r.Form.Get("client_secret"),
					ClientAssertion:     r.Form.Get("client_assertion"),
					ClientAssertionType: r.Form.Get("client_assertion_type"),
				},
				GrantType:    r.PostForm.Get("grant_type"),
				Code:         r.PostForm.Get("code"),
				RedirectURI:  r.PostForm.Get("redirect_uri"),
				CodeVerifier: r.PostForm.Get("code_verifier"),

				RefreshToken: r.PostForm.Get("refresh_token"),
				Scopes:       r.PostForm.Get("scope"),

				Assertion: r.PostForm.Get("assertion"),

				SubjectToken:       r.PostForm.Get("subject_token"),
				SubjectTokenType:   r.PostForm.Get("subject_token_type"),
				ActorToken:         r.PostForm.Get("actor_token"),
				ActorTokenType:     r.PostForm.Get("actor_token_type"),
				Resource:           r.PostForm.Get("resource"),
				Audience:           r.PostForm.Get("audience"),
				RequestedTokenType: r.PostForm.Get("requested_token_type"),
			}
		}
		data, err := handler(r.Context(), &tokenExchangeReq, r)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			return
		}
		w.WriteHeader(200)
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(data)
	})
}

func (h *HttpWrapper) Userinfo(userinfoEndpoint string, handler func(ctx context.Context, req *x_oidc.UserinfoReq, r *http.Request) (*model.UserInfo, error)) {
	h.handler.HandleFunc(userinfoEndpoint, func(w http.ResponseWriter, r *http.Request) {
		var userinfoReq x_oidc.UserinfoReq
		r.ParseForm()
		if r.Method == "GET" {
			userinfoReq = x_oidc.UserinfoReq{
				AccessToken: r.Form.Get("access_token"),
			}
		} else {
			userinfoReq = x_oidc.UserinfoReq{
				AccessToken: r.PostForm.Get("access_token"),
			}
		}
		data, err := handler(r.Context(), &userinfoReq, r)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			return
		}
		w.WriteHeader(200)
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(data)
	})
}

func (h *HttpWrapper) AuthorizeCallback(authorizeCallbackEndpoint string, handler func(ctx context.Context, req *x_oidc.AuthorizeCallbackReq) (callbackUrl string, err error)) {
	h.handler.HandleFunc(authorizeCallbackEndpoint, func(w http.ResponseWriter, r *http.Request) {

		var authorizeCallbackReq x_oidc.AuthorizeCallbackReq
		r.ParseForm()
		if r.Method == "POST" {
			username := r.FormValue("username")
			password := r.FormValue("password")
			id := r.FormValue("id")
			h.logger.Infof("authorizeCallback Method %s  %s %s", r.Method, username, id)
			if password == "test" {
				authorizeCallbackReq = x_oidc.AuthorizeCallbackReq{
					RequestID: id,
					UserID:    username,
				}
			}
		} else {
			w.WriteHeader(404)
			w.Write([]byte("Unsupported Method"))
			return
		}
		callbackUrl, err := handler(r.Context(), &authorizeCallbackReq)

		if err != nil {
			h.logger.Errorf("authorizeCallback err %v", err)
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			return
		}
		http.Redirect(w, r, callbackUrl, http.StatusFound)
	})
}
