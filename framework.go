package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
)

// Client contains infomation of a client
type Client struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	Scope        string
}

// Service contains AuthServer and its Clients
type Service struct {
	Clients []Client
}

func (s Service) getClient(clientID string) (*Client, *errorResponse) {
	for _, v := range s.Clients {
		if v.ClientID == clientID {
			return &v, nil
		}
	}

	return nil, &errorResponse{
		Error:            "invalid_client",
		ErrorDescription: "Unknown client: client_id = " + clientID,
		ErrorURI:         "",
	}
}

type tokenResponse struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

type clientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	IssuedAt                int64    `json:"iat"`
	ExpiresAt               int64    `json:"exp"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientURI               string   `json:"client_uri"`
	GrantTypes              []string `json:"grant_type"`
	ResponseTypes           []string `json:"response_type"`
	Scope                   string   `json:"scope"`
}

type header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

type payload struct {
	Issuer           string `json:"iss"`
	Subject          string `json:"sub"`
	Audience         string `json:"aud"`
	ExpiresAt        int64  `json:"exp"`
	IssuedAt         int64  `json:"iat"`
	UniqueIdentifier string `json:"jti"`
}

type responseContent interface {
	jsonify() ([]byte, error)
}

func (tr *tokenResponse) jsonify() ([]byte, error) {
	return json.Marshal(tr)
}

func (er *errorResponse) jsonify() ([]byte, error) {
	return json.Marshal(er)
}

func (cr *clientRegistrationResponse) jsonify() ([]byte, error) {
	return json.Marshal(cr)
}

type response struct {
	content responseContent
	code    int
}

// env contains global parameters for a web application
type env struct {
	template *template.Template
	service  Service
	requests map[string]url.Values
	scopes   map[string][]string
}

// handlerFunc is a function that can be registed to a router
type appHandlerFunc func(http.ResponseWriter, *http.Request, *env) *response

// appHandler is a struct that contains appContext and an original appHandler
type appHandler struct {
	env         *env
	handlerFunc appHandlerFunc
}

// newEnv is a function to initiate this framework
func newEnv() *env {
	return &env{
		template: template.Must(template.ParseGlob("templates/*")),
		service: Service{
			Clients: []Client{
				Client{
					ClientID:     "oauth-client-1",
					ClientSecret: "oauth-client-secret-1",
					RedirectURIs: []string{"http://localhost:9000/callback"},
					Scope:        "foo bar",
				},
			},
		},
		requests: map[string]url.Values{},
		scopes:   map[string][]string{},
	}
}

// executeTemplate is for rendering html with given data
func (e *env) executeTemplate(w http.ResponseWriter, name string, data interface{}) {
	if err := e.template.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		log.Println(err)
	}
}

// add is a shortcut for http.Handle
func (e *env) add(p string, h appHandlerFunc) {
	http.Handle(p, &appHandler{env: e, handlerFunc: h})
}

// ServeHTTP makes the handler implement the http.Handler interface
func (h *appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//Response a JSON if catch an error
	if res := h.handlerFunc(w, r, h.env); res != nil {

		// Jsonify the response. Return a error if failed to create a JSON.
		result, err := res.content.jsonify()
		if err != nil {
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			log.Println(err)
			return
		}

		// Send back JSON
		w.WriteHeader(res.code)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Write(result)
	}
}
