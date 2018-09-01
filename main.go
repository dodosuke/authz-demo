package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dodosuke/authz-demo/internal/utils"
	"github.com/rs/xid"
)

func index(w http.ResponseWriter, r *http.Request, a *env) *response {
	a.executeTemplate(w, "index.html", &a.service)
	return nil
}

func authorize(w http.ResponseWriter, r *http.Request, a *env) *response {
	clientID := r.FormValue("client_id")

	if clientID == "" {
		return &response{
			content: &errorResponse{
				Error:            "invalid_request",
				ErrorDescription: "no client_id",
				ErrorURI:         "",
			},
			code: http.StatusBadRequest,
		}
	}

	c, er := a.service.getClient(clientID)
	if er != nil {
		return &response{
			content: er,
			code:    http.StatusBadRequest,
		}
	}

	redirectURI := r.FormValue("redirect_uri")
	if i := utils.Contains(c.RedirectURIs, redirectURI); i == -1 {
		return &response{
			content: &errorResponse{
				Error:            "invalid_request",
				ErrorDescription: "redirect_uri does not exist in the request or redirect_uri in the request does not match to that of registered",
				ErrorURI:         "",
			},
			code: http.StatusBadRequest,
		}
	}

	// Get scopes from client information
	cscope := []string{}
	if c.Scope != "" {
		cscope = strings.Split(c.Scope, " ")
	}

	// Get scopes from the request
	rscope := []string{}
	if key := r.FormValue("scope"); key != "" {
		rscope = strings.Split(r.FormValue("scope"), " ")
	}

	// Compare scopes between the registered client information and the request
	if len(utils.Diff(rscope, cscope)) > 0 {
		return &response{
			content: &errorResponse{
				Error:            "invalid_scope",
				ErrorDescription: "The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner.",
				ErrorURI:         "",
			},
			code: http.StatusBadRequest,
		}
	}

	// Store the query temporarily
	reqid := utils.RandomString(8)
	query := r.URL.Query()
	a.requests[reqid] = query

	// Prepare data for parsing the template
	data := struct {
		ReqID  string
		Client Client
		Scope  []string
	}{reqid, *c, rscope}

	a.executeTemplate(w, "approve.html", data)

	return nil
}

func getScopeFromForm(r *http.Request) []string {
	s := []string{}
	for k := range r.PostForm {
		if i := strings.Index(k, "scope_"); i > -1 {
			s = append(s, k[6:])
		}
	}
	return s
}

func approve(w http.ResponseWriter, r *http.Request, a *env) *response {
	// Check its method
	if r.Method != "POST" {
		a.executeTemplate(w, "error.html", "Only POST are allowed")
		return nil
	}

	// Get a value for reqid from a request body
	reqid := r.PostFormValue("reqid")
	query, ok := a.requests[reqid]

	if !ok {
		a.executeTemplate(w, "error.html", "No matching authorization request")
		return nil
	}

	// Delete the query from the requests cache
	delete(a.requests, reqid)

	if r.PostFormValue("approve") == "" {
		a.executeTemplate(w, "error.html", "Access Denied")
		return nil
	}

	//responseType := query.Get("response_type")

	// This must be switch statement... Need to update
	if query.Get("response_type") != "code" {
		a.executeTemplate(w, "error.html", "unspported_response_type")
		return nil
	}

	// Get client information
	clientID := query.Get("client_id")
	client, er := a.service.getClient(clientID)
	if er != nil {
		return &response{
			content: er,
			code:    http.StatusBadRequest,
		}
	}

	// Compare scopes between a client and request
	rscope := getScopeFromForm(r)
	cscope := strings.Split(client.Scope, " ")
	if len(utils.Diff(rscope, cscope)) > 0 {
		a.executeTemplate(w, "error.html", "invalid_scope")
		return nil
	}

	// Generate a random string for later use
	code := utils.RandomString(8)

	state, ok := query["state"]
	if !ok {

	}

	// Create queries for authorization response
	ar := url.Values{
		"code":  {code},
		"state": state,
	}

	// Create a redirect uri using a given redirect_uri and queries
	u := utils.BuildURL(query.Get("redirect_uri"), ar, "")
	if u == nil {
		a.executeTemplate(w, "error.html", "Failed to create redirect uri")
		return nil
	}

	// Redirect to a client's reidrect uri
	http.Redirect(w, r, u.String(), http.StatusFound)

	// Temporally save the query and scopes
	a.requests[code] = query
	a.scopes[code] = rscope
	return nil
}

func decodeClientCredentials(auth string) (id, sercret string) {
	// Decode with base64
	s, err := base64.RawURLEncoding.DecodeString(strings.Split(auth, " ")[1])
	if err != nil {
		return "", ""
	}
	// Split into id and secret
	credentials := strings.Split(string(s), ":")
	return credentials[0], credentials[1]
}

func verifyCodeChallenge(r *http.Request, query url.Values) *errorResponse {
	codeChallenge := query.Get("code_challenge")

	// Finish verifying when code_challenge is not used
	if codeChallenge == "" {
		return nil
	}

	var codeVerifier string

	codeChallengeMethod := query.Get("code_challenge_method")

	switch codeChallengeMethod {
	case "S256":
		converted := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		codeVerifier = base64.RawURLEncoding.EncodeToString(converted[:])
	default:
		codeVerifier = r.PostFormValue("code_verifier")
	}

	if codeChallenge != codeVerifier {
		return &errorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Code challenge did not match",
			ErrorURI:         "",
		}
	}

	return nil
}

func authorizationCodeGrant(w http.ResponseWriter, r *http.Request, a *env) *response {
	clientID, clientSecret := "", ""

	// Get client credentials from Authorization header
	if auth := r.Header.Get("authorization"); auth != "" {
		clientID, clientSecret = decodeClientCredentials(auth)
	}

	// Get client information from database
	client, er := a.service.getClient(clientID)
	if er != nil {
		return &response{
			content: er,
			code:    http.StatusBadRequest,
		}
	}

	//
	if client.ClientSecret != clientSecret {
		return &response{
			content: &errorResponse{
				Error:            "Invalid client",
				ErrorDescription: "Mismatched client secret",
				ErrorURI:         "",
			},
			code: http.StatusUnauthorized,
		}
	}

	code := r.PostFormValue("code")

	query := a.requests[code]
	delete(a.requests, code)

	scope := a.scopes[code]
	delete(a.scopes, code)

	// Return error if there is no value for code in a request body
	if query == nil || scope == nil {
		// revoke all tokens issued based on the authorization code
		fmt.Println("revoked tokens")
	}

	if clientID != query.Get("client_id") {
		return &response{
			content: &errorResponse{
				Error:            "invalid_grant",
				ErrorDescription: "The provided authorization grant was issued to another client.",
				ErrorURI:         "",
			},
			code: http.StatusUnauthorized,
		}
	}

	// Chech the challenged code if it is exist
	er = verifyCodeChallenge(r, query)
	if er != nil {
		return &response{
			content: er,
			code:    http.StatusBadRequest,
		}
	}

	return &response{
		content: &tokenResponse{
			AccessToken:  xid.New().String(),
			RefreshToken: xid.New().String(),
			Scope:        strings.Join(scope, " "),
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		},
		code: http.StatusOK,
	}
}

func token(w http.ResponseWriter, r *http.Request, a *env) *response {
	// Get a grant_type from the request
	grantType := r.PostFormValue("grant_type")

	var res *response

	switch grantType {
	case "authorization_code":
		res = authorizationCodeGrant(w, r, a)
	default:
		res = &response{
			content: &errorResponse{
				Error:            "unsupported_grant_type",
				ErrorDescription: "Unknown grant type: " + grantType,
				ErrorURI:         "",
			},
			code: http.StatusUnauthorized,
		}
	}

	return res
}

func introspect(w http.ResponseWriter, r *http.Request, a *env) *response {
	return nil
}

func revoke(w http.ResponseWriter, r *http.Request, a *env) *response {
	return nil
}

func register(w http.ResponseWriter, r *http.Request, a *env) *response {
	if r.Method != "POST" {
		return &response{
			content: &errorResponse{
				Error:            "invalid_request",
				ErrorDescription: "Only POST is allowed.",
				ErrorURI:         "",
			},
			code: http.StatusBadRequest,
		}
	}

	// Parse JSON in the request body
	var client clientRegistrationResponse
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		fmt.Println(err)
	}

	if client.TokenEndpointAuthMethod == "" {
		client.TokenEndpointAuthMethod = "client_secret_basic"
	} else if utils.Contains([]string{"client_secret_basic", "client_secret_post", "none"}, client.TokenEndpointAuthMethod) == -1 {
		return &response{
			content: &errorResponse{
				Error:            "invalid_client_metadata",
				ErrorDescription: "unsupported authentication method at token endpoint",
				ErrorURI:         "",
			},
			code: http.StatusBadRequest,
		}
	}

	if client.ResponseTypes == nil {
		client.ResponseTypes = []string{"code"}
	} else if len(utils.Diff(client.ResponseTypes, []string{"code"})) > 0 {
		return &response{
			content: &errorResponse{
				Error:            "invalid_client_metadata",
				ErrorDescription: "unsupported response_type",
				ErrorURI:         "",
			},
			code: http.StatusBadRequest,
		}
	}

	if client.GrantTypes == nil {
		client.GrantTypes = []string{"authorization_code"}
	} else if len(utils.Diff(client.GrantTypes, []string{"authorization_code"})) > 0 {
		return &response{
			content: &errorResponse{
				Error:            "invalid_client_metadata",
				ErrorDescription: "Unsupported grant_type",
				ErrorURI:         "",
			},
			code: http.StatusBadRequest,
		}
	}

	if client.RedirectURIs == nil {
		return &response{
			content: &errorResponse{
				Error:            "invalid_client_metadata",
				ErrorDescription: "no redirect_uris",
				ErrorURI:         "",
			},
			code: http.StatusBadRequest,
		}
	}

	client.ClientID = xid.New().String()
	if client.TokenEndpointAuthMethod != "none" {
		client.ClientSecret = xid.New().String()
	}

	client.IssuedAt = time.Now().Unix()

	// Add Client
	var c Client
	c.ClientID = client.ClientID
	c.ClientSecret = client.ClientSecret
	c.RedirectURIs = client.RedirectURIs
	c.Scope = client.Scope
	a.service.Clients = append(a.service.Clients, c)

	// Return the response to the client app
	return &response{
		content: &client,
		code:    http.StatusOK,
	}
}

func main() {
	router := newEnv()

	router.add("/", index)
	router.add("/authorize", authorize)
	router.add("/approve", approve)
	router.add("/token", token)
	router.add("/introspect", introspect)
	router.add("/revoke", revoke)
	router.add("/register", register)

	fmt.Println("OAuth Authorization Server is listening at http://127.0.0.1:9001")
	log.Fatalln(http.ListenAndServe(":9001", nil))
}
