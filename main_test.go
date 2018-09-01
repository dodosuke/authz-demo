package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func getResponse(method string, url string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, url, nil)

	rr := httptest.NewRecorder()

	router := newEnv()
	handler := appHandler{env: router, handlerFunc: authorize}
	handler.ServeHTTP(rr, req)

	return rr
}

func TestAuthorize(t *testing.T) {
	cases := []struct {
		method string
		url    string
		want   string
	}{
		{
			method: "GET",
			url:    "/authorize",
			want:   "invalid_request",
		},
		{
			method: "GET",
			url:    "/authorize?client_id=oauth-client-2",
			want:   "invalid_client",
		},
		{
			method: "GET",
			url:    "/authorize?client_id=oauth-client-1&redirect_uri=http://localhost:9000/callback&scope=hoo",
			want:   "invalid_scope",
		},
	}

	for _, c := range cases {
		rr := getResponse(c.method, c.url)

		b, err := ioutil.ReadAll(rr.Body)
		if err != nil {
			t.Errorf("failed to read response body")
		}

		var res errorResponse
		err = json.Unmarshal(b, &res)
		if err != nil {
			t.Errorf("failed to parse JSON: %v", c.url)
		}

		if res.Error != c.want {
			t.Errorf("handler returned wrong response: got %v want %v", res, c.want)
		}
	}
}
