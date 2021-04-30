// https://solid.github.io/authentication-panel/solid-oidc/
// https://tools.ietf.org/html/draft-fett-oauth-dpop-04
// https://openid.net/specs/openid-connect-registration-1_0.html
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"html/template"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/sessions"
)

const provider = "https://inrupt.net"
const selfURL = "http://localhost:3000"

var b64 = base64.URLEncoding.WithPadding(base64.NoPadding)

func main() {
	conf, err := findConfiguration(provider)
	if err != nil {
		log.Fatal(err)
	}

	client, err := registerClient(conf.RegistrationEndpoint)
	if err != nil {
		log.Fatal(err)
	}

	store := sessions.NewCookieStore(randomBytes(32))

	codeVerifier, codeChallenge := generateVerifier()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		if idToken, ok := readIdToken(session); ok {
			if read := r.FormValue("read"); read != "" {
				req, _ := http.NewRequest(http.MethodGet, read, nil)
				req.Header.Add("Authorization", "Bearer "+signJwt(makePopToken(idToken), privateKey))

				resp, _ := http.DefaultClient.Do(req)
				defer resp.Body.Close()

				data, _ := ioutil.ReadAll(resp.Body)

				tmpl.Execute(w, tmplData{LoggedIn: true, Read: read, Content: string(data)})
			} else {
				tmpl.Execute(w, tmplData{LoggedIn: true})
			}
		} else {
			tmpl.Execute(w, tmplData{})
		}
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		form := url.Values{
			"response_type":         {"code"},
			"redirect_uri":          {selfURL + "/cb"},
			"scope":                 {"openid profile offline_access"},
			"client_id":             {client.ClientID},
			"code_challenge_method": {"S256"},
			"code_challenge":        {codeChallenge},
		}

		redirectURL := conf.AuthorizationEndpoint + "?" + form.Encode()

		http.Redirect(w, r, redirectURL, http.StatusFound)
	})

	http.HandleFunc("/cb", func(w http.ResponseWriter, r *http.Request) {
		code := r.FormValue("code")

		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code_verifier": {codeVerifier},
			"code":          {code},
			"redirect_uri":  {selfURL + "/cb"},
			"client_id":     {client.ClientID},
		}

		req, _ := http.NewRequest(http.MethodPost, conf.TokenEndpoint, strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		resp, _ := http.DefaultClient.Do(req)
		defer resp.Body.Close()

		var v struct {
			AccessToken  string `json:"access_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    int    `json:"expires_in"`
			RefreshToken string `json:"refresh_token"`
			IdToken      string `json:"id_token"`
		}
		json.NewDecoder(resp.Body).Decode(&v)

		session, _ := store.Get(r, "session")
		session.Values["idToken"] = v.IdToken
		session.Save(r, w)

		http.Redirect(w, r, "/?read="+url.QueryEscape(idTokenSub(v.IdToken)), http.StatusFound)
	})

	log.Println("Running at :3000")
	http.ListenAndServe(":3000", nil)
}

type OpenidConfiguration struct {
	Issuer                string `json:"issuer"`
	JwksURI               string `json:"jwks_uri"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
}

func findConfiguration(host string) (*OpenidConfiguration, error) {
	resp, err := http.Get(host + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var v OpenidConfiguration
	err = json.NewDecoder(resp.Body).Decode(&v)
	return &v, err
}

func generateVerifier() (verifier, challenge string) {
	verifier = b64.EncodeToString(randomBytes(15))

	data := sha256.Sum256([]byte(verifier))
	challenge = b64.EncodeToString(data[:])

	return verifier, challenge
}

func randomBytes(n int) []byte {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	return bytes
}

type Client struct {
	ClientID string `json:"client_id"`
}

func registerClient(uri string) (*Client, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(struct {
		GrantTypes               []string `json:"grant_types"`
		RedirectURIs             []string `json:"redirect_uris"`
		ResponseTypes            []string `json:"response_types"`
		ApplicationType          string   `json:"application_type"`
		SubjectType              string   `json:"subject_type"`
		TokenEndpointAuthMethod  string   `json:"token_endpoint_auth_method"`
		IdTokenSignedResponseAlg string   `json"id_token_signed_response_alg"`
	}{
		GrantTypes:               []string{"authorization_code"},
		RedirectURIs:             []string{selfURL + "/cb"},
		ResponseTypes:            []string{"code"},
		ApplicationType:          "web",
		SubjectType:              "pairwise",
		TokenEndpointAuthMethod:  "client_secret_basic",
		IdTokenSignedResponseAlg: "RS256",
	}); err != nil {
		return nil, err
	}

	resp, err := http.Post(uri, "application/json", &buf)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var v Client
	err = json.NewDecoder(resp.Body).Decode(&v)
	return &v, err
}

type Key struct {
	Alg    string   `json:"alg"`
	E      string   `json:"e"`
	Ext    bool     `json:"ext"`
	KeyOps []string `json:"key_ops"`
	Kty    string   `json:"kty"`
	N      string   `json:"n"`
}

func signDpop(data string, privateKey *rsa.PrivateKey) string {
	header, _ := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Jwk Key    `json:"jwk"`
	}{
		Alg: "RS256",
		Typ: "dpop+jwt",
		Jwk: Key{
			Alg:    "RS256",
			E:      base64Int(privateKey.E),
			Ext:    true,
			KeyOps: []string{"verify"},
			Kty:    "RSA",
			N:      base64BigInt(*privateKey.N),
		},
	})

	digest := sha256.Sum256([]byte(data))
	sig, err := privateKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		panic(err)
	}

	return b64.EncodeToString(header) + "." +
		b64.EncodeToString([]byte(data)) + "." +
		b64.EncodeToString(sig)
}

func signJwt(data string, privateKey *rsa.PrivateKey) string {
	header := `{"alg":"RS256"}`

	digest := sha256.Sum256([]byte(data))
	sig, err := privateKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		panic(err)
	}

	return b64.EncodeToString([]byte(header)) + "." +
		b64.EncodeToString([]byte(data)) + "." +
		b64.EncodeToString(sig)
}

type popToken struct {
	Iss       string `json:"iss"`
	Aud       string `json:"aud"`
	Exp       int64  `json:"exp"`
	Iat       int64  `json:"iat"`
	IdToken   string `json:"id_token"`
	TokenType string `json:"pop"`
}

func makePopToken(idToken string) string {
	token, _ := json.Marshal(popToken{
		Iss:       selfURL,
		Exp:       time.Now().Add(time.Hour).Unix(),
		Iat:       time.Now().Unix(),
		IdToken:   idToken,
		TokenType: "pop",
	})

	return string(token)
}

func base64Int(n int) string {
	buf := make([]byte, binary.MaxVarintLen64)
	l := binary.PutVarint(buf, int64(n))

	return b64.EncodeToString(buf[:l])
}

func base64BigInt(n big.Int) string {
	return b64.EncodeToString(n.Bytes())
}

func readIdToken(session *sessions.Session) (string, bool) {
	v, ok := session.Values["idToken"]
	if !ok {
		return "", false
	}

	s, ok := v.(string)
	return s, ok
}

func idTokenSub(idToken string) string {
	parts := strings.Split(idToken, ".")
	data, _ := b64.DecodeString(parts[1])

	var v struct {
		Sub string `json:"sub"`
	}
	json.Unmarshal(data, &v)

	return v.Sub
}

type tmplData struct {
	LoggedIn bool
	Read     string
	Content  string
}

var tmpl = template.Must(template.New("").Parse(`<!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="utf-8" />
		<title>pod-reader</title>
	</head>
	<body>
		<header>
			<h1>pod-reader</h1>
			{{ if .LoggedIn }}<a href="/logout">Logout{{ else }}<a href="/login">Login{{ end }}</a>
		</header>

		{{ if .LoggedIn }}
		<main>
			<form action="/" method="get">
				<label for="read">URL to read:</label>
				<input type="url" id="read" name="read" value="{{ .Read }}" />

				<button type="submit">Go</button>
			</form>

			<hr />

			<pre>{{ .Content }}</pre>
		</main>
		{{ end }}
	</body>
</html>`))
