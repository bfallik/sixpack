package beertasting

import (
	"appengine"
	"appengine/datastore"
	"appengine/urlfetch"
	"appengine/user"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

func init() {
	http.HandleFunc("/", handler)
	http.HandleFunc("/search", searchHandler)
	http.HandleFunc("/feed", feedHandler)
	http.HandleFunc("/admin/untappd/client_id", clientIdHandler)
	http.HandleFunc("/admin/untappd/client_secret", clientSecretHandler)
	http.HandleFunc("/admin/whitelist", whitelistHandler)
	http.HandleFunc("/oauth/untappd", oauthUntappdHandler)
}

const (
	endpoint = "http://api.untappd.com/v4"
)

type ClientId struct {
	Value string
}

type ClientSecret struct {
	Value string
}

type Whitelist struct {
	Value string
}

func clientIdKey(c appengine.Context) *datastore.Key {
	return datastore.NewKey(c, "ClientId", "default", 0, nil)
}

func clientSecretKey(c appengine.Context) *datastore.Key {
	return datastore.NewKey(c, "ClientSecret", "default", 0, nil)
}

func whitelistKey(c appengine.Context) *datastore.Key {
	return datastore.NewKey(c, "Whitelist", "default", 0, nil)
}

func getClientId(c appengine.Context) (ClientId, error) {
	var clientId ClientId
	err := datastore.Get(c, clientIdKey(c), &clientId)
	return clientId, err
}

func getClientSecret(c appengine.Context) (ClientSecret, error) {
	var clientSecret ClientSecret
	err := datastore.Get(c, clientSecretKey(c), &clientSecret)
	return clientSecret, err
}

func getWhitelist(c appengine.Context) (Whitelist, error) {
	var whitelist Whitelist
	err := datastore.Get(c, whitelistKey(c), &whitelist)
	return whitelist, err
}

func oauthCallback(c appengine.Context, svc string) string {
	var u url.URL
	u.Scheme = "http"
	u.Host = appengine.DefaultVersionHostname(c)
	u.Path = fmt.Sprintf("oauth/%s", svc)
	return u.String()
}

func userLoggedIn(c appengine.Context, curUrl *url.URL, w http.ResponseWriter) (*user.User, bool) {
	u := user.Current(c)
	if u != nil {
		return u, true
	}
	url, err := user.LoginURL(c, curUrl.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, false
	}
	w.Header().Set("Location", url)
	w.WriteHeader(http.StatusFound)
	return nil, false
}

func handler(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	user, ok := userLoggedIn(c, r.URL, w)
	if !ok {
		return
	}
	fmt.Fprintf(w, "Welcome, %s", user)
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	user, ok := userLoggedIn(c, r.URL, w)
	if !ok {
		return
	}
	var err error
	var whitelist Whitelist
	if err = datastore.Get(c, whitelistKey(c), &whitelist); err != nil {
		if err == datastore.ErrNoSuchEntity {
			c.Infof("whitelist not found, using test@example.com")
			whitelist.Value = "test@example.com"
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	records, err := csv.NewReader(strings.NewReader(whitelist.Value)).Read()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	found := false
	for _, record := range records {
		if record == user.Email {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, fmt.Sprintf("user %s not in whitelist", user), http.StatusInternalServerError)
		return
	}

	var clientId ClientId
	if clientId, err = getClientId(c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t, err := template.ParseFiles("templates/trial1.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	var clientSecret ClientSecret
	if clientSecret, err = getClientSecret(c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s := struct{ Name, Endpoint, ClientId, ClientSecret string }{user.String(), endpoint, clientId.Value, clientSecret.Value}
	if err := t.Execute(w, s); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func oauthUntappdHandler(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	_, ok := userLoggedIn(c, r.URL, w)
	if !ok {
		return
	}
	if len(r.FormValue("code")) == 0 {
		http.Error(w, "missing code parameter", http.StatusInternalServerError)
	}
	clientId, err := getClientId(c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	clientSecret, err := getClientSecret(c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u := url.URL{Scheme: "https", Host: "untappd.com", Path: "oauth/authorize/"}
	q := u.Query()
	q.Add("client_id", clientId.Value)
	q.Add("client_secret", clientSecret.Value)
	q.Add("response_type", "code")
	q.Add("code", r.FormValue("code"))
	q.Add("redirect_url", oauthCallback(c, "untappd"))
	u.RawQuery = q.Encode()
	resp, err := urlfetch.Client(c).Get(u.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	oauthResponse := struct {
		Response struct {
			AccessToken string `json:"access_token"`
		}
	}{}
	err = json.Unmarshal(buf, &oauthResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u = url.URL{Scheme: "https", Host: "api.untappd.com", Path: "/v4/checkin/recent"}
	q = u.Query()
	q.Add("access_token", oauthResponse.Response.AccessToken)
	u.RawQuery = q.Encode()
	client := urlfetch.Client(c)
	resp, err = client.Get(u.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp.Write(w)
}

func feedHandler(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	_, ok := userLoggedIn(c, r.URL, w)
	if !ok {
		return
	}
	var err error
	var clientId ClientId
	if clientId, err = getClientId(c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var untappdOath url.URL
	untappdOath.Scheme = "https"
	untappdOath.Host = "untappd.com"
	untappdOath.Path = "oauth/authenticate/"
	q := untappdOath.Query()
	q.Add("client_id", clientId.Value)
	q.Add("response_type", "code")
	q.Add("redirect_url", oauthCallback(c, "untappd"))
	untappdOath.RawQuery = q.Encode()
	http.Redirect(w, r, untappdOath.String(), http.StatusFound)
	return
}

func clientIdHandler(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	switch r.Method {
	case "PUT":
		var clientId ClientId
		clientId.Value = r.FormValue("value")
		if _, err := datastore.Put(c, clientIdKey(c), &clientId); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "GET":
		var clientId ClientId
		if err := datastore.Get(c, clientIdKey(c), &clientId); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, clientId)
	default:
		http.Error(w, fmt.Sprintf("Unhandled method: %s", r.Method), http.StatusInternalServerError)
	}
}

func clientSecretHandler(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	switch r.Method {
	case "PUT":
		var clientSecret ClientSecret
		clientSecret.Value = r.FormValue("value")
		if _, err := datastore.Put(c, clientSecretKey(c), &clientSecret); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "GET":
		var clientSecret ClientSecret
		if err := datastore.Get(c, clientSecretKey(c), &clientSecret); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, clientSecret)
	default:
		http.Error(w, fmt.Sprintf("Unhandled method: %s", r.Method), http.StatusInternalServerError)
	}
}

func whitelistHandler(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	switch r.Method {
	case "PUT":
		var whitelist Whitelist
		whitelist.Value = r.FormValue("value")
		if _, err := datastore.Put(c, whitelistKey(c), &whitelist); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "GET":
		var whitelist Whitelist
		if err := datastore.Get(c, whitelistKey(c), &whitelist); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, whitelist.Value)
	default:
		http.Error(w, fmt.Sprintf("Unhandled method: %s", r.Method), http.StatusInternalServerError)
	}
}
