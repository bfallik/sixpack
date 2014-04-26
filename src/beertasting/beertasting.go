package beertasting

import (
	"appengine"
	"appengine/datastore"
	"appengine/urlfetch"
	"appengine/user"
	"encoding/json"
	"fmt"
	"github.com/ant0ine/go-json-rest/rest"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
)

func init() {
	http.HandleFunc("/", handler)
	http.HandleFunc("/search", searchHandler)
	http.HandleFunc("/feed", feedHandler)
	http.HandleFunc("/oauth/untappd", oauthUntappdHandler)
	restHandler := rest.ResourceHandler{}
	restHandler.SetRoutes(
		&rest.Route{"GET", "/admin/config", getAdminConfig},
		&rest.Route{"PUT", "/admin/config", putAdminConfig},
	)
	http.Handle("/admin/config", &restHandler)
}

const (
	endpoint = "http://api.untappd.com/v4"
)

type Config struct {
	ClientId     string
	ClientSecret string
	Whitelist    []string
}

func configKey(c appengine.Context) *datastore.Key {
	return datastore.NewKey(c, "Config", "default", 0, nil)
}

func getConfig(c appengine.Context) (Config, error) {
	var cfg Config
	err := datastore.Get(c, configKey(c), &cfg)
	return cfg, err
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
	var config Config
	if config, err = getConfig(c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(config.Whitelist) == 0 {
		c.Infof("whitelist not found, using test@example.com")
		config.Whitelist = []string{"test@example.com"}
	}
	found := false
	for _, record := range config.Whitelist {
		if record == user.Email {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, fmt.Sprintf("user %s not in whitelist", user), http.StatusInternalServerError)
		return
	}

	t, err := template.ParseFiles("templates/trial1.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	s := struct{ Name, Endpoint, ClientId, ClientSecret string }{
		user.String(),
		endpoint,
		config.ClientId,
		config.ClientSecret,
	}
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
	var config Config
	var err error
	if config, err = getConfig(c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u := url.URL{Scheme: "https", Host: "untappd.com", Path: "oauth/authorize/"}
	q := u.Query()
	q.Add("client_id", config.ClientId)
	q.Add("client_secret", config.ClientSecret)
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
	var config Config
	var err error
	if config, err = getConfig(c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var untappdOath url.URL
	untappdOath.Scheme = "https"
	untappdOath.Host = "untappd.com"
	untappdOath.Path = "oauth/authenticate/"
	q := untappdOath.Query()
	q.Add("client_id", config.ClientId)
	q.Add("response_type", "code")
	q.Add("redirect_url", oauthCallback(c, "untappd"))
	untappdOath.RawQuery = q.Encode()
	http.Redirect(w, r, untappdOath.String(), http.StatusFound)
	return
}

func putAdminConfig(w rest.ResponseWriter, r *rest.Request) {
	c := appengine.NewContext(r.Request)
	var config Config
	err := r.DecodeJsonPayload(&config)
	if err != nil {
		err = fmt.Errorf("DecodeJsonPayload(): %s", err)
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := datastore.Put(c, configKey(c), &config); err != nil {
		err = fmt.Errorf("datastore.Put(): %s", err)
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err = w.WriteJson(config); err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func getAdminConfig(w rest.ResponseWriter, r *rest.Request) {
	c := appengine.NewContext(r.Request)
	var config Config
	if err := datastore.Get(c, configKey(c), &config); err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := w.WriteJson(config); err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
