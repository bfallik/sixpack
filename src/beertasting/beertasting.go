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
	"path"
	"time"
)

func init() {
	http.HandleFunc("/", handler)
	http.HandleFunc("/search", searchHandler)
	http.HandleFunc("/feed", feedHandler)
	http.HandleFunc("/displayFeed", displayFeedHandler)
	http.HandleFunc("/oauth/untappd", oauthUntappdHandler)
	restHandler := rest.ResourceHandler{}
	restHandler.SetRoutes(
		&rest.Route{"GET", "/admin/config", getAdminConfig},
		&rest.Route{"PUT", "/admin/config", putAdminConfig},
	)
	http.Handle("/admin/config", &restHandler)
}

var (
	endpoint = url.URL{Scheme: "http", Host: "api.untappd.com", Path: "v4"}
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

func httpCallback(c appengine.Context, path string) *url.URL {
	return &url.URL{
		Scheme: "http",
		Host:   appengine.DefaultVersionHostname(c),
		Path:   path,
	}
}

func oauthCallback(c appengine.Context, svc string) *url.URL {
	return httpCallback(c, fmt.Sprintf("oauth/%s", svc))
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
		return
	}
	s := struct{ Name, Endpoint, ClientId, ClientSecret string }{
		user.String(),
		endpoint.String(),
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
		return
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
	q.Add("redirect_url", oauthCallback(c, "untappd").String())
	u.RawQuery = q.Encode()
	c.Infof("authorize URL: %s", u.String())
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
		err = fmt.Errorf("%s: %s", err.Error(), string(buf))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	expire := time.Now().AddDate(0, 0, 1)
	hostname := appengine.DefaultVersionHostname(c)
	raw := fmt.Sprintf("access_token=%s", oauthResponse.Response.AccessToken)
	cookie := http.Cookie{
		Name:       "access_token",
		Value:      oauthResponse.Response.AccessToken,
		Path:       "/",
		Domain:     hostname,
		Expires:    expire,
		RawExpires: expire.Format(time.UnixDate),
		MaxAge:     86400,
		Secure:     false,
		HttpOnly:   false,
		Raw:        raw,
		Unparsed:   []string{raw},
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/displayFeed", http.StatusFound)
}

func displayFeedHandler(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	user, ok := userLoggedIn(c, r.URL, w)
	if !ok {
		return
	}
	t, err := template.ParseFiles("templates/feed.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	endpoint.Path = path.Join(endpoint.Path, "checkin/recent")
	s := struct{ Name, FeedRequest string }{user.String(), endpoint.String()}
	if err := t.Execute(w, s); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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
	q.Add("redirect_url", oauthCallback(c, "untappd").String())
	untappdOath.RawQuery = q.Encode()
	http.Redirect(w, r, untappdOath.String(), http.StatusFound)
	return
}

func writeJson(w rest.ResponseWriter, v interface{}) {
	if err := w.WriteJson(v); err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
	}
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
	writeJson(w, config)
}

func getAdminConfig(w rest.ResponseWriter, r *rest.Request) {
	c := appengine.NewContext(r.Request)
	var config Config
	if err := datastore.Get(c, configKey(c), &config); err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJson(w, config)
}
