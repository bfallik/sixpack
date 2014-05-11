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
	"strconv"
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
		&rest.Route{"GET", "/users", getAllUsers},
		&rest.Route{"POST", "/users", postUser},
		&rest.Route{"GET", "/users/:id", getUser},
		&rest.Route{"DELETE", "/users/:id", deleteUser},
		&rest.Route{"GET", "/users/:id/cellars", getAllCellars},
		&rest.Route{"POST", "/users/:id/cellars", postCellar},
		&rest.Route{"GET", "/users/:id/cellars/:cellar_id", getCellar},
		&rest.Route{"DELETE", "/users/:id/cellars/:cellar_id", deleteCellar},
	)
	http.Handle("/admin/config", &restHandler)
	http.Handle("/users", &restHandler)
	http.Handle("/users/", &restHandler)
}

var (
	endpoint = url.URL{Scheme: "http", Host: "api.untappd.com", Path: "v4"}
)

type Config struct {
	ClientId     string
	ClientSecret string
	Whitelist    []string
}

type User struct {
	ID    int64 `datastore:"-"`
	Name  string
	Email string
}

func (user *User) DecodeJsonPayload(r *rest.Request) error {
	err := r.DecodeJsonPayload(user)
	if err != nil {
		return err
	}
	if user.Name == "" {
		return fmt.Errorf("name required")
	}
	if user.Email == "" {
		return fmt.Errorf("email required")
	}
	return nil
}

type Cellar struct {
	ID   int64 `datastore:"-"`
	Name string
}

func (cellar *Cellar) DecodeJsonPayload(r *rest.Request) error {
	err := r.DecodeJsonPayload(cellar)
	if err != nil {
		return err
	}
	if cellar.Name == "" {
		return fmt.Errorf("name required")
	}
	return nil
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

func datastoreRestGet(c appengine.Context, k *datastore.Key, w rest.ResponseWriter, v interface{}) {
	if err := datastore.Get(c, k, v); err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJson(w, v)
}

func datastoreRestPut(c appengine.Context, k *datastore.Key, w rest.ResponseWriter, v interface{}) {
	if _, err := datastore.Put(c, k, v); err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJson(w, v)
}

func putAdminConfigCtx(c appengine.Context, w rest.ResponseWriter, r *rest.Request) {
	var config Config
	err := r.DecodeJsonPayload(&config)
	if err != nil {
		err = fmt.Errorf("DecodeJsonPayload(): %s", err)
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	datastoreRestPut(c, configKey(c), w, &config)
}

func putAdminConfig(w rest.ResponseWriter, r *rest.Request) {
	c := appengine.NewContext(r.Request)
	putAdminConfigCtx(c, w, r)
}

func getAdminConfigCtx(c appengine.Context, w rest.ResponseWriter) {
	var config Config
	datastoreRestGet(c, configKey(c), w, &config)
}

func getAdminConfig(w rest.ResponseWriter, r *rest.Request) {
	c := appengine.NewContext(r.Request)
	getAdminConfigCtx(c, w)
}

func getUser(w rest.ResponseWriter, r *rest.Request) {
	id, err := strconv.Atoi(r.PathParam("id"))
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c := appengine.NewContext(r.Request)
	key := datastore.NewKey(c, "User", "", int64(id), nil)
	var user User
	datastoreRestGet(c, key, w, &user)
}

func getAllUsers(w rest.ResponseWriter, r *rest.Request) {
	users := []User{}
	c := appengine.NewContext(r.Request)
	q := datastore.NewQuery("User")
	for t := q.Run(c); ; {
		var u User
		key, err := t.Next(&u)
		if err == datastore.Done {
			break
		}
		if err != nil {
			rest.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		u.ID = key.IntID()
		users = append(users, u)
	}
	w.WriteJson(&users)
}

func postUser(w rest.ResponseWriter, r *rest.Request) {
	user := User{}
	err := user.DecodeJsonPayload(r)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c := appengine.NewContext(r.Request)
	key := datastore.NewIncompleteKey(c, "User", nil)
	newKey, err := datastore.Put(c, key, &user)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	user.ID = newKey.IntID()
	writeJson(w, user)
}

func deleteUser(w rest.ResponseWriter, r *rest.Request) {
	c := appengine.NewContext(r.Request)
	id, err := strconv.Atoi(r.PathParam("id"))
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	key := datastore.NewKey(c, "User", "", int64(id), nil)
	err = datastore.Delete(c, key)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func getCellar(w rest.ResponseWriter, r *rest.Request) {
	id, err := strconv.Atoi(r.PathParam("id"))
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cellarId, err := strconv.Atoi(r.PathParam("cellar_id"))
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c := appengine.NewContext(r.Request)
	userKey := datastore.NewKey(c, "User", "", int64(id), nil)
	key := datastore.NewKey(c, "Cellar", "", int64(cellarId), userKey)
	var cellar Cellar
	datastoreRestGet(c, key, w, &cellar)
}

func getAllCellars(w rest.ResponseWriter, r *rest.Request) {
	id, err := strconv.Atoi(r.PathParam("id"))
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cellars := []Cellar{}
	c := appengine.NewContext(r.Request)
	userKey := datastore.NewKey(c, "User", "", int64(id), nil)
	q := datastore.NewQuery("Cellar").Ancestor(userKey)
	for t := q.Run(c); ; {
		var c Cellar
		key, err := t.Next(&c)
		if err == datastore.Done {
			break
		}
		if err != nil {
			rest.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		c.ID = key.IntID()
		cellars = append(cellars, c)
	}
	w.WriteJson(&cellars)
}

func postCellar(w rest.ResponseWriter, r *rest.Request) {
	id, err := strconv.Atoi(r.PathParam("id"))
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cellar := Cellar{}
	err = cellar.DecodeJsonPayload(r)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c := appengine.NewContext(r.Request)
	userKey := datastore.NewKey(c, "User", "", int64(id), nil)
	key := datastore.NewIncompleteKey(c, "Cellar", userKey)
	newKey, err := datastore.Put(c, key, &cellar)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cellar.ID = newKey.IntID()
	writeJson(w, cellar)
}

func deleteCellar(w rest.ResponseWriter, r *rest.Request) {
	id, err := strconv.Atoi(r.PathParam("id"))
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cellarId, err := strconv.Atoi(r.PathParam("cellar_id"))
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c := appengine.NewContext(r.Request)
	userKey := datastore.NewKey(c, "User", "", int64(id), nil)
	key := datastore.NewKey(c, "Cellar", "", int64(cellarId), userKey)
	err = datastore.Delete(c, key)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
