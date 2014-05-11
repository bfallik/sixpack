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
		&rest.Route{"GET", "/users/:id/cellars/:cellar_id/beers", getAllBeers},
		&rest.Route{"POST", "/users/:id/cellars/:cellar_id/beers", postBeer},
		&rest.Route{"GET", "/users/:id/cellars/:cellar_id/beers/:beer_id", getBeer},
		&rest.Route{"DELETE", "/users/:id/cellars/:cellar_id/beers/:beer_id", deleteBeer},
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

type IDKeyer interface {
	PathParamID() string
	Kind() string
}

func datastoreKey(r *rest.Request, keyer IDKeyer, parent *datastore.Key) (*datastore.Key, error) {
	id, err := strconv.Atoi(r.PathParam(keyer.PathParamID()))
	if err != nil {
		return nil, err
	}
	c := appengine.NewContext(r.Request)
	return datastore.NewKey(c, keyer.Kind(), "", int64(id), parent), nil
}

type User struct {
	ID    int64 `datastore:"-"`
	Name  string
	Email string
}

func (user *User) DecodeJsonPayload(r *rest.Request) error {
	if err := r.DecodeJsonPayload(user); err != nil {
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

func (User) PathParamID() string {
	return "id"
}

func (User) Kind() string {
	return "User"
}

func (user User) DatastoreKey(r *rest.Request) (*datastore.Key, error) {
	return datastoreKey(r, user, nil)
}

func (user *User) DatastoreGet(r *rest.Request) (int, error) {
	key, err := user.DatastoreKey(r)
	if err != nil {
		return http.StatusBadRequest, err
	}
	c := appengine.NewContext(r.Request)
	if status, err := datastoreRestGet(c, key, user); err != nil {
		return status, err
	}
	user.ID = key.IntID()
	return http.StatusOK, nil
}

type Users []User

func (users *Users) DatastoreGet(r *rest.Request) (int, error) {
	c := appengine.NewContext(r.Request)
	*users = Users{}
	q := datastore.NewQuery("User")
	for t := q.Run(c); ; {
		var u User
		key, err := t.Next(&u)
		if err == datastore.Done {
			break
		}
		if err != nil {
			return http.StatusInternalServerError, err
		}
		u.ID = key.IntID()
		*users = append(*users, u)
	}
	return http.StatusOK, nil
}

type Cellar struct {
	ID   int64 `datastore:"-"`
	Name string
}

func (cellar *Cellar) DecodeJsonPayload(r *rest.Request) error {
	if err := r.DecodeJsonPayload(cellar); err != nil {
		return err
	}
	if cellar.Name == "" {
		return fmt.Errorf("name required")
	}
	return nil
}

func (Cellar) PathParamID() string {
	return "cellar_id"
}

func (Cellar) Kind() string {
	return "Cellar"
}

func (cellar Cellar) DatastoreKey(r *rest.Request) (*datastore.Key, error) {
	userKey, err := User{}.DatastoreKey(r)
	if err != nil {
		return nil, err
	}
	return datastoreKey(r, cellar, userKey)
}

func (cellar *Cellar) DatastoreGet(r *rest.Request) (int, error) {
	key, err := cellar.DatastoreKey(r)
	if err != nil {
		return http.StatusBadRequest, err
	}
	c := appengine.NewContext(r.Request)
	if status, err := datastoreRestGet(c, key, cellar); err != nil {
		return status, err
	}
	cellar.ID = key.IntID()
	return http.StatusOK, nil
}

type Cellars []Cellar

func (cellars *Cellars) DatastoreGet(r *rest.Request) (int, error) {
	var user User
	c := appengine.NewContext(r.Request)
	userKey, err := user.DatastoreKey(r)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	*cellars = Cellars{}
	q := datastore.NewQuery("Cellar").Ancestor(userKey)
	for t := q.Run(c); ; {
		var cl Cellar
		key, err := t.Next(&cl)
		if err == datastore.Done {
			break
		}
		if err != nil {
			return http.StatusInternalServerError, err
		}
		cl.ID = key.IntID()
		*cellars = append(*cellars, cl)
	}
	return http.StatusOK, nil
}

type Beer struct {
	ID   int64
	Name string
}

func (beer *Beer) DecodeJsonPayload(r *rest.Request) error {
	if err := r.DecodeJsonPayload(beer); err != nil {
		return err
	}
	if beer.Name == "" {
		return fmt.Errorf("name required")
	}
	return nil
}

func (Beer) PathParamID() string {
	return "beer_id"
}

func (Beer) Kind() string {
	return "Beer"
}

func (beer Beer) DatastoreKey(r *rest.Request) (*datastore.Key, error) {
	cellarKey, err := Cellar{}.DatastoreKey(r)
	if err != nil {
		return nil, err
	}
	return datastoreKey(r, beer, cellarKey)
}

func (beer *Beer) DatastoreGet(r *rest.Request) (int, error) {
	key, err := beer.DatastoreKey(r)
	if err != nil {
		return http.StatusBadRequest, err
	}
	c := appengine.NewContext(r.Request)
	if status, err := datastoreRestGet(c, key, beer); err != nil {
		return status, err
	}
	beer.ID = key.IntID()
	return http.StatusOK, nil
}

type Beers []Beer

func (beers *Beers) DatastoreGet(r *rest.Request) (int, error) {
	c := appengine.NewContext(r.Request)
	cellarKey, err := Cellar{}.DatastoreKey(r)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	*beers = Beers{}
	q := datastore.NewQuery("Beer").Ancestor(cellarKey)
	for t := q.Run(c); ; {
		var b Beer
		key, err := t.Next(&b)
		if err == datastore.Done {
			break
		}
		if err != nil {
			return http.StatusInternalServerError, err
		}
		b.ID = key.IntID()
		*beers = append(*beers, b)
	}
	return http.StatusOK, nil
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

func datastoreRestGet(c appengine.Context, k *datastore.Key, v interface{}) (int, error) {
	if err := datastore.Get(c, k, v); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func putAdminConfig(w rest.ResponseWriter, r *rest.Request) {
	var config Config
	c := appengine.NewContext(r.Request)
	err := r.DecodeJsonPayload(&config)
	if err != nil {
		err = fmt.Errorf("DecodeJsonPayload(): %s", err)
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := datastore.Put(c, configKey(c), &config); err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJson(w, config)
}

func getAdminConfig(w rest.ResponseWriter, r *rest.Request) {
	var config Config
	c := appengine.NewContext(r.Request)
	if status, err := datastoreRestGet(c, configKey(c), config); err != nil {
		rest.Error(w, err.Error(), status)
		return
	}
	writeJson(w, config)
}

func getUser(w rest.ResponseWriter, r *rest.Request) {
	var user User
	if status, err := user.DatastoreGet(r); err != nil {
		rest.Error(w, err.Error(), status)
		return
	}
	writeJson(w, user)
}

func getAllUsers(w rest.ResponseWriter, r *rest.Request) {
	users := Users{}
	users.DatastoreGet(r)
	w.WriteJson(users)
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
	key, err := User{}.DatastoreKey(r)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c := appengine.NewContext(r.Request)
	err = datastore.Delete(c, key)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func getCellar(w rest.ResponseWriter, r *rest.Request) {
	var cellar Cellar
	if status, err := cellar.DatastoreGet(r); err != nil {
		rest.Error(w, err.Error(), status)
		return
	}
	writeJson(w, cellar)
}

func getAllCellars(w rest.ResponseWriter, r *rest.Request) {
	var cellars Cellars
	if status, err := cellars.DatastoreGet(r); err != nil {
		rest.Error(w, err.Error(), status)
		return
	}
	w.WriteJson(cellars)
}

func postCellar(w rest.ResponseWriter, r *rest.Request) {
	userKey, err := User{}.DatastoreKey(r)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cellar := Cellar{}
	err = cellar.DecodeJsonPayload(r)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c := appengine.NewContext(r.Request)
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
	key, err := Cellar{}.DatastoreKey(r)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c := appengine.NewContext(r.Request)
	err = datastore.Delete(c, key)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func getBeer(w rest.ResponseWriter, r *rest.Request) {
	var beer Beer
	if status, err := beer.DatastoreGet(r); err != nil {
		rest.Error(w, err.Error(), status)
		return
	}
	writeJson(w, beer)
}

func getAllBeers(w rest.ResponseWriter, r *rest.Request) {
	var beers Beers
	if status, err := beers.DatastoreGet(r); err != nil {
		rest.Error(w, err.Error(), status)
		return
	}
	w.WriteJson(beers)
}

func postBeer(w rest.ResponseWriter, r *rest.Request) {
	cellarKey, err := Cellar{}.DatastoreKey(r)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	beer := Beer{}
	if err := beer.DecodeJsonPayload(r); err != nil {
		rest.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c := appengine.NewContext(r.Request)
	key := datastore.NewIncompleteKey(c, "Beer", cellarKey)
	newKey, err := datastore.Put(c, key, &beer)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	beer.ID = newKey.IntID()
	writeJson(w, beer)
}

func deleteBeer(w rest.ResponseWriter, r *rest.Request) {
	key, err := Beer{}.DatastoreKey(r)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c := appengine.NewContext(r.Request)
	err = datastore.Delete(c, key)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
