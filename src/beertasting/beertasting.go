package beertasting

import (
	"appengine"
	"appengine/datastore"
	"appengine/urlfetch"
	"appengine/user"
	"code.google.com/p/go-uuid/uuid"
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

type handlerError struct {
	error
	code int
}

func (e handlerError) Error() string {
	return e.error.Error()
}

type appHandler func(http.ResponseWriter, *http.Request) *handlerError

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := fn(w, r); err != nil {
		http.Error(w, err.Error(), err.code)
	}
}

type appRestHandler func(rest.ResponseWriter, *rest.Request) *handlerError

func restHandler(fn appRestHandler) rest.HandlerFunc {
	return func(w rest.ResponseWriter, r *rest.Request) {
		if err := fn(w, r); err != nil {
			rest.Error(w, err.Error(), err.code)
		}
	}
}

func endpoint(p string) url.URL {
	return url.URL{
		Scheme: "http",
		Host:   "api.untappd.com",
		Path:   path.Join("v4", p),
	}
}

type AppengineMiddleware struct{}

func isAuthorized(r *http.Request) error {
	c := appengine.NewContext(r)
	u := user.Current(c)
	if u == nil {
		return fmt.Errorf("Not Authorized")
	}
	usr, err := lookupUser(r, u)
	if err != nil {
		return err
	}
	if usr == nil {
		return fmt.Errorf("Not Authorized")
	}
	return nil
}

func (AppengineMiddleware) MiddlewareFunc(handler rest.HandlerFunc) rest.HandlerFunc {
	return func(w rest.ResponseWriter, r *rest.Request) {
		if err := isAuthorized(r.Request); err != nil {
			rest.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

type AppengineAdminMiddleware struct{}

func (AppengineAdminMiddleware) MiddlewareFunc(handler rest.HandlerFunc) rest.HandlerFunc {
	return func(w rest.ResponseWriter, r *rest.Request) {
		c := appengine.NewContext(r.Request)
		if !user.IsAdmin(c) {
			rest.Error(w, "Not Authorized", http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

func init() {
	http.HandleFunc("/feed", feedHandler)
	http.HandleFunc("/displayFeed", displayFeedHandler)
	http.HandleFunc("/oauth/untappd", oauthUntappdHandler)
	http.Handle("/login", appHandler(loginHandler))
	http.Handle("/logout", appHandler(logoutHandler))
	http.Handle("/new-user", appHandler(newUserHandler))

	restNoAuthHandler := rest.ResourceHandler{}
	restNoAuthHandler.SetRoutes(
		&rest.Route{"GET", "/api/user/me", getUserMe},
		&rest.Route{"GET", "/api/untappd/search/beer", restHandler(untappdSearchBeer)},
	)

	restAdminHandler := rest.ResourceHandler{
		PreRoutingMiddlewares: []rest.Middleware{
			&AppengineMiddleware{},
			&AppengineAdminMiddleware{},
		},
	}
	restAdminHandler.SetRoutes(
		&rest.Route{"GET", "/api/admin/config", restHandler(getAdminConfig)},
		&rest.Route{"PUT", "/api/admin/config", restHandler(putAdminConfig)},
		&rest.Route{"GET", "/api/admin/user-tokens", getAdminAllUserTokens},
		&rest.Route{"POST", "/api/admin/user-tokens", postAdminUserTokens},
		&rest.Route{"DELETE", "/api/admin/user-tokens/:token", deleteAdminUserTokens},
	)

	restHandler := rest.ResourceHandler{
		PreRoutingMiddlewares: []rest.Middleware{
			&AppengineMiddleware{},
		},
	}
	restHandler.SetRoutes(
		&rest.Route{"GET", "/api/users", getAllUsers},
		&rest.Route{"POST", "/api/users", postUser},
		&rest.Route{"GET", "/api/users/:id", getUser},
		&rest.Route{"DELETE", "/api/users/:id", deleteUser},
		&rest.Route{"GET", "/api/users/:id/cellars", getAllCellars},
		&rest.Route{"POST", "/api/users/:id/cellars", postCellar},
		&rest.Route{"GET", "/api/users/:id/cellars/:cellar_id", getCellar},
		&rest.Route{"DELETE", "/api/users/:id/cellars/:cellar_id", deleteCellar},
		&rest.Route{"GET", "/api/users/:id/cellars/:cellar_id/beers", getAllBeers},
		&rest.Route{"POST", "/api/users/:id/cellars/:cellar_id/beers", postBeer},
		&rest.Route{"GET", "/api/users/:id/cellars/:cellar_id/beers/:beer_id", getBeer},
		&rest.Route{"DELETE", "/api/users/:id/cellars/:cellar_id/beers/:beer_id", deleteBeer},
	)
	http.Handle("/api/admin/config", &restAdminHandler)
	http.Handle("/api/admin/user-tokens", &restAdminHandler)
	http.Handle("/api/admin/user-tokens/", &restAdminHandler)
	http.Handle("/api/user/me", &restNoAuthHandler)
	http.Handle("/api/untappd/", &restNoAuthHandler)
	http.Handle("/api/users", &restHandler)
	http.Handle("/api/users/", &restHandler)
}

type Config struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
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

type UserToken struct {
	ID   int64 `datastore:"-"`
	Hash string
}

func (token *UserToken) DecodeJsonPayload(*rest.Request) error {
	token.Hash = uuid.NewRandom().String()
	return nil
}

type UserTokens []UserToken

func (tokens *UserTokens) DatastoreGet(r *rest.Request) (int, error) {
	c := appengine.NewContext(r.Request)
	*tokens = UserTokens{}
	q := datastore.NewQuery("UserToken")
	for t := q.Run(c); ; {
		var ut UserToken
		key, err := t.Next(&ut)
		if err == datastore.Done {
			break
		}
		if err != nil {
			return http.StatusInternalServerError, err
		}
		ut.ID = key.IntID()
		*tokens = append(*tokens, ut)
	}
	return http.StatusOK, nil
}

func (UserToken) PathParamID() string {
	return "token"
}

func (UserToken) Kind() string {
	return "UserToken"
}

func (ut UserToken) WriteJson(w rest.ResponseWriter, key *datastore.Key) {
	ut.ID = key.IntID()
	writeJson(w, ut)
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

func (u User) WriteJson(w rest.ResponseWriter, key *datastore.Key) {
	u.ID = key.IntID()
	writeJson(w, u)
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
	if err := datastore.Get(c, key, user); err != nil {
		return http.StatusInternalServerError, err
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

func (c Cellar) WriteJson(w rest.ResponseWriter, key *datastore.Key) {
	c.ID = key.IntID()
	writeJson(w, c)
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
	if err := datastore.Get(c, key, cellar); err != nil {
		return http.StatusInternalServerError, err
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

func (b Beer) WriteJson(w rest.ResponseWriter, key *datastore.Key) {
	b.ID = key.IntID()
	writeJson(w, b)
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
	if err := datastore.Get(c, key, beer); err != nil {
		return http.StatusInternalServerError, err
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
	if err := datastore.Get(c, configKey(c), &cfg); err != nil {
		c.Errorf("missing config")
		return Config{}, fmt.Errorf("getConfig(): %v", err)
	}
	return cfg, nil
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

func userLoggedIn(r *http.Request, w http.ResponseWriter) (*user.User, bool) {
	c := appengine.NewContext(r)
	u := user.Current(c)
	if u != nil {
		return u, true
	}
	ur, err := user.LoginURL(c, r.URL.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, false
	}
	http.Redirect(w, r, ur, http.StatusFound)
	return nil, false
}

func loginHandler(w http.ResponseWriter, r *http.Request) *handlerError {
	c := appengine.NewContext(r)
	newURL := r.URL
	newURL.Path = "/"
	u, err := user.LoginURL(c, newURL.String())
	if err != nil {
		return &handlerError{err, http.StatusInternalServerError}
	}
	http.Redirect(w, r, u, http.StatusFound)
	return nil
}

func logoutHandler(w http.ResponseWriter, r *http.Request) *handlerError {
	c := appengine.NewContext(r)
	newURL := r.URL
	newURL.Path = "/"
	u, err := user.LogoutURL(c, newURL.String())
	if err != nil {
		return &handlerError{err, http.StatusInternalServerError}
	}
	http.Redirect(w, r, u, http.StatusFound)
	return nil
}

func oauthUntappdHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := userLoggedIn(r, w)
	if !ok {
		return
	}
	if len(r.FormValue("code")) == 0 {
		http.Error(w, "missing code parameter", http.StatusInternalServerError)
		return
	}
	var config Config
	var err error
	c := appengine.NewContext(r)
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
	user, ok := userLoggedIn(r, w)
	if !ok {
		return
	}
	t, err := template.ParseFiles("templates/feed.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	end := endpoint("checkin/recent")
	s := struct{ Name, FeedRequest string }{user.String(), end.String()}
	if err := t.Execute(w, s); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func feedHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := userLoggedIn(r, w)
	if !ok {
		return
	}
	var config Config
	var err error
	c := appengine.NewContext(r)
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

func lookupUser(r *http.Request, u *user.User) (*User, error) {
	c := appengine.NewContext(r)
	q := datastore.NewQuery("User").Filter("Email =", u.Email)
	for t := q.Run(c); ; {
		var usr User
		_, err := t.Next(&usr)
		if err == datastore.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		// TODO: handle >1 result
		c.Warningf("user %s already exists", u.Email)
		return &usr, nil
	}
	usr := User{Name: u.String(), Email: u.Email}
	key := datastore.NewIncompleteKey(c, usr.Kind(), nil)
	if _, err := datastore.Put(c, key, &usr); err != nil {
		return nil, err
	}
	c.Warningf("added user %s", u.Email)
	return &usr, nil
}

func maybeCreateUser(r *http.Request, u *user.User) (*User, error) {
	usr, err := lookupUser(r, u)
	if err != nil {
		return nil, err
	}
	c := appengine.NewContext(r)
	if usr == nil {
		usr := User{Name: u.String(), Email: u.Email}
		key := datastore.NewIncompleteKey(c, usr.Kind(), nil)
		if _, err := datastore.Put(c, key, &usr); err != nil {
			return nil, err
		}
		c.Warningf("added user %s", u.Email)
	} else {
		c.Warningf("user %s already exists", u.Email)
	}
	return usr, nil
}

func lookupTokenKeys(r *http.Request) ([]*datastore.Key, error) {
	if err := r.ParseForm(); err != nil {
		return []*datastore.Key{}, err
	}
	token := r.FormValue("token")
	if len(token) == 0 {
		return []*datastore.Key{}, fmt.Errorf("missing 'token'")
	}
	c := appengine.NewContext(r)
	q := datastore.NewQuery("UserToken").Filter("Hash =", token).KeysOnly()
	res := []*datastore.Key{}
	for t := q.Run(c); ; {
		key, err := t.Next(nil)
		if err == datastore.Done {
			break
		}
		if err != nil {
			return []*datastore.Key{}, err
		}
		res = append(res, key)
	}
	return res, nil
}

func newUserHandler(w http.ResponseWriter, r *http.Request) *handlerError {
	c := appengine.NewContext(r)
	tokenKeys, err := lookupTokenKeys(r)
	if err != nil {
		return &handlerError{err, http.StatusBadRequest}
	}
	u := user.Current(c)
	if u == nil {
		ur, err := user.LoginURL(c, r.URL.String())
		if err != nil {
			return &handlerError{err, http.StatusInternalServerError}
		}
		http.Redirect(w, r, ur, http.StatusFound)
		return nil
	}
	if _, err = maybeCreateUser(r, u); err != nil {
		return &handlerError{err, http.StatusInternalServerError}
	}
	if err = datastore.DeleteMulti(c, tokenKeys); err != nil {
		return &handlerError{err, http.StatusInternalServerError}
	}
	newURL := r.URL
	newURL.Path = "/"
	newURL.RawQuery = ""
	http.Redirect(w, r, newURL.String(), http.StatusFound)
	return nil
}

func writeJson(w rest.ResponseWriter, v interface{}) {
	if err := w.WriteJson(v); err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func putAdminConfig(w rest.ResponseWriter, r *rest.Request) *handlerError {
	var config Config
	c := appengine.NewContext(r.Request)
	err := r.DecodeJsonPayload(&config)
	if err != nil {
		err = fmt.Errorf("DecodeJsonPayload(): %s", err)
		return &handlerError{err, http.StatusInternalServerError}
	}
	if _, err := datastore.Put(c, configKey(c), &config); err != nil {
		return &handlerError{err, http.StatusInternalServerError}
	}
	writeJson(w, config)
	return nil
}

func getAdminConfig(w rest.ResponseWriter, r *rest.Request) *handlerError {
	var config Config
	c := appengine.NewContext(r.Request)
	if err := datastore.Get(c, configKey(c), &config); err != nil {
		return &handlerError{err, http.StatusInternalServerError}
	}
	writeJson(w, config)
	return nil
}

func getUserMe(w rest.ResponseWriter, r *rest.Request) {
	c := appengine.NewContext(r.Request)
	u := user.Current(c)
	if u == nil {
		http.Error(w.(http.ResponseWriter), "not signed in", http.StatusNotFound)
		return
	}
	logoutURL, err := user.LogoutURL(c, r.URL.String())
	if err != nil {
		http.Error(w.(http.ResponseWriter), err.Error(), http.StatusNotFound)
		return
	}
	writeJson(w, struct {
		Name      string `json:"name"`
		IsAdmin   bool   `json:"is_admin"`
		LogoutURL string `json:"logout_url"`
	}{u.String(), user.IsAdmin(c), logoutURL})
}

type RestGetter interface {
	DatastoreGet(r *rest.Request) (int, error)
}

func restGet(w rest.ResponseWriter, r *rest.Request, val RestGetter) {
	if status, err := val.DatastoreGet(r); err != nil {
		rest.Error(w, err.Error(), status)
		return
	}
	writeJson(w, val)
}

func getUser(w rest.ResponseWriter, r *rest.Request) {
	var user User
	restGet(w, r, &user)
}

func getAllUsers(w rest.ResponseWriter, r *rest.Request) {
	var users Users
	restGet(w, r, &users)
}

type RestPutter interface {
	DecodeJsonPayload(r *rest.Request) error
	WriteJson(w rest.ResponseWriter, key *datastore.Key)
	IDKeyer
}

func restPost(w rest.ResponseWriter, r *rest.Request, val RestPutter, parentKey *datastore.Key) {
	err := val.DecodeJsonPayload(r)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c := appengine.NewContext(r.Request)
	key := datastore.NewIncompleteKey(c, val.Kind(), parentKey)
	newKey, err := datastore.Put(c, key, val)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	val.WriteJson(w, newKey)
}

func postUser(w rest.ResponseWriter, r *rest.Request) {
	var user User
	restPost(w, r, &user, nil)
}

type RestKeyer interface {
	DatastoreKey(r *rest.Request) (*datastore.Key, error)
}

func restDelete(w rest.ResponseWriter, r *rest.Request, keyer RestKeyer) {
	key, err := keyer.DatastoreKey(r)
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

func deleteUser(w rest.ResponseWriter, r *rest.Request) {
	restDelete(w, r, User{})
}

func getCellar(w rest.ResponseWriter, r *rest.Request) {
	var cellar Cellar
	restGet(w, r, &cellar)
}

func getAllCellars(w rest.ResponseWriter, r *rest.Request) {
	var cellars Cellars
	restGet(w, r, &cellars)
}

func postCellar(w rest.ResponseWriter, r *rest.Request) {
	parentKey, err := User{}.DatastoreKey(r)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var cellar Cellar
	restPost(w, r, &cellar, parentKey)
}

func deleteCellar(w rest.ResponseWriter, r *rest.Request) {
	restDelete(w, r, Cellar{})
}

func getBeer(w rest.ResponseWriter, r *rest.Request) {
	var beer Beer
	restGet(w, r, &beer)
}

func getAllBeers(w rest.ResponseWriter, r *rest.Request) {
	var beers Beers
	restGet(w, r, &beers)
}

func postBeer(w rest.ResponseWriter, r *rest.Request) {
	parentKey, err := Cellar{}.DatastoreKey(r)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var beer Beer
	restPost(w, r, &beer, parentKey)
}

func deleteBeer(w rest.ResponseWriter, r *rest.Request) {
	restDelete(w, r, Beer{})
}

func noAuthUntappdURL(r *http.Request, path string) (url.URL, error) {
	c := appengine.NewContext(r)
	config, err := getConfig(c)
	if err != nil {
		return url.URL{}, err
	}
	res := endpoint(path)
	res.RawQuery = r.URL.RawQuery
	q := res.Query()
	q.Add("client_id", config.ClientId)
	q.Add("client_secret", config.ClientSecret)
	res.RawQuery = q.Encode()
	return res, nil
}

func untappdSearchBeer(w rest.ResponseWriter, r *rest.Request) *handlerError {
	if err := isAuthorized(r.Request); err != nil {
		return &handlerError{err, http.StatusUnauthorized}
	}
	c := appengine.NewContext(r.Request)
	url := "/search/beer"
	reqURL, err := noAuthUntappdURL(r.Request, url)
	if err != nil {
		return &handlerError{err, http.StatusInternalServerError}
	}
	client := urlfetch.Client(c)
	resp, err := client.Get(reqURL.String())
	if err != nil {
		c.Errorf("client.Get: %v", err)
		return &handlerError{err, http.StatusInternalServerError}
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.Errorf("ReadAll: %v", err)
		return &handlerError{err, http.StatusInternalServerError}
	}
	var v interface{}
	if err = json.Unmarshal(body, &v); err != nil {
		c.Errorf("json.Unmarshall: %v", err)
		return &handlerError{err, http.StatusInternalServerError}
	}
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	w.WriteJson(v)
	return nil
}

func getAdminAllUserTokens(w rest.ResponseWriter, r *rest.Request) {
	var tokens UserTokens
	restGet(w, r, &tokens)
}

func postAdminUserTokens(w rest.ResponseWriter, r *rest.Request) {
	var token UserToken
	restPost(w, r, &token, nil)
}

func deleteAdminUserTokens(w rest.ResponseWriter, r *rest.Request) {
	if keys, err := lookupTokenKeys(r.Request); err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		c := appengine.NewContext(r.Request)
		if err := datastore.DeleteMulti(c, keys); err != nil {
			rest.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
	return
}
