package beertasting

import (
	"fmt"
	"html/template"
	"net/http"

	"appengine"
	"appengine/datastore"
	"appengine/user"
)

func init() {
	http.HandleFunc("/", handler)
	http.HandleFunc("/admin/untappd/client_id", clientIdHandler)
	http.HandleFunc("/admin/untappd/client_secret", clientSecretHandler)
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

func clientIdKey(c appengine.Context) *datastore.Key {
	return datastore.NewKey(c, "ClientId", "default", 0, nil)
}

func clientSecretKey(c appengine.Context) *datastore.Key {
	return datastore.NewKey(c, "ClientSecret", "default", 0, nil)
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

func handler(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	u := user.Current(c)
	if u == nil {
		url, err := user.LoginURL(c, r.URL.String())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Location", url)
		w.WriteHeader(http.StatusFound)
		return
	}
	t, err := template.ParseFiles("templates/trial1.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	var clientId ClientId
	if clientId, err = getClientId(c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var clientSecret ClientSecret
	if clientSecret, err = getClientSecret(c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s := struct{ Name, Endpoint, ClientId, ClientSecret string }{u.String(), endpoint, clientId.Value, clientSecret.Value}
	if err := t.Execute(w, s); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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
