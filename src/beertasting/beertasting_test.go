package beertasting

import (
	"appengine/aetest"
	"appengine/datastore"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/http"
	"testing"
)

func Test_configKey(t *testing.T) {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	assert.NotNil(t, configKey(c))
}

type mockResponseWriter struct {
	http.TestResponseWriter
	t *testing.T
}

func (m *mockResponseWriter) WriteJson(v interface{}) error {
	b, err := m.EncodeJson(v)
	if err != nil {
		panic("NOT IMPLEMENTED")
	}
	_, err = m.Write(b)
	return err
}

func (m *mockResponseWriter) EncodeJson(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func Test_writeJson(t *testing.T) {
	s := struct{ int }{4}
	var w = mockResponseWriter{t: t}
	writeJson(&w, &s)
	assert.Equal(t, "{}", w.Output)
}

func mustNewContext(t *testing.T) aetest.Context {
	c, err := aetest.NewContext(nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustPut(t *testing.T, c aetest.Context, v interface{}) {
	key := configKey(c)
	if _, err := datastore.Put(c, key, v); err != nil {
		t.Fatal(err)
	}
}

func Test_datastoreRestGet(t *testing.T) {
	c := mustNewContext(nil)
	defer c.Close()
	var cfg Config
	var w = mockResponseWriter{t: t}
	datastoreRestGet(c, configKey(c), &w, &cfg)
	assert.Equal(t, `{"Error":"datastore: no such entity"}`, w.Output)
	w.Output = ""
	cfg.ClientSecret = "foo"
	mustPut(t, c, &cfg)
	datastoreRestGet(c, configKey(c), &w, &cfg)
	assert.Equal(t, `{"ClientId":"","ClientSecret":"foo","Whitelist":null}`, w.Output)
}
