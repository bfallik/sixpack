package beertasting

import (
	"appengine/aetest"
	"appengine/datastore"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	httptest "github.com/stretchr/testify/http"
	"net/http"
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
	httptest.TestResponseWriter
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
	status, err := datastoreRestGet(c, configKey(c), &cfg)
	assert.Equal(t, http.StatusInternalServerError, status)
	assert.Error(t, err)
	cfg.ClientSecret = "foo"
	mustPut(t, c, &cfg)
	status, err = datastoreRestGet(c, configKey(c), &cfg)
	assert.Equal(t, http.StatusOK, status)
	assert.NoError(t, err)
}
