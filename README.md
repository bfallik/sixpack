sixpack
=======

geeky fun with beer


Notes
-----
* remember to use the goapp tool and not the go tool directly

* to view the files being uploaded:
  $ path/to/go_appengine/appcfg.py update --noisy .


Bootstrap
---------

set the API keys: PUT http://<HOST>/api/admin/config

```
{
  "client_id" : "XXX",
  "client_secret": "XXX"
}
```

create a new token: POST http://<HOST>/api/admin/user-tokens

```
{
    "ID": 5629499534213120,
    "Hash": "d5d84d34-93c7-47c9-8667-2852f5c995af"
}
```

browse to http://<HOST>/new-user?token=d5d84d34-93c7-47c9-8667-2852f5c995af
