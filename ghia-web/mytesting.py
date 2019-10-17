import requests
import atexit
import contextlib
import os
import pathlib
import requests
import shlex
import subprocess
import sys
import importlib

@contextlib.contextmanager
def env(**kwargs):
    original = {key: os.getenv(key) for key in kwargs}
    os.environ.update({key: str(value) for key, value in kwargs.items()})
    try:
        yield
    finally:
        for key, value in original.items():
            if value is None:
                del os.environ[key]
            else:
                os.environ[key] = value

def _import_app():
    import ghia
    importlib.reload(ghia)  # force reload (config could change)
    if hasattr(ghia, 'app'):
        return ghia.app
    elif hasattr(ghia, 'create_app'):
        return ghia.create_app(None)
    else:
        raise RuntimeError(
            "Can't find a Flask app. "
            "Either instantiate `ghia.app` variable "
            "or implement `ghia.create_app(dummy)` function. "
            "See https://flask.palletsprojects.com/en/1.1.x/patterns/appfactories/"
            "for additional information."
        )

def _test_app():
    app = _import_app()
    app.config['TESTING'] = True
    return app.test_client()

PING = {
    'zen': 'Keep it logically awesome.',
    'hook_id': 123456,
    'hook': {
        'type': 'Repository',
        'id': 55866886,
        'name': 'web',
        'active': True,
        'events': [
            'issues',
        ],
        'config': {
            'content_type': 'json',
            'insecure_ssl': '0',
            'secret': '********',
        },
    },
    'repository': {
        'id': 123456,
        'name': 'ghia',
        'full_name': 'cvut/ghia',
        'private': False,
    },
    'sender': {
        'login': 'user',
    },
}

# with env(GHIA_CONFIG='credentials.cfg:rules.cfg'):
#     app = _test_app()
#     rv = app.post('/', json=PING, headers={
#         'X-Hub-Signature': 'sha1=d00e131ec9215b2a349ea1541e01e1a84ac38d8e',
#         'X-GitHub-Event': 'ping'})
#     print(rv.status_code)

wh = {
  "action": "opened",
  "issue": {
    "url": "https://api.github.com/repos/mi-pyt-ghia/wekoil-web/issues/1",
    "number": 1,
  },
  "repository" : {
    "id": 1296269,
    "full_name": "mi-pyt-ghia/wekoil-web",
    "owner": {
      "login": "octocat",
      "id": 1,
    },
  },
  "sender": {
    "login": "octocat",
    "id": 1,
  }
}

header = {
    'Host': 'localhost:4567',
    'X-GitHub-Delivery': '72d3162e-cc78-11e3-81ab-4c9367dc0958',
    'X-Hub-Signature': 'sha1=aed62caf5a360ad315b16ed6ac09e9c465b69da5',
    'User-Agent': 'GitHub-Hookshot/044aadd',
    'Content-Type': 'application/json',
    'Content-Length': '6615',
    'X-GitHub-Event': 'issues'
}

with env(GHIA_CONFIG='credentials.cfg:rules.cfg'):
    app = _test_app()
    rv = app.post('/', json=wh, headers=header)
    print(rv.status_code)