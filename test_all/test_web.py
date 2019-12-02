from ghia.web import Web
import pytest
import os
import flexmock
import requests
import importlib

def test_load_config_files(capsys):
	with pytest.raises(Exception) as excinfo:   
		Web.load_config_files()
	cp = capsys.readouterr()
	assert not cp.out
	assert 'You must set GHIA_CONFIG environ var' in str(excinfo.value)

	os.environ['GHIA_CONFIG'] = 'rules.cfg'
	Web.load_config_files()
	cp = capsys.readouterr()
	assert not cp.err

def test_get_rules_from_config(capsys):
	os.environ['GHIA_CONFIG'] = ''
	assert Web.get_rules_from_config() == None

	os.environ['GHIA_CONFIG'] = 'rules.cfg'
	assert Web.get_rules_from_config() != None
	cp = capsys.readouterr()
	assert not cp.err

def test_get_token_from_config(capsys):
	os.environ['GHIA_CONFIG'] = ''
	assert Web.get_token_from_config() == None

	os.environ['GHIA_CONFIG'] = 'credentials.cfg'
	assert Web.get_token_from_config() != None
	cp = capsys.readouterr()
	assert not cp.err


def test_verify_signature(capsys):
	assert Web.verify_signature('')

	os.environ['GHIA_CONFIG'] = 'secret.cfg'
	req = flexmock(requests.Response(), headers={'X-Hub-Signature': 'sha1=8dd7186bd499f38cfe5f3b829e9f931f105e760f'})
	req.data=b'nevim'
	assert Web.verify_signature(req)

	req.data=b'neplatne'
	assert not Web.verify_signature(req)
	
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

def test_ping_pongs():
	os.environ['GHIA_CONFIG'] = 'secret.cfg'
	app = _test_app()
	rv = app.post('/', json=PING, headers={
		'X-Hub-Signature': 'sha1=b025077e5b1f972113e2aa1e83ecc45f2b6aaee9',
		'X-GitHub-Event': 'ping'})
	assert rv.status_code == 200


def test_bad_secret():
	os.environ['GHIA_CONFIG'] = 'secret.cfg'
	app = _test_app()
	rv = app.post('/', json=PING, headers={
		'X-Hub-Signature': 'sha1=1cacacc4207bdd4a51a7528bd9a5b9d6546b0c22',
		'X-GitHub-Event': 'ping'})
	assert rv.status_code >= 400


