from ghia import cli
from ghia.cli import Cli
import pytest
import os


def test_cli_conf_file(capsys):
	with pytest.raises(Exception) as excinfo:   
		cli.is_empty_file("test_all/empty.cfg")
	cp = capsys.readouterr()
	assert not cp.out
	assert 'incorrect configuration format' in str(excinfo.value)


	cli.is_empty_file("rules.cfg")
	cp = capsys.readouterr()
	assert not cp.err


def test_validate_auth(capsys):
	cli.validate_auth("ctx", "param", "rules.cfg")
	cp = capsys.readouterr()
	assert not cp.err

	with pytest.raises(Exception) as excinfo:  
		cli.validate_auth("ctx", "param", "")
	cp = capsys.readouterr()
	assert not cp.out
	assert 'incorrect configuration format' in str(excinfo.value)


def test_validate_rules(capsys):
	cli.validate_rules("ctx", "param", "rules.cfg")
	cp = capsys.readouterr()
	assert not cp.err


	with pytest.raises(Exception) as excinfo:  
		cli.validate_rules("ctx", "param", "")
	cp = capsys.readouterr()
	assert not cp.out
	assert 'incorrect configuration format' in str(excinfo.value)

def test_validate_reposlug(capsys):
	cli.validate_reposlug("ctx", "param", "username/repo")
	cp = capsys.readouterr()
	assert not cp.err

	with pytest.raises(Exception) as excinfo:  
		cli.validate_reposlug("ctx", "param", "")
	cp = capsys.readouterr()
	assert not cp.out

	with pytest.raises(Exception) as excinfo:  
		cli.validate_reposlug("ctx", "param", "reposlug")
	cp = capsys.readouterr()
	assert not cp.out


@pytest.mark.parametrize(
	['strategy', 'new_users', 'old_users'],
	[('append', ['dog', 'lion', 'cat'], ['cat']),
	('set', '', ['cat']),
	('set', ['cat'], ''),
	('change', ['cat', 'dog'], ['dog']),
	('change', '', ['dog']),
	('change', ['cat'], ['cat', 'dog']),

	])
def test_print_users(capsys, strategy, new_users, old_users):
	Cli.print_users(strategy, new_users, old_users)
	captured = capsys.readouterr()
	if strategy == 'append':
		for user in new_users:
			if user in old_users:
				assert '= {}'.format(user) in captured.out
			else:
				assert '+ {}'.format(user) in captured.out

	if strategy == 'set':
		for user in new_users:
			assert '+ {}'.format(user) in captured.out
		for user in old_users:
			assert '= {}'.format(user) in captured.out

	if strategy == 'change':
		for user in new_users:
			if user in old_users:
				assert '= {}'.format(user) in captured.out
			else:
				assert '+ {}'.format(user) in captured.out
			
		for user in old_users:
			if not user in new_users:
				assert '- {}'.format(user) in captured.out

from ghia.github import GitHub
import betamax

with betamax.Betamax.configure() as config:
    # tell Betamax where to find the cassettes
    # make sure to create the directory
    config.cassette_library_dir = 'test_all/fixtures/cassettes'

    auth = cli.validate_auth("ctx", "param", "credentials.cfg")
    TOKEN = auth['github']['token']

    config.define_cassette_placeholder('<TOKEN>', TOKEN)

try:
	user = os.environ['GITHUB_USER']
	repo = f'mi-pyt-ghia/{user}'
except KeyError:
	raise RuntimeError('You must set GITHUB_USER environ var')

@pytest.fixture
def connection(betamax_session):
	return GitHub(TOKEN, session = betamax_session)

@pytest.fixture
def issue(connection):
	r = connection.issue('https://api.github.com/repos/mi-pyt-ghia/wekoil/issues/120')
	return r.json()

@pytest.fixture
def label_issue(connection):
	r = connection.issue('https://api.github.com/repos/mi-pyt-ghia/wekoil/issues/119')
	return r.json()

def test_append_users(issue, connection, capsys):
	Cli.append_users(issue, True, connection, [user], [], repo)
	captured = capsys.readouterr()
	assert user in captured.out
	assert '+' in captured.out or '=' in captured.out

	Cli.append_users(issue, False, connection, [user], [], repo)
	captured = capsys.readouterr()
	assert user in captured.out
	assert '+' in captured.out or '=' in captured.out

def test_change_users(issue, connection, capsys):
	Cli.change_users(issue, False, connection, [], [user], repo)
	captured = capsys.readouterr()
	assert user in captured.out
	assert '-' in captured.out

	Cli.set_users(issue, False, connection, [user], [], repo)
	captured = capsys.readouterr()
	assert user in captured.out
	assert '+' in captured.out

	Cli.set_users(issue, False, connection, [user], [user], repo)
	captured = capsys.readouterr()
	assert user in captured.out
	assert '=' in captured.out

def test_set_users(issue, connection, capsys):
	Cli.set_users(issue, False, connection, [user], [user], repo)
	captured = capsys.readouterr()
	assert user in captured.out
	assert '=' in captured.out

	Cli.set_users(issue, False, connection, [user], [], repo)
	captured = capsys.readouterr()
	assert user in captured.out
	assert '+' in captured.out

def test_assign_issue(label_issue, issue, connection, capsys):
	cli.assign_issue(issue, cli.validate_rules("ctx", "param", "rules.cfg"), 'append', False, connection, 'mi-pyt-ghia/wekoil')
	captured = capsys.readouterr()
	assert user in captured.out
	assert '=' in captured.out

	cli.assign_issue(label_issue, cli.validate_rules("ctx", "param", "rules.cfg"), 'append', True, connection, 'mi-pyt-ghia/wekoil')
	captured = capsys.readouterr()
	assert 'FALLBACK: added label "Need assignment"' in captured.out
