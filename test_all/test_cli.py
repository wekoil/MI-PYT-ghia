from ghia import cli
from ghia.cli import Cli
import pytest
import sys
import shlex


def test_cli_conf_file(capsys):
	with pytest.raises(Exception) as excinfo:   
		cli.is_empty_file("test_all/empty.cfg")
	cp = capsys.readouterr()
	assert not cp.out
	assert 'incorrect configuration format' in str(excinfo.value)


	cli.is_empty_file("rules.cfg")
	cp = capsys.readouterr()
	assert not cp.err

# @pytest.mark.parametrize('foo', ("cli.validate_auth", "cli.validate_rules"))
def test_validate_auth():
	try:
		cli.validate_auth("ctx", "param", "rules.cfg")
	except:
		assert 0
	else:
		assert 1

	try:
		cli.validate_auth("ctx", "param", "")
	except:
		assert 1
	else:
		assert 0

def test_validate_rules():
	try:
		cli.validate_rules("ctx", "param", "rules.cfg")
	except:
		assert 0
	else:
		assert 1

	try:
		cli.validate_rules("ctx", "param", "")
	except:
		assert 1
	else:
		assert 0

def test_validate_reposlug():
	try:
		cli.validate_reposlug("ctx", "param", "username/repo")
	except:
		assert 0
	else:
		assert 1

	try:
		cli.validate_reposlug("ctx", "param", "")
	except:
		assert 1
	else:
		assert 0

	try:
		cli.validate_reposlug("ctx", "param", "reposlug")
	except:
		assert 1
	else:
		assert 0

# def test_run():



	# ('append', 'set', 'change')
# 	
# @pytest.mark.parametrize('new_users', ('lion', ['cat', 'bear']))
# @pytest.mark.parametrize('old_users', ('octocat', 'cat', ['dog', 'rafan']))


# @pytest.mark.parametrize('strategy', ('append', 'set', 'change'))
# @pytest.mark.parametrize('new_users', ('lion', ['cat', 'bear']))
# @pytest.mark.parametrize('old_users', ('octocat', 'cat', ['dog', 'rafan']))

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

# # here we test only dry functionality coz we will test set_assignees in github tests
# def test_append_users():
# 	cli.append_users(issue, dry, gh, new_users, old_users, reposlug)

# from ghia.github import GitHub

# class GHConnection:
# 	def __init__(self, token):
# 		gh = GitHub(token)

# @pytest.fixture
