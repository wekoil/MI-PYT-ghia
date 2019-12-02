from ghia.github import GitHub
import pytest
from ghia import cli
import os

import betamax

with betamax.Betamax.configure() as config:
    # tell Betamax where to find the cassettes
    # make sure to create the directory
    config.cassette_library_dir = 'test_all/fixtures/cassettes'

    auth = cli.validate_auth("ctx", "param", "credentials.cfg")
    TOKEN = auth['github']['token']

    config.define_cassette_placeholder('<TOKEN>', TOKEN)

try:
	user = 'wekoil'
	repo = f'mi-pyt-ghia/{user}'
except KeyError:
	raise RuntimeError('You must set GITHUB_USER environ var')

@pytest.fixture
def connection(betamax_session):
	return GitHub(TOKEN, session = betamax_session)


def test_connection(connection):
	assert connection.get_user_by_token() == user


def test_get_issues(connection, capsys):
	connection.get_issues(repo)
	cp = capsys.readouterr()
	assert not cp.err
