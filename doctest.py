from ghia import cli
from ghia.cli import Cli


strategy = 'append'
gh = {'token': ''}
dry = True

rules = {}
rules['patterns'] = {'Nejakej profik': 'any:python'}
rules['fallback'] = {'label': 'Need assignment'}

issue1 = {
    'state': 'open',
    'title': 'Python problem',
    'body': 'python problem',
    'labels': [],
    'assignees': [{'login': 'Nejakej jouda'}]
    }

issue2 = {
    'state': 'open',
    'title': 'Bug',
    'body': 'Mas tam bug troubo!',
    'labels': [],
    'assignees': []
    }

reposlug = 'user/repo'
url1 = 'https://github.com/user/repo/issues/1'
url2 = 'https://github.com/user/repo/issues/2'

Cli.print_issue(reposlug, 1, url1)
cli.assign_issue(issue1, rules, 'change', dry, gh, reposlug)

Cli.print_issue(reposlug, 2, url2)
cli.assign_issue(issue2, rules, 'append', dry, gh, reposlug)