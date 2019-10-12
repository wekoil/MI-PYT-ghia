import click
import os
import configparser
import sys
import requests
import re


def is_empty_file(value):
    if (os.stat(value).st_size == 0):
        raise click.BadParameter('incorrect configuration format')

def validate_auth(ctx, param, value):
    try:
        is_empty_file(value)
        config = configparser.ConfigParser()
        with open(value) as f:
            config.read_file(f)
        return config
    except:
        raise click.BadParameter('incorrect configuration format')

def validate_rules(ctx, param, value):
    try:
        is_empty_file(value)
        config = configparser.ConfigParser()
        with open(value) as f:
            config.read_file(f)
        return config
    except:
        raise click.BadParameter('incorrect configuration format')

def validate_reposlug(ctx, param, value):
    try:
        owner, repository = value.split('/')
        # print(owner)
        # print(repository)
        return value
    except ValueError:
        raise click.BadParameter('not in owner/repository format')

@click.command()
@click.option('-s', '--strategy', default='append', show_default=True,
                type=click.Choice(['append', 'set', 'change'], case_sensitive=False),
                help='How to handle assignment collisions.')

@click.option('-d', '--dry-run', 'dry', is_flag=True, default=False, help='Run without making any changes.')

@click.option('-a', '--config-auth', 'auth', callback=validate_auth, metavar='FILENAME', required=True, help='File with authorization configuration.')

@click.option('-r', '--config-rules', 'rules', callback=validate_rules, metavar='FILENAME', required=True, help='File with assignment rules configuration.')

@click.argument('reposlug', nargs=1, required=True, callback=validate_reposlug)

def run(strategy, dry, auth, rules, reposlug):
    """CLI tool for automatic issue assigning of GitHub issues"""
    # print(auth['github']['token'])
    # print(rules['patterns']['MarekSuchanek'])

    session = requests.Session()
    session.headers = {'User-Agent': 'Python'}
    token = auth['github']['token']
    def token_auth(req):
        req.headers['Authorization'] = f'token {token}'
        return req
    session.auth = token_auth

    issues = get_issues(reposlug, session)
    assign_issue(issues[0], rules, strategy, dry, session)
    
class crule:
    def __init__(self, who, where, what):
        self.who = who
        self.where = where
        self.what = what

class crules:
    rules = []crule

    def add_rule(rule):
        rules.append(rule)


def assign_issue(issue, rules, strategy, dry, session):
    # print(issue.get('url'))
    # print(issue.get('title'))
    # print(issue.get('label'))
    # print(issue.get('text'))

    # print(rules['patterns'])

    print(rules.items('patterns'))
    my_rules = crules

    for user in rules['patterns']:
        # print(user)
        for rule in rules['patterns'][user].split('\n'):
            # print(rule.split(':', 1)[0], rule.split(':', 1)[1:])
            crules.add_rule(crule(user, rule.split(':', 1)[0], rule.split(':', 1)[1:]))
            # where, what = rule.split(':')
            # if what in issue.get(where):
            #     click.echo('neco')
    if 'fallback' in rules:
        for rule in rules['fallback']:
            print(rule, rules['fallback'][rule])

    

def get_issues(reposlug, session):
    owner, repository = reposlug.split('/')
    
    # print(owner)
    # print(repository)
    r = session.get('https://api.github.com/repos/{}/{}/issues'.format(repository, owner))
    # print(r)
    # print(r.json())
    if not r.ok:
        click.echo('{} Could not list issues for repository {}'.format(click.style('ERROR', fg='red'), repository), file=sys.stderr)
        exit(10)
    return r.json()
    
    



if __name__ == '__main__':
    run()