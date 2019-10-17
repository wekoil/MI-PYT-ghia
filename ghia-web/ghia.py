import click
import os
import configparser
import sys
import requests
import re
from flask import Flask, render_template, jsonify, request, abort
import hashlib
import hmac
import json

app = Flask(__name__)


# functions for validating params
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
        config.optionxform = str
        with open(value) as f:
            config.read_file(f)
        return config
    except:
        raise click.BadParameter('incorrect configuration format')

def validate_reposlug(ctx, param, value):
    try:
        owner, repository = value.split('/')
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

    # setup session
    session = requests.Session()
    session.headers = {'User-Agent': 'Python'}
    token = auth['github']['token']
    def token_auth(req):
        req.headers['Authorization'] = f'token {token}'
        return req
    session.auth = token_auth

    issues = get_issues(reposlug, session)

    # process all issues
    for issue in issues:
        click.echo('-> {} ({})'.format(click.style(reposlug + '#' + str(issue.get('number')), bold=True, fg='white'), issue.get('html_url')))
        assign_issue(issue, rules, strategy, dry, session, reposlug)
    

def print_users(strategy, new_users, old_users):
    """Print old and new assignees depending on chosen strategy"""

    all_users = list(set([*new_users, *old_users]))
    
    if (strategy == 'append'):
        for user in sorted(all_users, key=str.casefold):
            if (user in old_users and user in new_users):
                click.echo('   {} {}'.format(click.style('=', bold=True, fg='blue'), user))
                continue
            if (user in old_users):
                click.echo('   {} {}'.format(click.style('=', bold=True, fg='blue'), user))
                continue
            if (user in new_users):
                click.echo('   {} {}'.format(click.style('+', bold=True, fg='green'), user))
                continue
        return

    if (strategy == 'set'):
        if (len(old_users) > 0):
            for user in sorted(list(set([*old_users]))):
                click.echo('   {} {}'.format(click.style('=', bold=True, fg='blue'), user))
            return

        if (len(new_users) > 0):
            for user in sorted(list(set([*new_users]))):
                click.echo('   {} {}'.format(click.style('+', bold=True, fg='green'), user))
            return
        
    if (strategy == 'change'):
        for user in sorted(all_users, key=str.casefold):
            if (user in old_users and user in new_users):
                click.echo('   {} {}'.format(click.style('=', bold=True, fg='blue'), user))
                continue
            if (user in old_users):
                click.echo('   {} {}'.format(click.style('-', bold=True, fg='red'), user))
                continue
            if (user in new_users):
                click.echo('   {} {}'.format(click.style('+', bold=True, fg='green'), user))
                continue
        return


def append_users(issue, dry, session, new_users, old_users, reposlug):
    """Add new assignees to the old ones"""

    if not dry and len(new_users) > 0 and not (session.patch(issue.get('url'), json={"assignees": [*old_users, *new_users]})).ok:
        click.echo('   {}: Could not update issue {}#{}'.format(click.style('ERROR', fg='red'), reposlug, issue.get('number')), file=sys.stderr)
    else:
        print_users('append', new_users, old_users)


def set_users(issue, dry, session, new_users, old_users, reposlug):
    """Sets new assignees if the assignees are empty"""

    if (len(old_users) > 0):
        print_users('set', [], old_users)
        return

    if not dry and len(new_users) > 0 and not (session.patch(issue.get('url'), json={"assignees": [*new_users]})).ok:
        click.echo('   {}: Could not update issue {}#{}'.format(click.style('ERROR', fg='red'), reposlug, issue.get('number')), file=sys.stderr)
    else:
        print_users('set', new_users, [])
    

def change_users(issue, dry, session, new_users, old_users, reposlug):
    """Changes all assignees to the new ones"""

    if not dry and new_users != old_users and not (session.patch(issue.get('url'), json={"assignees": [*new_users]})).ok:
        click.echo('   {}: Could not update issue {}#{}'.format(click.style('ERROR', fg='red'), reposlug, issue.get('number')), file=sys.stderr)
    else:
        print_users('change', new_users, old_users)


def assign_issue(issue, rules, strategy, dry, session, reposlug):
    """Take issue and sets assignees depending on chosen strategy"""

    new_users = []
    old_users = []
    for i in issue.get('assignees'):
        old_users.append(i['login'])

    # parsing rules from config file
    for user in rules['patterns']:
        for rule in rules['patterns'][user].split('\n'):
            if (rule.split(':', 1)[0] == 'any'):
                if issue.get('title') is not None:
                    if re.search(rule.split(':', 1)[-1].lower(), issue.get('title').lower()):
                        new_users.append(user)

                if issue.get('labels') is not None:
                    for label in issue.get('labels'):
                        if re.search(rule.split(':', 1)[-1].lower(), label['name'].lower()):
                            new_users.append(user)
                        

                if issue.get('body') is not None:
                    if re.search(rule.split(':', 1)[-1].lower(), issue.get('body').lower()):
                        new_users.append(user)

            if (rule.split(':', 1)[0] == 'title'):
                if issue.get('title') is not None:
                    if re.search(rule.split(':', 1)[-1].lower(), issue.get('title').lower()):
                        new_users.append(user)

            if (rule.split(':', 1)[0] == 'label'):
                if issue.get('labels') is not None:
                    for label in issue.get('labels'):
                        if re.search(rule.split(':', 1)[-1].lower(), label['name'].lower()):
                            new_users.append(user)

            if (rule.split(':', 1)[0] == 'text'):
                if issue.get('body') is not None:
                    if re.search(rule.split(':', 1)[-1].lower(), issue.get('body').lower()):
                        new_users.append(user)
                            
    # changing assignees
    if (strategy == 'change'):
        change_users(issue, dry, session, new_users, old_users, reposlug)
    if (strategy == 'set'):
        set_users(issue, dry, session, new_users, old_users, reposlug)
    if (strategy == 'append'):
        append_users(issue, dry, session, new_users, old_users, reposlug)
        
    users = []
    for i in issue.get('assignees'):
        users.append(i['login'])

    # setting labels if needed
    if (len(users) == 0):
        if 'fallback' in rules:
            new_labels = []
            for rule in rules['fallback']:
                new_labels.append(rules['fallback'][rule])

            old_labels = []
            if (issue.get('labels')):
                for label in issue.get('labels'):
                    old_labels.append(label['name'])

            if not dry:
                r = session.patch(issue.get('url'), json={"labels":[*new_labels, *old_labels]})
                if not r.ok:
                    click.echo('{} Could not update issue {}#{}'.format(click.style('ERROR', fg='red'), reposlug, issue.get('number')), file=sys.stderr)
                else:
                    for label in new_labels:
                        label_flag = False
                        for old_label in old_labels:
                            if re.search(label.lower(), old_label.lower()):
                                label_flag = True
                                break

                        if label_flag:
                            click.echo('   {}: already has label "{}"'.format(click.style('FALLBACK', bold=True, fg='yellow'), label))
                        else:
                            click.echo('   {}: added label "{}"'.format(click.style('FALLBACK', bold=True, fg='yellow'), label))
            else:
                for label in new_labels:
                    label_flag = False
                    for old_label in old_labels:
                        if re.search(label.lower(), old_label.lower()):
                            label_flag = True
                            break

                    if label_flag:
                        click.echo('   {}: already has label "{}"'.format(click.style('FALLBACK', bold=True, fg='yellow'), label))
                    else:
                        click.echo('   {}: added label "{}"'.format(click.style('FALLBACK', bold=True, fg='yellow'), label))


def get_issues(reposlug, session):
    """Download issues from reposlug"""

    owner, repository = reposlug.split('/')
    r = session.get('https://api.github.com/repos/{}/{}/issues'.format(owner, repository))

    if not r.ok:
        click.echo('{}: Could not list issues for repository {}'.format(click.style('ERROR', fg='red'), reposlug), file=sys.stderr)
        sys.exit(10)

    issues = r.json()
    
    while(r.links.get('next')):
        next = r.links["next"]["url"]
        r = session.get(next)
        issues += r.json()
        if not r.ok:
            click.echo('{}: Could not list issues for repository {}'.format(click.style('ERROR', fg='red'), reposlug), file=sys.stderr)
            sys.exit(10)

    return issues
    
##############################################################################################
    # Flask webserver below

def load_config_files():
    try:
        conf_files = os.environ['GHIA_CONFIG'].split(':')
    except:
        try:
            conf_files = [os.environ['GHIA_CONFIG']]
        except KeyError:
            raise RuntimeError('You must set GHIA_CONFIG environ var')
    return conf_files
    

def get_rules_from_config(value = None):
    config = configparser.ConfigParser()
    config.optionxform = str
    for fil in load_config_files():
        try:
            with open(fil) as f:
                config.read_file(f)

                if value != None and value in config:
                    return config[value]
                if value == None and 'patterns' in config:
                    return config
        except:
            pass
    return None

def get_token_from_config():
    config = configparser.ConfigParser()
    config.optionxform = str
    for fil in load_config_files():
        try:
            with open(fil) as f:
                config.read_file(f)

                return config['github']['token']
        except:
            pass
    return None


def get_user_by_token():
    token = get_token_from_config()
    if token != None:
        session = requests.Session()
        session.headers = {'User-Agent': 'Python'}
        def token_auth(req):
            req.headers['Authorization'] = f'token {token}'
            return req

        session.auth = token_auth
        r = session.get('https://api.github.com/user')
        return r.json().get('login')

    return None


def verify_signature(req):
    secret = get_rules_from_config('github').get('secret')
    if secret == None:
        return True

    header_signature = req.headers.get('X-Hub-Signature')
    if header_signature is None:
        return False

    sha_name, signature = header_signature.split('=')
    if sha_name != 'sha1':
        return False

    mac = hmac.new(bytes(secret, encoding='ascii'), msg=req.data, digestmod='sha1').hexdigest()
    print(mac)
    if not str(mac) == str(signature):
        return False
    return True


@app.route('/', methods=['POST'])
def webhook():
    if request.method == 'POST' and ( request.headers.get('X-GitHub-Event') == 'ping' or request.headers.get('X-GitHub-Event') == 'issues' ):
        if not verify_signature(request):
            return 'Invalid signature!', 400
        if request.headers.get('X-GitHub-Event') == 'issues':
            available_actions = ['opened', 'edited', 'transferred', 'reopened', 'assigned', 'unassigned', 'labeled', 'unlabeled']
            if request.json.get('action') in available_actions:
                session = requests.Session()
                session.headers = {'User-Agent': 'Python'}

                token = get_token_from_config()
                def token_auth(req):
                    req.headers['Authorization'] = f'token {token}'
                    return req
                session.auth = token_auth
                
                rules = get_rules_from_config()

                reposlug = request.json.get('repository').get('full_name')
                issue_number = request.json.get('issue').get('number')
                issue_url = request.json.get('issue').get('url')

                click.echo('-> {} ({})'.format(click.style(reposlug + '#' + str(issue_number), bold=True, fg='white'), issue_url))

                r = session.get(issue_url)

                if not r.ok:
                    click.echo('{}: Could not list issues for repository {}'.format(click.style('ERROR', fg='red'), reposlug), file=sys.stderr)
                    sys.exit(10)

                assign_issue(r.json(), rules, 'append', '', session, reposlug)

        return '', 200
    else:
        abort(400)

@app.route('/')
def index():
    name = get_user_by_token()
    paterns = get_rules_from_config('patterns')
    fallback = get_rules_from_config('fallback')
    return render_template('index.html', name=name, rules=paterns, fallback=fallback)


if __name__ == '__main__':
    run()