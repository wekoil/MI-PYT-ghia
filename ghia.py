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

    session = requests.Session()
    session.headers = {'User-Agent': 'Python'}
    token = auth['github']['token']
    def token_auth(req):
        req.headers['Authorization'] = f'token {token}'
        return req
    session.auth = token_auth

    issues = get_issues(reposlug, session)

    for i in range(len(issues)):
        click.echo('-> {} ({})'.format(click.style(reposlug + '#' + str(issues[i].get('number')), bold=True, fg='white'), issues[i].get('html_url')))
        assign_issue(issues[i], rules, strategy, dry, session, reposlug)
    

def print_users(strategy, new_users, old_users):
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
    if not dry:
        if (len(new_users) > 0):
            r = session.patch(issue.get('url'), json={"assignees": [*old_users, *new_users]})
            if not r.ok:
                click.echo('   {}: Could not update issue {}#{}'.format(click.style('ERROR', fg='red'), reposlug, issue.get('number')), file=sys.stderr)
            else:
                print_users('append', new_users, old_users)
        else:
            print_users('append', new_users, old_users)
    else:
        print_users('append', new_users, old_users)

def set_users(issue, dry, session, new_users, old_users, reposlug):
    if (len(old_users) > 0):
        print_users('set', [], old_users)
        return

    if not dry:
        if (len(new_users) > 0):
            r = session.patch(issue.get('url'), json={"assignees": [*new_users]})
            if not r.ok:
                click.echo('   {}: Could not update issue {}#{}'.format(click.style('ERROR', fg='red'), reposlug, issue.get('number')), file=sys.stderr)
            else:
                print_users('set', new_users, [])
    else:
        print_users('set', new_users, [])
    
def change_users(issue, dry, session, new_users, old_users, reposlug):

    if not dry:
        if (new_users != old_users):
            r = session.patch(issue.get('url'), json={"assignees": [*new_users]})
            if not r.ok:
                click.echo('   {}: Could not update issue {}#{}'.format(click.style('ERROR', fg='red'), reposlug, issue.get('number')), file=sys.stderr)
            else:
                print_users('change', new_users, old_users)
        else:
            print_users('change', new_users, old_users)
    else:
        print_users('change', new_users, old_users)

def assign_issue(issue, rules, strategy, dry, session, reposlug):

    new_users = []
    old_users = []
    for i in issue.get('assignees'):
        old_users.append(i['login'])

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
                            
    if (strategy == 'change'):
        change_users(issue, dry, session, new_users, old_users, reposlug)

    if (strategy == 'set'):
        set_users(issue, dry, session, new_users, old_users, reposlug)

    if (strategy == 'append'):
        append_users(issue, dry, session, new_users, old_users, reposlug)
        
    users = []
    for i in issue.get('assignees'):
        users.append(i['login'])

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
    owner, repository = reposlug.split('/')
    
    r = session.get('https://api.github.com/repos/{}/{}'.format(owner, repository))

    if not r.ok:
        click.echo('{}: Could not list issues for repository {}'.format(click.style('ERROR', fg='red'), reposlug), file=sys.stderr)
        sys.exit(10)
    

    number_of_issues = r.json()['open_issues_count']
    issues = []
    next = 'https://api.github.com/repos/{}/{}/issues'.format(owner, repository)

    while(True):
        r = session.get(next)
        if not r.ok:
            click.echo('{}: Could not list issues for repository {}'.format(click.style('ERROR', fg='red'), reposlug), file=sys.stderr)
            sys.exit(10)

        issues += r.json()
        number_of_issues -= len(r.json())

        if (number_of_issues <= 0):
            break
        next = r.links["next"]["url"]
        
    return issues
    
    



if __name__ == '__main__':
    run()