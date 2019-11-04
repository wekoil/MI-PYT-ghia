from flask import Flask, render_template, jsonify, request, abort
import flask
import hashlib
import hmac
import configparser
import os

from .cli import Cli
from .github import GitHub

class Web():
    @staticmethod
    def load_config_files():
        """Loads config files from env var"""
        try:
            conf_files = os.environ['GHIA_CONFIG'].split(':')
        except:
            try:
                conf_files = [os.environ['GHIA_CONFIG']]
            except KeyError:
                raise RuntimeError('You must set GHIA_CONFIG environ var')
        return conf_files

    @staticmethod
    def get_rules_from_config(value = None):
        config = configparser.ConfigParser()
        config.optionxform = str
        for fil in Web.load_config_files():
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

    @staticmethod
    def get_token_from_config():
        config = configparser.ConfigParser()
        config.optionxform = str
        for fil in Web.load_config_files():
            try:
                with open(fil) as f:
                    config.read_file(f)

                    return config['github']['token']
            except:
                pass
        return None

    @staticmethod
    def verify_signature(req):
        secret = Web.get_rules_from_config('github').get('secret')
        # If no issue is specified we accept the webhook
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

ghia_blueprint = flask.Blueprint('ghia', __name__)

@ghia_blueprint.route('/', methods=['POST'])
def webhook():
    # Accept only POST method and webhooks ping or issues
    if request.method == 'POST' and ( request.headers.get('X-GitHub-Event') == 'ping' or request.headers.get('X-GitHub-Event') == 'issues' ):
        # Signature must be same
        if not Web.verify_signature(request):
            return 'Invalid signature!', 400
        if request.headers.get('X-GitHub-Event') == 'issues':
            available_actions = ['opened', 'edited', 'transferred', 'reopened', 'assigned', 'unassigned', 'labeled', 'unlabeled']
            # Accept only some actions
            print(request.json.get('action'))
            if request.json.get('action') in available_actions:
                # Setup session and authorize
                gh = GitHub
                gh.init(Web.get_token_from_config())

                reposlug = request.json.get('repository').get('full_name')
                issue_number = request.json.get('issue').get('number')
                issue_url = request.json.get('issue').get('url')
                r = gh.issue(issue_url)

                if not r.ok:
                    Cli.can_not_list_issues(reposlug)

                if r.json().get('state') == 'closed':
                    return '', 200

                # proccess the issue
                Cli.print_issue(reposlug, issue_number, issue_url)
                assign_issue(r.json(), Web.get_rules_from_config(), 'append_from_webhook', '', session, reposlug)

        return '', 200
    else:
        abort(400)


@ghia_blueprint.route('/')
def index():
    # get name and rules from config file and pass them to the template
    gh = GitHub
    gh.init(Web.get_token_from_config())
    name = gh.get_user_by_token()
    paterns = Web.get_rules_from_config('patterns')
    fallback = Web.get_rules_from_config('fallback')
    return render_template('index.html.j2', name=name, rules=paterns, fallback=fallback)

def create_app(*args, **kwargs):
    app = flask.Flask(__name__)

    app.register_blueprint(ghia_blueprint)

    return app