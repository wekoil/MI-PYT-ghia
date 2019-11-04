import requests

class GitHub:
    def __init__(self, token, session=None):
        self.token = token
        self.session = session or requests.Session()
        self.session.headers = {'User-Agent': 'Python'}
        self.session.auth = self.token_auth

    def token_auth(self, req):
        req.headers['Authorization'] = f'token {self.token}'
        return req

    def get_issues(self, reposlug):
        """Download issues from reposlug"""

        owner, repository = reposlug.split('/')
        r = self.session.get('https://api.github.com/repos/{}/{}/issues'.format(owner, repository))

        if not r.ok:
            return False

        issues = r.json()

        while(r.links.get('next')):
            next = r.links["next"]["url"]
            r = self.session.get(next)
            issues += r.json()
            if not r.ok:
                return False

        return issues

    def get_user_by_token(self):
        return self.session.get('https://api.github.com/user').json().get('login')

    def issue(self, url):
        return self.session.get(url)

    def set_labels(self, issue, new_labels, old_labels):
        return self.session.patch(issue.get('url'), json={"labels":[*new_labels, *old_labels]})

    def set_assignees(self, issue, new_assignees, old_assignees = None):
        if old_assignees == None:
            return (self.session.patch(issue.get('url'), json={"assignees": [*new_assignees]})).ok
        else:
            return (self.session.patch(issue.get('url'), json={"assignees": [*new_assignees, *old_assignees]})).ok

