import random, yaml, os, flask, mwoauth, requests

from qwikidata.linked_data_interface import get_entity_dict_from_api
from requests_oauthlib import OAuth1

app = flask.Flask(__name__)
__dir__ = os.path.dirname(__file__)
app.config.update(yaml.safe_load(open(os.path.join(__dir__, 'config.yaml'))))

with open('Qs.txt', 'r') as file:
    Qs = [line.replace('\n', '') for line in file.readlines()]
    random.shuffle(Qs)


def get_labels(rec=10):
    if rec < 0 or not Qs:
        return None, None
    print(len(Qs))
    Q = Qs.pop()
    dict = get_entity_dict_from_api(Q)
    labels = []
    if 'labels' in dict:
        if 'hy' in dict['labels']:
            return get_labels(rec - 1)
        for lang in dict['labels']:
            temp = dict['labels'][lang]
            if 'descriptions' in dict and lang in dict['descriptions']:
                temp['description'] = dict['descriptions'][lang]['value']
            if 'sitelinks' in dict and lang + 'wiki' in dict['sitelinks']:
                temp['url'] = dict['sitelinks'][lang + 'wiki']['url']
            labels.append(dict['labels'][lang])
    return Q, labels


def save_label(Q, label):
    auth1 = OAuth1(app.config['CONSUMER_KEY'],
                   client_secret=app.config['CONSUMER_SECRET'],
                   resource_owner_key=flask.session['access_token']['key'],
                   resource_owner_secret=flask.session['access_token']['secret'])
    token = requests.get("https://www.wikidata.org/w/api.php", params={
        "action": "query",
        "format": "json",
        "meta": "tokens"
    },
                         auth=auth1)
    csrftoken = token.json()['query']['tokens']['csrftoken']
    response = requests.post(
        "https://www.wikidata.org/w/api.php",
        data={
            "action": "wbsetlabel",
            "token": csrftoken,
            "format": "json",
            "id": Q,
            "language": "hy",
            "value": label
        },
        auth=auth1
    )
    return csrftoken, response


@app.route('/', methods=['POST', 'GET'])
def index():
    username = flask.session.get('username', None)
    if username:

        if flask.request.method == 'POST':
            print(flask.request.form)
            if flask.request.form['action'] == 'save' and flask.request.form['hylabel']:
                save_label(flask.request.form['Q'], flask.request.form['hylabel'])
            Q, labels = get_labels()
            if not Q:
                return flask.render_template('error.html',
                                             error={'msg': 'Չթարգմանված տարր չի գտնվել։ Խնդրում ենք փորձել ավելի ուշ։'})
            return flask.render_template('main.html', labels=labels, Q=Q, username=username)

        if flask.request.method == 'GET':
            Q, labels = get_labels()
            if not Q:
                return flask.render_template('error.html',
                                             error={'msg': 'Չթարգմանված տարր չի գտնվել։ Խնդրում ենք փորձել ավելի ուշ։'})
            else:
                return flask.render_template('main.html', labels=labels, Q=Q, username=username)

    return flask.render_template('main.html')


@app.route('/login')
def login():
    """Initiate an OAuth login.

    Call the MediaWiki server to get request secrets and then redirect the
    user to the MediaWiki server to sign the request.
    """
    consumer_token = mwoauth.ConsumerToken(
        app.config['CONSUMER_KEY'], app.config['CONSUMER_SECRET'])
    try:
        redirect, request_token = mwoauth.initiate(
            app.config['OAUTH_MWURI'], consumer_token)
    except Exception:
        app.logger.exception('mwoauth.initiate failed')
        return flask.redirect(flask.url_for('index'))
    else:
        flask.session['request_token'] = dict(zip(
            request_token._fields, request_token))
        return flask.redirect(redirect)


@app.route('/oauth-callback')
def oauth_callback():
    """OAuth handshake callback."""
    if 'request_token' not in flask.session:
        flask.flash(u'OAuth callback failed. Are cookies disabled?')
        return flask.redirect(flask.url_for('index'))

    consumer_token = mwoauth.ConsumerToken(
        app.config['CONSUMER_KEY'], app.config['CONSUMER_SECRET'])

    try:
        access_token = mwoauth.complete(
            app.config['OAUTH_MWURI'],
            consumer_token,
            mwoauth.RequestToken(**flask.session['request_token']),
            flask.request.query_string)

        identity = mwoauth.identify(
            app.config['OAUTH_MWURI'], consumer_token, access_token)
    except Exception:
        app.logger.exception('OAuth authentication failed')
    else:
        flask.session['access_token'] = dict(zip(
            access_token._fields, access_token))
        flask.session['username'] = identity['username']

    return flask.redirect(flask.url_for('index'))


@app.route('/logout')
def logout():
    """Log the user out by clearing their session."""
    flask.session.clear()
    return flask.redirect(flask.url_for('index'))
