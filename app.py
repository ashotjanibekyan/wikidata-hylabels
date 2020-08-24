import datetime

import flask
import mwoauth
import os
import random
import requests
import yaml
from collections import deque

from flask import jsonify
from qwikidata.linked_data_interface import get_entity_dict_from_api
from requests_oauthlib import OAuth1
from flask_sqlalchemy import SQLAlchemy

app = flask.Flask(__name__)
__dir__ = os.path.dirname(__file__)
app.config.update(yaml.safe_load(open(os.path.join(__dir__, 'config.yaml'))))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)
API_URL = 'https://hy.wikipedia.org/w/api.php'


class WikiDataItems(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    q = db.Column(db.String(20), nullable=False, unique=True)

    def __repr__(self):
        return self.q


class Done(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    q = db.Column(db.String(20), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    add_time = db.Column(db.DateTime, nullable=False,
                         default=datetime.datetime.utcnow)
    action = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return 'Username: ' + str(self.username) + ', q: ' + str(self.q) + ', add_time: ' + str(
            self.add_time) + ', action: ' + str(self.action) + ', id: ' + str(self.id)


def first_edit_date(user):
    r = requests.get(API_URL, params={
        "action": "query",
        "format": "json",
        "list": "usercontribs",
        "uclimit": "1",
        "ucuser": user,
        "ucdir": "newer",
        "ucprop": "timestamp"
    })
    jsn = r.json()
    if 'query' in jsn and 'usercontribs' in jsn['query'] and jsn['query']['usercontribs']:
        return datetime.datetime.strptime(jsn['query']['usercontribs'][0]['timestamp'], "%Y-%m-%dT%H:%M:%SZ")
    return None


def registration_date(user):
    r = requests.get(API_URL, params={
        "action": "query",
        "format": "json",
        "list": "users",
        "usprop": "registration",
        "ususers": user
    })
    jsn = r.json()
    if 'query' in jsn and 'users' in jsn['query'] and 'registration' in jsn['query']['users'][0]:
        if jsn['query']['users'][0]['registration']:
            return datetime.datetime.strptime(jsn['query']['users'][0]['registration'], "%Y-%m-%dT%H:%M:%SZ")
        else:
            return first_edit_date(user)
    return None


def get_labels(username, rec=10):
    if rec < 0:
        return None, None
    Q = str(random.choice(WikiDataItems.query.all()))
    if Done.query.filter_by(username=username, q=Q).all():
        return get_labels(username, rec - 1)
    dict = get_entity_dict_from_api(Q)
    labels = []
    hydesc = 'հայերեն նկարագրություն չկա'
    if 'labels' in dict:
        if 'hy' in dict['labels']:
            return get_labels(username, rec - 1)
        if 'hy' in dict['descriptions']:
            hydesc = dict['descriptions']['hy']['value']
        for lang in dict['labels']:
            temp = dict['labels'][lang]
            if 'descriptions' in dict and lang in dict['descriptions']:
                temp['description'] = dict['descriptions'][lang]['value']
            if 'sitelinks' in dict and lang + 'wiki' in dict['sitelinks']:
                temp['url'] = dict['sitelinks'][lang + 'wiki']['url']
            labels.append(dict['labels'][lang])
    return Q, labels, hydesc


def get_csrf_token():
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
    csrf_token = token.json()['query']['tokens']['csrftoken']
    return auth1, csrf_token


def save_description(Q, desc):
    auth1, csrf_token = get_csrf_token()
    response = requests.post(
        "https://www.wikidata.org/w/api.php",
        data={
            "action": "wbsetdescription",
            "token": csrf_token,
            "format": "json",
            "id": Q,
            "language": "hy",
            "value": desc
        },
        auth=auth1
    )
    return csrf_token, response


def save_label(Q, label):
    data = get_entity_dict_from_api(Q)
    if 'labels' in data and 'hy' in data['labels']:
        WikiDataItems.query.filter_by(q=Q).delete()
        db.session.commit()
        return None
    auth1, csrf_token = get_csrf_token()
    response = requests.post(
        "https://www.wikidata.org/w/api.php",
        data={
            "action": "wbsetlabel",
            "token": csrf_token,
            "format": "json",
            "id": Q,
            "language": "hy",
            "value": label
        },
        auth=auth1
    )
    if response and 'success' in response.json() and response.json()['success']:
        WikiDataItems.query.filter_by(q=Q).delete()
        db.session.commit()
    return csrf_token, response


@app.errorhandler(Exception)
def handle_error(error):
    return flask.render_template('error.html', error=error)


@app.route('/', methods=['POST', 'GET'])
def index():
    def divide_labels(l):
        loved_langs = ['ru', 'en', 'fr', 'es', 'de', 'pl', 'it', 'hyw']
        d = deque()
        for label in l:
            if label['language'] in loved_langs:
                label['big'] = True
                d.appendleft(label)
            else:
                d.append(label)
        return list(d)

    username = flask.session.get('username', None)
    if username:
        if flask.request.method == 'POST':
            print(flask.request.form)
            if flask.request.form['action'] == 'save' and flask.request.form['hylabel']:
                save_label(flask.request.form['Q'], flask.request.form['hylabel'])
                action = Done(username=username, q=flask.request.form['Q'], action=1)
                db.session.add(action)
                db.session.commit()

            if flask.request.form['action'] == 'save' and flask.request.form['hydescription']:
                save_description(flask.request.form['Q'], flask.request.form['hydescription'])

            if flask.request.form['action'] == 'skip':
                action = Done(username=username, q=flask.request.form['Q'], action=0)
                db.session.add(action)
                db.session.commit()

            Q, labels, hydesc = get_labels(username)
            if not Q:
                return flask.render_template('error.html',
                                             error={'msg': 'Չթարգմանված տարր չի գտնվել։ Խնդրում ենք փորձել ավելի ուշ։'})
            return flask.render_template('main.html', labels=divide_labels(labels), Q=Q, hydesc=hydesc,
                                         username=username)

        if flask.request.method == 'GET':
            Q, labels, hydesc = get_labels(username)
            if not Q:
                return flask.render_template('error.html',
                                             error={'msg': 'Չթարգմանված տարր չի գտնվել։ Խնդրում ենք փորձել ավելի ուշ։'})
            else:
                return flask.render_template('main.html', labels=divide_labels(labels), Q=Q, hydesc=hydesc,
                                             username=username)

    return flask.render_template('main.html')


@app.route('/skipped', methods=['POST', 'GET'])
def skipped():
    username = flask.session.get('username', None)
    if username:
        user_skipped = Done.query.filter_by(username=username, action=0).all()
        return flask.render_template('skipped.html', username=username, user_skipped=user_skipped)
    return flask.render_template('main.html')


@app.route('/done', methods=['POST', 'GET'])
def done():
    username = flask.session.get('username', None)
    if username:
        user_done = Done.query.filter_by(username=username, action=1).all()
        return flask.render_template('done.html', username=username, user_done=user_done)
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

    regdate = registration_date(flask.session['username'])
    if regdate:
        delta = datetime.datetime.now() - regdate
        if delta.days >= 365:
            return flask.redirect(flask.url_for('index'))
    return flask.render_template('error.html', error={'msg': 'Ցավոք դուք չունեք բավարար վիքիստաժ (անհրաժեշտ է մեկ տարի)'})


@app.route('/logout')
def logout():
    """Log the user out by clearing their session."""
    flask.session.clear()
    return flask.redirect(flask.url_for('index'))
