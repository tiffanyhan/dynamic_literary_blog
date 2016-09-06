from google.appengine.ext import db
from templates import template_dir, jinja_env


def users_key(name='default'):
    '''
    returns a key to be used as the parent for each
    user instance created
    '''
    return db.Key.from_path('/', name)


def blog_key(name='default'):
    '''
    returns a key to be used as the parent for each
    submission instance created
    '''
    return db.Key.from_path('/', name)


def render_str(template, **params):
    '''
    a global version of render_str that is available
    to functions that don't inherit from Handler
    '''
    t = jinja_env.get_template(template)
    return t.render(params)
