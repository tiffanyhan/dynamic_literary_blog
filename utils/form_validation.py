import re


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_username(username):
    '''
    checks that a valid username was entered
    '''
    return username and USER_RE.match(username)


def valid_password(password):
    '''
    checks that a valid password was entered
    '''
    return password and PASSWORD_RE.match(password)


def valid_email(email):
    '''
    checks that either an email was not entered or
    if it was, that a valid one was entered
    '''
    return not email or EMAIL_RE.match(email)
