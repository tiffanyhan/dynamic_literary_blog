import hmac

SECRET = 'imsosecret'


def hash_str(s):
    '''
    given some input, creates a hashed output.
    used for making secure cookie values
    '''
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    '''
    makes a secure cookie value
    '''
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    '''
    takes the unhashed part of the cookie.  if hashing it
    matches the entire cookie value, then the unhashed
    part of the cookie is returned
    '''
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val
