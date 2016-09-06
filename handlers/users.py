from handlers.handler import Handler
from utils.form_validation import valid_username, valid_password, \
    valid_email
from models.user import User
from decorators.authentication import logout_required, \
    login_required_redirect_home, login_required_redirect_login


class SignUpHandler(Handler):
    @logout_required
    def get(self):
        '''
        renders the form to register
        '''
        self.render("users/signup.html")

    @logout_required
    def post(self):
        '''
        creates a new user instance and inserts it into the db.
        logs the user in, then redirects the user to the welcome page.

        if there are any errors, render the signup form again with
        the appropriate saved data and error messages
        '''
        have_error = False

        self.username = self.request.get("username").encode("latin-1")
        self.password = self.request.get("password").encode("latin-1")
        self.verify = self.request.get("verify").encode("latin-1")
        self.email = self.request.get("email").encode("latin-1")

        params = dict(username=self.username,
                      email=self.email)

        # check for any errors
        if not valid_username(self.username):
            params['username_error'] = "That's not a valid username"
            have_error = True
        elif User.by_name(self.username):
                params['username_error'] = 'That user already exists'
                have_error = True

        if not valid_password(self.password):
            params['password_error'] = "That's not a valid password"
            have_error = True
        elif self.password != self.verify:
            params['verify_error'] = "Your passwords don't match"

        if not valid_email(self.email):
            params['email_error'] = "That's not a valid email"
            have_error = True

        # there's some error(s)
        if have_error:
            self.render("users/signup.html", **params)
        # succest!!
        else:
            user = User.register(self.username, self.password, self.email)
            user.put()

            self.login(user)
            self.redirect('/welcome')


class LogInHandler(Handler):
    @logout_required
    def get(self):
        '''
        render the form to login
        '''
        self.render('users/login.html')

    @logout_required
    def post(self):
        '''
        check the information entered against information stored
        in the db.  if all is well, log the user in and redirect
        them to the welcome page.

        if not, render the login form again with an error message
        '''
        have_error = False

        username = self.request.get("username").encode("latin-1")
        password = self.request.get("password").encode("latin-1")

        user = User.login(username, password)

        if user:
            self.login(user)
            self.redirect('/welcome')
        else:
            error = 'Invalid login'
            self.render('users/login.html', error=error)


class LogOutHandler(Handler):
    @login_required_redirect_home
    def get(self):
        '''
        renders the logout page
        '''
        self.render('users/logout.html', username=self.user.username)

    @login_required_redirect_home
    def post(self):
        '''
        log the user out and redirect them to the signup page
        '''
        self.logout()
        self.redirect('/')


class WelcomeHandler(Handler):
    @login_required_redirect_login
    def get(self):
        '''
        renders the welcome page
        '''
        self.render("users/welcome.html", user=self.user)
