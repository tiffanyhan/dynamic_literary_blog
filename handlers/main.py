from google.appengine.ext import db
from handlers.handler import Handler


class MainHandler(Handler):
    def get(self):
        '''
        show all submissions on the main page
        '''
        submissions = db.GqlQuery('''
            SELECT * from Submission ORDER BY created DESC limit 10
        ''')

        self.render("main/main.html", submissions=submissions)
