#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from google.appengine.ext import db
from handlers.main import MainHandler
from handlers.users import SignUpHandler, LogInHandler, LogOutHandler, \
    WelcomeHandler
from handlers.submissions import SubmissionHandler, NewHandler, \
    EditPostHandler, DeletePostHandler
from handlers.comments import NewCommentHandler, EditCommentHandler, \
    DeleteCommentHandler
from handlers.likes import LikePostHandler

import webapp2

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/newpost', NewHandler),
    ('/([0-9]+)', SubmissionHandler),
    ('/signup', SignUpHandler),
    ('/welcome', WelcomeHandler),
    ('/login', LogInHandler),
    ('/logout', LogOutHandler),
    ('/([0-9]+)/edit', EditPostHandler),
    ('/([0-9]+)/delete', DeletePostHandler),
    ('/([0-9]+)/newcomment', NewCommentHandler),
    ('/([0-9]+)/comment/([0-9]+)/edit', EditCommentHandler),
    ('/([0-9]+)/comment/([0-9]+)/delete', DeleteCommentHandler),
    ('/([0-9]+)/like', LikePostHandler)
], debug=True)
