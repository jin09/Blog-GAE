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
import re
import webapp2
import jinja2
import os

jinja_env = jinja2.Environment(autoescape=True,
                               loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    if username and USER_RE.match(username):
        return True
    else:
        return False


PASS_RE = re.compile(r"^.{3,20}$")


def valid_pass(passw):
    if passw and PASS_RE.match(passw):
        return True
    else:
        return False

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_email(email):
    if email and EMAIL_RE.match(email):
        return True
    else:
        return False



class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class MainHandler(Handler):
    def get(self):
        self.response.write('Hello world!')


class RotHandler(Handler):
    def get(self):
        self.render("rot13.html")

    def post(self):
        rot13 = ''
        g = self.request.get("text")
        if g:
            rot13 = g.encode('rot13')
        self.render("rot13.html", text=rot13)


class SignupHandler(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        is_error = False
        username = self.request.get("username")
        passw = self.request.get("pass")
        verify_pass = self.request.get("verify_pass")
        email = self.request.get("email")
        username_error = ""
        pass_error = ""
        verifypass_error = ""
        email_error = ""
        if (username):
            if (valid_username(username) == False):
                is_error = True
                username_error = "Thats not a valid username"
        if (passw):
            if (valid_pass(passw) == False):
                is_error = True
                pass_error = "Invalid Pass"
        if (valid_pass(passw) == True):
            if (verify_pass != passw):
                is_error = True
                verifypass_error = "Passwords Don't match"

        if (email):
            if (valid_email(email) == False):
                is_error = True
                email_error = "Invalid Email address"

        if (is_error == True):
            self.render("signup.html", username_value=username, username_error=username_error, pass_value=passw,
                        pass_error=pass_error, verifypass_value=verify_pass,
                        verifypass_error=verifypass_error, email_value=email, email_error=email_error)
        else:
            self.redirect("/verifed?username=" + username)


class VerifiedHandler(Handler):
    def get(self):
        username = self.request.get("username")
        if(valid_username(username)):
            self.render("verified.html",username = username)


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/rot13', RotHandler),
    ('/signup', SignupHandler),
    ('/verifed', VerifiedHandler)
], debug=True)
