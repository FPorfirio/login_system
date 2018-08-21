import webapp2
import os
import jinja2
import re

from google.appengine.ext import db 

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
            autoescape = True)


class Handler(webapp2.Requesthandler):
    def write(self, *a, **params)
        self.response.out.write(*a, **a)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, *a, **params):
        self.write(self.render_str(template, **params))

class Validation:
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASS_RE = re.compile(r"^.{3,20}$")
    MAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


    def validName(self, username):
        return username and self.USER_RE.match(username)

    def validPass(self, password):
        return password and self.PASS_RE.match(password)

    def validMail(self, email):
        return mail and self.MAIL_RE.match(email)


class Hash():
    def make_salt():
        return ''.join(random.choice(string.letters) for x in range(5))
   
    def hash_str(name, pw, salt = none):
        if not salt:
            salt = make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s|%s' % (h, salt)

    def valid_pw(name, pw, h):
        salt = h.split('|')[1]
        return h == hash_str(name, pw, salt)


class User(db.model):
    user = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    

class Front(Handler):
    def get(self):
        self.render('front.html')
    
class Register(Handler, Validation, Hash)
     def get(self)
        self.render('register.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        confirm_pass = self.request.get('confirm_pass')
        email = self.request.get('email')

        valid_user = self.validName(username)
        valid_pass = self.validPass(password)
        valid_confirm_pass = password == confirm_pass
        valid_email = self.validMail(email)

        if (valid_user and valid_pass and valid_confirm_pass):
            q = Person.all()
            q.filter("user =", username)
            result = q.get()
            
            if not result:
                hash = self.hash_str(username, password)
                u = User(user = user, password = hash, email = email)
                u.put()
                self.response.headers.add_header('set-Cookie', 'user_id=%s;%s' % (hash, 'Path=/')
                self.redirect('/front/success)

            else:
                error = "Username already exists"
                self.render('register.html', error=error)

        else:
            error = ""
            if not valid_user:
                error += "Please enter a valid username"
            elif not valid_pass:
                error += "Please enter a valid password"
            elif not valid_confirm_pass:
                error += "Password doesn't match"
            self.render('register.html', user=username, password=password, error=error) 

class Success(handler):
    def get(self):
        user_id = self.request.cookies.get('user_id')
        userHash = user_id.split(';')[0]
        
        q = Person.all()
        q.filter("password =", userHash)
        result = q.get()
        user = result.user

        if q:
            self.render('success.html', username=user)
        else:
            self.rediret('/front/register')


class sign_in(Handler, Hash):
    def get(self):
        self.render('sign_in.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        if username and password:
            q = Person.all()
            q.filter("user =", username)
            result = q.get()
            hash = result.password
            autentication = self.valid_pw(username, password, hash)
            
            if autentication
                self.response.headers.add_header('set-Cookie', 'user_id=%s;%s' % (hash, 'Path=/')       
                self.redirect('success.html')
            else:
                error = "invalid username or password"
                self.render('sign_in.html', error=error)
        else:
            error = "please enter username and password"
            self.render('sign_in.html', error=error)







