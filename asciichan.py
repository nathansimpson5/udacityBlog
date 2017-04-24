import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

# set up file to use Jinja2
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = "snakeybaby"


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s = %s; Path = /' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id = ; Path = /')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# homework 1. doesn't effect blog
class MainPage(BlogHandler):
    def get(self):
        self.render('home.html')


# set up password hashes for storing
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    """Create user database"""
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name = ', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Post(db.Model):
    """create post database object"""
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty(required=False)
    likes = db.IntegerProperty(required=False)
    liked_by = db.ListProperty(str)

    @classmethod
    def by_post_name(cls, name):
        u = cls.all().filter('name  = ', name).get()
        return u

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    @property
    def comments(self):
        return Comment.all().filter("post = ", str(self.key().id()))


class Comment(db.Model):
    """create comment database object"""
    comment = db.TextProperty(required=True)
    post = db.StringProperty(required=True)
    author = db.StringProperty(required=False)

    @classmethod
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment-page.html", c=self)


# blog start
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# fills the front page with blog posts
class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts)


# makes the permalink page
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


# creates new blog post if user is logged in
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            author = self.user.name
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content,
                     author=author, likes=0, liked_by=[])
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error, author=author)


# make it so users can edit posts
class EditPost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            subject = post.subject
            content = post.content
            # check if the post author is the same as the logged in user
            n1 = post.author
            n2 = self.user.name

            if n1 == n2:
                self.render("edit-post.html", subject=subject, content=content)
            else:
                self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            self.redirect('/login')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post is not None:
            n1 = post.author
            n2 = self.user.name

            if n1 == n2:
                subject = self.request.get('subject')
                content = self.request.get('content')
                author = self.user.name

                if subject and content:
                    post.subject = subject
                    post.content = content
                    post.put()
                    self.redirect('/blog/%s' % str(post.key().id()))
                else:
                    error = "subject and content, please!"
                    self.render("newpost.html", subject=subject,
                                content=content, error=error, author=author)


# like handler
class LikePage(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post is not None:
                author = post.author
                current_user = self.user.name

                if author == current_user or current_user in post.liked_by:
                    self.redirect('/blog')
                else:
                    post.likes = post.likes + 1
                    post.liked_by.append(current_user)
                    post.put()
                    self.redirect('/blog')


# Comment handler
class NewComment(BlogHandler):
    def get(self, post_id):
        if not self.user:
            error = "You must be logged in to comment"
            self.redirect("/login")
        post = Post.get_by_id(int(post_id), parent=blog_key())
        subject = post.subject
        content = post.content
        author = self.user.name
        self.render("comment-page.html", subject=subject,
                    content=content, author=author, pkey=post.key())

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        author = self.user.name
        if not post:
            self.error(404)
            return

        if not self.user:
            return self.redirect('/login')

        comment = self.request.get('comment')
        if comment:
            c = Comment(comment=comment, post=post_id, author=author, parent=self.user.key())
            c.put()
            self.redirect('/blog/%s' % str(post_id))
        else:
            error = "add content, please!"
            self.render("comment-page.html", error=error)


# make it so users can edit their own comments
class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        if not self.user:
            error = "You must be logged in to comment"
            return self.redirect("/login")
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment:
            self.render("editcomment.html", subject=post.subject,
                        content=post.content, comment=comment.comment)

    def post(self, post_id, comment_id):
        if not self.user:
            error = "You must be logged in to comment"
            return self.redirect("/login")
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment is not None:
            if comment.parent().key().id() == self.user.key().id():
                comment.comment = self.request.get('comment')
                comment.put()
            self.redirect('/blog/%s' % str(post_id))


# make it so users can delete their own comments
class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        if not self.user:
            error = "You must be logged in to delete"
            return self.redirect("/login")
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if post is not None and comment is not None:
            n1 = post.author
            n2 = self.user.name

            if n1 == n2:
                comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
                comment.delete()
                self.redirect('/blog/%s' % str(post_id))
            else:
                return self.redirect("/login")


# deletes posts
class DeletePost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post is not None:
                n1 = post.author
                n2 = self.user.name

                if n1 == n2:
                    key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                    post = db.get(key)
                    post.delete()
                    self.redirect('/blog')
                else:
                    self.redirect('/login')


# Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text=rot13)


# check user sign-ins
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# make it so users can create accounts
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


# make it so users can register
class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


# Allow users to sign in
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


# log out users
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


# tell users hello
class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/signup')


# Cookie page. doesn't affect blog
class CookiePage(BlogHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visits = 0
        visit_cookie_str = self.request.cookies.get('visits')
        if visit_cookie_str:
            cookie_val = check_secure_val(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)

        visits += 1

        new_cookie_val = make_secure_val(str(visits))

        self.response.headers.add_header('Set-Cookie',
                                         'visits = %s' % new_cookie_val)

        if visits > 10:
            self.write("You are the best ever!")
        else:
            self.write("you've been here %s times" % visits)


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)/editpost', EditPost),
                               ('/signup', Register),
                               ('/blog/([0-9]+)/like', LikePage),
                               ('/blog/([0-9]+)/newcomment', NewComment),
                               ('/blog/([0-9]+)/deletepost', DeletePost),
                               ('/blog/([0-9]+)/editcomment/([0-9]+)', EditComment),
                               ('/blog/([0-9]+)/deletecomment/([0-9]+)', DeleteComment),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/cookiepage', CookiePage)], debug=True)
