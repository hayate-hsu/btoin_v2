'''
'''
from __future__ import absolute_import, division, print_function, with_statement

# Tornado framework
import tornado.web
HTTPError = tornado.web.HTTPError

import tornado.ioloop
import tornado.auth
import tornado.escape
import tornado.options
import tornado.locale
import tornado.util
import tornado.httpclient
import tornado.gen
import tornado.httputil

from tornado.util import errno_from_exception
from tornado.platform.auto import set_close_exec

from tornado.options import define, options

define('port', default=9090, help='running on the given port', type=int)

import errno
import os
import sys

# import struct
# import hashlib
import socket
# import collections
import functools

import logging

from MySQLdb import (IntegrityError)

# Mako template
import mako.lookup
import mako.template

import user_agents

logger = None

import util

_now = util.now

import settings
import business
import message


json_encoder = util.json_encoder
json_decoder = util.json_decoder

CURRENT_PATH = os.path.abspath(os.path.dirname(__file__))
TEMPLATE_PATH = '/www/niot'
UPLOAD_PATH = os.path.join(TEMPLATE_PATH, 'up_files')
UPLOAD_PREFIX = '/up_files/'
if not os.path.exists(UPLOAD_PATH):
    os.mkdir(UPLOAD_PATH)
MOBILE_PATH = os.path.join(TEMPLATE_PATH, 'm')

OK = {'Code':200, 'Msg':'OK'}

NIOT=12698


class Application(tornado.web.Application):
    '''
        Web application class.
        Redefine __init__ method.
    '''
    def __init__(self):
        handlers = [
            (r'/(.*?\.html)$', PageHandler),
            # in product environment, use nginx to support static resources
            # (r'/(.*\.(?:css|jpg|png|js|ico|json))$', tornado.web.StaticFileHandler, 
            #  {'path':TEMPLATE_PATH}),
            # (r'/test', TestHandler),
            (r'/project', ProjectHandler),
            (r'/file', FileHandler),
            (r'/message/(.*)/', MessageHandler),
            (r'/', MainHandler),
        ]
        settings = {
            'cookie_secret':util.sha1('niot').hexdigest(), 
            'static_path':TEMPLATE_PATH,
            # 'static_url_prefix':'resource/',
            'debug':False,
            'autoreload':True,
            'autoescape':'xhtml_escape',
            'i18n_path':os.path.join(CURRENT_PATH, 'resource/i18n'),
            # 'login_url':'',
            'xheaders':True,    # use headers like X-Real-IP to get the user's IP address instead of
                                # attributeing all traffic to the balancer's IP address.
        }
        super(Application, self).__init__(handlers, **settings)

class BaseHandler(tornado.web.RequestHandler):
    '''
        BaseHandler
        override class method to adapt special demands
    '''
    LOOK_UP = mako.lookup.TemplateLookup(directories=[TEMPLATE_PATH, ], 
                                         module_directory='/tmp/niot/mako',
                                         output_encoding='utf-8',
                                         input_encoding='utf-8',
                                         encoding_errors='replace')
    # LOOK_UP_MOBILE = mako.lookup.TemplateLookup(directories=[MOBILE_PATH, ], 
    #                                             module_directory='/tmp/niot/mako_mobile',
    #                                             output_encoding='utf-8',
    #                                             input_encoding='utf-8',
    #                                             encoding_errors='replace')

    RESPONSES = {}
    RESPONSES.update(tornado.httputil.responses)

    def initialize(self):
        '''
        '''
        pass

    # def on_finish(self):
    #     '''
    #     '''
    #     logger.info('on_finish')
    #     # self.set_header('Access-Control-Allow-Origin', 'http://183.63.152.237:8180')
    #     self.set_header('Access-Control-Allow-Origin', '*')

    def get_arguments(self, name, strip=True):
        assert isinstance(strip, bool)
        return self._get_arguments(name, self.request.arguments, strip)

    def _get_arguments(self, name, source, strip=True):
        values = []
        for v in source.get(name, []):
            if isinstance(v, basestring):
                v = self.decode_argument(v, name=name)
                if isinstance(v, tornado.escape.unicode_type):
                    v = tornado.web.RequestHandler._remove_control_chars_regex.sub(' ', v)
                if strip:
                    v = v.strip()
            values.append(v)
        return values

    def render_string(self, filename, **kwargs):
        '''
            Override render_string to use mako template.
            Like tornado render_string method, this method also
            pass request handler environment to template engine
        '''
        try:
            # if not self.is_mobile():
            #     template = self.LOOK_UP.get_template(filename)
            # else:
            #     template = self.LOOK_UP_MOBILE.get_template(filename)
            # cms = 'http://cms.bidongwifi.com/'
            cms = settings['cms']
            template = self.LOOK_UP.get_template(filename)
            env_kwargs = dict(
                handler = self,
                request = self.request,
                # current_user = self.current_user
                locale = self.locale,
                _ = self.locale.translate,
                static_url = self.static_url,
                xsrf_form_html = self.xsrf_form_html,
                reverse_url = self.application.reverse_url,
                cms = cms,
            )
            env_kwargs.update(kwargs)
            return template.render(**env_kwargs)
        except:
            from mako.exceptions import RichTraceback
            tb = RichTraceback()
            for (module_name, line_no, function_name, line) in tb.traceback:
                print('File:{}, Line:{} in {}'.format(module_name, line_no, function_name))
                print(line)
            logger.error('Render {} failed, {}:{}'.format(filename, tb.error.__class__.__name__, tb.error), 
                         exc_info=True)
            raise HTTPError(500, 'Render page failed')

    def render(self, filename, **kwargs):
        '''
            Render the template with the given arguments
        '''
        template = TEMPLATE_PATH
        # if self.is_mobile():
        #     template = MOBILE_PATH
        if not os.path.exists(os.path.join(template, filename)):
            raise HTTPError(404, 'File Not Found')
        self.finish(self.render_string(filename, **kwargs))

    def set_status(self, status_code, reason=None):
        '''
            Set custom error resson
        '''
        self._status_code = status_code
        self._reason = 'Unknown Error'
        if reason is not None:
            self._reason = tornado.escape.native_str(reason)
        else:
            try:
                self._reason = self.RESPONSES[status_code]
            except KeyError:
                raise ValueError('Unknown status code {}'.format(status_code))

    def write_error(self, status_code, **kwargs):
        '''
            Customer error return format
        '''
        if self.settings.get('Debug') and 'exc_info' in kwargs:
            self.set_header('Content-Type', 'text/plain')
            import traceback
            for line in traceback.format_exception(*kwargs['exc_info']):
                self.write(line)
            self.finish()
        else:
            self.render_json_response(Code=status_code, Msg=self._reason)
            # self.render('error.html', Code=status_code, Msg=self._reason)

    def render_json_response(self, **kwargs):
        '''
            Encode dict and return response to client
        '''
        callback = self.get_argument('callback', None)
        # check should return jsonp
        if callback:
            self.set_status(200, kwargs.get('Msg', None))
            self.finish('{}({})'.format(callback, json_encoder(kwargs)))
        else:
            self.set_status(kwargs['Code'], kwargs.get('Msg', None))
            self.set_header('Content-Type', 'application/json')
            self.finish(json_encoder(kwargs))

    def is_mobile(self):
        agent_str = self.request.headers.get('User-Agent', '')
        if not agent_str:
            return False

        if 'MicroMessenger' in agent_str:
            # from weixin client
            return True

        self.check_app()
        if hasattr(self, 'is_mobile'):
            return self.is_mobile

        agent = user_agents.parse(agent_str)

        return agent.is_mobile

    def check_app(self):
        '''
        '''
        name = '\xe8\x87\xaa\xe8\xb4\xb8\xe9\x80\x9a'
        if name in self.agent_str:
            self.is_mobile = True

def _parse_body(method):
    '''
        Framework only parse body content as arguments 
        like request POST, PUT method.
        Through this method parameters can be send in uri or
        in body not matter request methods(contain 'GET', 'DELETE')
    '''
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        content_type = self.request.headers.get('Content-Type', '')

        # parse json format arguments in request body content
        if content_type.startswith('application/json') and self.request.body:
            arguments = json_decoder(tornado.escape.native_str(self.request.body))
            for name, values in arguments.iteritems():
                self.request.arguments.setdefault(name, []).extend([values,])
                # if isinstance(values, basestring):
                #     values = [values, ]
                # elif isinstance(values, dict):
                #     values = [values, ]
                # else:
                #     values = [v for v in values if v]
                # if values:
                #     self.request.arguments.setdefault(name, []).extend(values)
        # parse body if request's method not in (PUT, POST, PATCH)
        if self.request.method not in ('PUT', 'PATCH', 'POST'):
            if content_type.startswith('application/x-www-form-urlencode'):
                arguments = tornado.escape.parse_qs_bytes(
                    tornado.escape.native_str(self.request.body))
                for name, values in arguments.iteritems():
                    values = [v for v in values if v]
                    if values:
                        self.request.arguments.setdefault(name, []).extend(values)
            elif content_type.startswith('multipart/form-data'):
                fields = content_type.split(';')
                for field in fields:
                    k, sep, v = field.strip().partition('=')
                    if k == 'boundary' and v:
                        tornado.httputil.parse_multipart_form_data(
                            tornado.escape.utf8(v), self.request.body, 
                            self.request.arguments, self.request.files)
                        break
                    else:
                        logger.warning('Invalid multipart/form-data')
        return method(self, *args, **kwargs)
    return wrapper

def _trace_wrapper(method):
    '''
        Decorate method to trace logging and exception.
        Remarks : to make sure except catch and progress record
        _trace_wrapper should be the first decorator if a method
        is decorated by multiple decorators.
    '''
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        try:
            logger.info('<-- In %s: <%s> -->', self.__class__.__name__, self.request.method)
            return method(self, *args, **kwargs)
        except HTTPError:
            logger.error('HTTPError catch', exc_info=True)
            raise
        except KeyError:
            if self.application.settings.get('debug', False):
                print(self.request)
            logger.warning('Arguments error', exc_info=True)
            raise HTTPError(400)
        except ValueError:
            if self.application.settings.get('debug', False):
                print(self.request)
            logger.warning('Arguments value abnormal', exc_info=True)
            raise HTTPError(400)
        except Exception:
            # Only catch normal exceptions
            # exclude SystemExit, KeyboardInterrupt, GeneratorExit
            logger.error('Unknow error', exc_info=True)
            raise HTTPError(500)
        finally:
            logger.info('<-- Out %s: <%s> -->\n\n', self.__class__.__name__, self.request.method)
    return wrapper

class MainHandler(BaseHandler):
    '''
    '''
    @_trace_wrapper
    def get(self):
        # query notify
        notices = message.get_messages(NIOT, 2, 0, 2, '', 0, 5)
        
        logger.info('notices: {}'.format(notices))

        # identify
        ids = message.get_messages(NIOT, 2, 0, 1, '', 0, 6)
        # logger.info('ids: {}'.format(ids))

        # news 
        news = message.get_messages(NIOT, 2, 0, 3, '', 0, 10)
        # logger.info('news: {}'.format(news))

        
        self.render('index.html', notices=notices, ids=ids, news=news)

class MessageHandler(BaseHandler):
    '''
    '''
    @_trace_wrapper
    def get(self, _id):
        '''
            get special news
        '''
        logger.info(self.request)
        record = message.get_message(_id)

        self.render('newsdetail.html', message=record)

class PageHandler(BaseHandler):
    '''
    '''
    @property
    def render_dispatch(self):
        _DISPATCH_ = {
            # 'jobs':PageHandler.render_jobs,
            # 'jobs.html':PageHandler.render_jobs,

            # 'news':PageHandler.render_news,
            # 'news.html':PageHandler.render_news,
            'jobs':self.render_jobs,
            'jobs.html':self.render_jobs,

            'news':self.render_news,
            'news.html':self.render_news,

            'newsdetail':self.render_msg,
            'newsdetail.html':self.render_msg,

            'nameinfo':self.render_nameinfo,
            'nameinfo.html':self.render_nameinfo,

            'notices':self.render_notices,
            'notices.html':self.render_notices,

        }

        return _DISPATCH_

    @_trace_wrapper
    @_parse_body
    def get(self, page):
        '''
            Render html page
        '''
        page = page.lower()

        method = self.render_dispatch.get(page, self.render)
        method(page)

    def render_jobs(self, page):
        '''
        '''
        jobs = message.get_messages2(NIOT, 16, 0, 0, '', 0, 10)
        
        self.render('jobs.html', jobs=jobs)

    def render_news(self, page):
        '''
        '''
        news = message.get_messages(NIOT, 2, 0, 3, '', 0, 20)

        self.render('news.html', news=news)

    def render_msg(self, page):
        _id = self.get_argument('id')
        _message = message.get_message(_id)
        
        news = message.get_messages(NIOT, 2, 0, 3, '', 0, 5)
        if message:
            self.render('newsdetail.html', _message=_message, news=news)
        else:
            self.render('news.html', news=news)

    def render_nameinfo(self, page):
        ids = message.get_messages(NIOT, 2, 0, 1, '', 0, 20)
        self.render('nameinfo.html', ids=ids)

    def render_notices(self, page):
        notices = message.get_messages(NIOT, 2, 0, 2, '', 0, 20)
        self.render('notices.html', notices=notices)


class ProjectHandler(BaseHandler):
    '''
    '''
    def _gen_project_id_(self, name, mobile):
        '''
            generate id by name&mobile    
        '''
        return util.md5(name, mobile).hexdigest()
    
    @_trace_wrapper
    @_parse_body
    def post(self):
        kwargs = {key:value[0] for key,value in self.request.arguments.iteritems()}
        if 'name' not in kwargs or 'mobile' not in kwargs:
            raise HTTPError(400, reason='should set name or mobile')

        kwargs['id'] = self._gen_project_id_(kwargs['name'], kwargs['mobile'])
        try:
            business.add_project(**kwargs)
        except IntegrityError:
            raise HTTPError(406, reason='Not Accept, duplicated name&mobile')
    
        self.render_json_response(**OK)

class FileHandler(BaseHandler):
    '''
        1. user upload image & update databse
    '''
    def _gen_file_id_(self, *args):
        now = util.now()

        return util.md5(now, *args).hexdigest()

    # @_trace_wrapper
    # def get(self, _id):
    #     filepath = os.path.join(UPLOAD_PATH, _id)
    #     logger.info('id:{}, filepath:{}'.format(_id, filepath))
    #     with open(filepath, 'rb') as f:
    #         data = f.read()
    #         self.finish(data)

    @_trace_wrapper
    # @_parse_body
    def post(self, _id=None):
        '''
            engineer uplaod image
            update engineer's image
        '''
        file_metas = self.request.files['uploadImg']
        filename, ext = _id, ''
        for meta in file_metas:
            filename = meta['filename']
            content_type = meta['content_type']
            if '.' in filename and filename[-1] != '.':
                ext = filename.split('.')[-1]
            if not _id:
                filename = self._gen_file_id_(filename, content_type, util.generate_password(8)) 
                if ext:
                    filename = '.'.join([filename, ext])
            else:
                filename = _id
            filepath = os.path.join(UPLOAD_PATH, filename)
            with open(filepath, 'wb') as uf:
                uf.write(meta['body'])
            break

        if filename:
            self.render_json_response(name=UPLOAD_PREFIX+filename, **OK)
        else:
            raise HTTPError(400)

_DEFAULT_BACKLOG = 128
# These errnos indicate that a non-blocking operation must be retried
# at a later time. On most paltforms they're the same value, but on 
# some they differ
_ERRNO_WOULDBLOCK = (errno.EWOULDBLOCK, errno.EAGAIN)
if hasattr(errno, 'WSAEWOULDBLOCK'):
    _ERRNO_WOULDBLOCK += (errno.WSAEWOULDBLOCK, )

def bind_udp_socket(port, address=None, family=socket.AF_UNSPEC, backlog=_DEFAULT_BACKLOG, flags=None):
    '''
    '''
    udp_sockets = []
    if address == '':
        address = None
    if not socket.has_ipv6 and family == socket.AF_UNSPEC:
        family = socket.AFINET
    if flags is None:
        flags = socket.AI_PASSIVE
    bound_port = None
    for res in socket.getaddrinfo(address, port, family, socket.SOCK_DGRAM, 0, flags):
        af, socktype, proto, canonname, sockaddr = res
        try:
            sock = socket.socket(af, socktype, proto)
        except socket.error as e:
            if errno_from_exception(e) == errno.EAFNOSUPPORT:
                continue
            raise
        set_close_exec(sock.fileno())
        if os.name != 'nt':
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if af == socket.AF_INET6:
            if hasattr(socket, 'IPPROTO_IPV6'):
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        # automatic port allocation with port=None
        # should bind on the same port on IPv4 & IPv6 
        host, requested_port = sockaddr[:2]
        if requested_port == 0 and bound_port is not None:
            sockaddr = tuple([host, bound_port] + list(sockaddr[2:]))
        sock.setblocking(0)
        sock.bind(sockaddr)
        bound_port = sock.getsockname()[1]
        udp_sockets.append(sock)
    return udp_sockets

def add_udp_handler(sock, servers, io_loop=None):
    '''
        Read data in 4096 buffer
    '''
    if io_loop is None:
        io_loop = tornado.ioloop.IOLoop.current()
    def udp_handler(fd, events):
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                if data:
                    # ac data arrived, deal with
                    pass
            except socket.error as e:
                if errno_from_exception(e) in _ERRNO_WOULDBLOCK:
                    # _ERRNO_WOULDBLOCK indicate we have accepted every
                    # connection that is avaiable
                    return
                import traceback
                traceback.print_exc(file=sys.stdout)
            except: 
                import traceback
                traceback.print_exc(file=sys.stdout)
    io_loop.add_handler(sock.fileno(), udp_handler, tornado.ioloop.IOLoop.READ)

def main():
    global logger
    tornado.options.parse_command_line()
    import trace
    trace.init(settings['LOG_NIOT_PATH'], options.port)
    logger = trace.logger('niot', False)
    logger.setLevel(logging.INFO)

    niot_pid = os.path.join(settings['RUN_PATH'], 'p_{}.pid'.format(options.port))
    with open(niot_pid, 'w') as f:
        f.write('{}'.format(os.getpid()))

    app = Application()
    app.listen(options.port, xheaders=app.settings.get('xheaders', False))
    io_loop = tornado.ioloop.IOLoop.instance()
    logger.info('Niot Main-WEB Server Listening:{} Started'.format(options.port))
    io_loop.start()

if __name__ == '__main__':
    main()
