#!/usr/bin/env python3

"""Gruyere - a web application with holes.

Copyright 2017 Google Inc. All rights reserved.

This code is licensed under the
https://creativecommons.org/licenses/by-nd/3.0/us/
Creative Commons Attribution-No Derivative Works 3.0 United States license.

DO NOT COPY THIS CODE!

This application is a small self-contained web application with numerous
security holes. It is provided for use with the Web Application Exploits and
Defenses codelab. You may modify the code for your own use while doing the
codelab but you may not distribute the modified code. Brief excerpts of this
code may be used for educational or instructional purposes provided this
notice is kept intact. By using Gruyere you agree to the Terms of Service
https://www.google.com/intl/en/policies/terms/
"""
from __future__ import print_function

from future import standard_library
standard_library.install_aliases()
from builtins import str
__author__ = 'Bruce Leban'

# system modules
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
import cgi
import pickle
import os
import random
import sys
import threading
import urllib.request, urllib.parse, urllib.error
from urllib.parse import urlparse

try:
  sys.dont_write_bytecode = True
except AttributeError:
  pass

# our modules
import data
import gtl
import html

#DB_FILE = '/stored-data.txt'
#SECRET_FILE = '/secret.txt'

INSTALL_PATH = '/home/OneHalf/gruyere'
RESOURCE_PATH = '/home/OneHalf/gruyere/resources'

INSTALL_PATH = '.'
RESOURCE_PATH = './resources'

SPECIAL_COOKIE = '_cookie'
SPECIAL_PROFILE = '_profile'
SPECIAL_DB = '_db'
SPECIAL_PARAMS = '_params'
SPECIAL_UNIQUE_ID = '_unique_id'

COOKIE_UID = 'uid'
COOKIE_ADMIN = 'is_admin'
COOKIE_AUTHOR = 'is_author'


# Set to True to cause the server to exit after processing the current url.
#quit_server = False

# A global copy of the database so that _GetDatabase can access it.
global stored_data
stored_data = None

# The HTTPServer object.
http_server = None

# A secret value used to generate hashes to protect cookies from tampering.
cookie_secret = ''

# File extensions of resource files that we recognize.
RESOURCE_CONTENT_TYPES = {
    '.css': 'text/css',
    '.gif': 'image/gif',
    '.htm': 'text/html',
    '.html': 'text/html',
    '.js': 'application/javascript',
    '.jpeg': 'image/jpeg',
    '.jpg': 'image/jpeg',
    '.png': 'image/png',
    '.ico': 'image/x-icon',
    '.text': 'text/plain',
    '.txt': 'text/plain',
}


#def main():
#  _SetWorkingDirectory()
#
#  global quit_server
#  quit_server = False
#
#  quit_timer = threading.Timer(7200, lambda: _Exit('Timeout'))
#  quit_timer.start()
#
#  server_name = 'localhost'
#  server_port = 8008
#
#  # The unique id is created from a CSPRNG.
#  try:
#    r = random.SystemRandom()
#  except NotImplementedError:
#    _Exit('Could not obtain a CSPRNG source')
#
#  global server_unique_id
#  server_unique_id = str(r.randint(2**128, 2**(128+1)))
#
#
#
#  global http_server
#  http_server = HTTPServer((server_name, server_port),
#                           GruyereRequestHandler)
#
#  print('''
#      Gruyere started...
#          http://%s:%d/
#          http://%s:%d/%s/''' % (
#              server_name, server_port, server_name, server_port,
#              server_unique_id), file=sys.stderr)
#
#  global stored_data
#  stored_data = _LoadDatabase()
#
#  while not quit_server:
#    try:
#      http_server.handle_request()
#      _SaveDatabase(stored_data)
#    except KeyboardInterrupt:
#      print('\nReceived KeyboardInterrupt', file=sys.stderr)
#      quit_server = True
#
#  print('\nClosing', file=sys.stderr)
#  http_server.socket.close()
#  _Exit('quit_server')

global quit_server
quit_server = False

global server_unique_id
server_unique_id = str(random.randint(2**128, 2**(128 + 1)))

def _Exit(reason):
  # use os._exit instead of sys.exit because this can't be trapped
  print('\nExit: ' + reason, file=sys.stderr)
  os._exit(0)


def _SetWorkingDirectory():
  """Set the working directory to the directory containing this file."""
  if sys.path[0]:
    os.chdir(sys.path[0])


def _LoadDatabase():
  """Load the database from stored-data.txt.

  Returns:
    The loaded database.
  """

  try:
    f = _Open(INSTALL_PATH, DB_FILE,'rb')
    stored_data = pickle.load(f)
    f.close()
  except (IOError, ValueError):
    _Log('Couldn\'t load data; expected the first time Gruyere is run')
    stored_data = None

  f = _Open(INSTALL_PATH, SECRET_FILE)
  global cookie_secret
  cookie_secret = f.readline()
  f.close()

  return stored_data


def _SaveDatabase(save_database):
    """Save the database to stored-data.txt.

    Args:
        save_database: the database to save.
    """
    try:
        # Using 'with' ensures the file is properly closed after writing
        with _Open(INSTALL_PATH, DB_FILE, 'wb') as f:
            pickle.dump(save_database, f)
        print("Database saved successfully.")
    except IOError as e:
        _Log(f"Couldn't save data: {e}")


def _Open(location, filename, mode='r'):
  """Open a file from a specific location.

  Args:
    location: The directory containing the file.
    filename: The name of the file.
    mode: File mode for open().

  Returns:
    A file object.
  """
  return open(location + filename, mode)


class GruyereRequestHandler(BaseHTTPRequestHandler):
  """Handle a http request."""

  # An empty cookie
  NULL_COOKIE = {COOKIE_UID: None, COOKIE_ADMIN: False, COOKIE_AUTHOR: False}

  # Urls that can only be accessed by administrators.
  _PROTECTED_URLS = [
      '/quit',
      '/reset'
  ]

  def _GetDatabase(self):
    """Gets the database."""
    global stored_data
    if not stored_data:
      stored_data = data.DefaultData()
    return stored_data

  def _ResetDatabase(self):
      """Reset the database."""
      global stored_data
      print("Resetting the database...")
      
      # Delete the database file if it exists
      #db_file_path = os.path.join(INSTALL_PATH, DB_FILE)
      #if os.path.exists(db_file_path):
      #    os.remove(db_file_path)
      #    print(f"Deleted old database file at {db_file_path}")
  
      # Set stored_data to default values
      stored_data = data.DefaultData()
      print("Database reset to default data.")
      
      # Save the reset database to storage
      _SaveDatabase(stored_data)

  def _DoLogin(self, cookie, specials, params):
    """Handles the /login url: validates the user and creates a cookie.

    Args:
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters.
    """
    database = self._GetDatabase()
    message = ''
    if 'uid' in params and 'pw' in params:
      uid = self._GetParameter(params, 'uid')
      if uid in database:
        if database[uid]['pw'] == self._GetParameter(params, 'pw'):
          (cookie, new_cookie_text) = (
              self._CreateCookie('GRUYERE', uid))
          self._DoHome(cookie, specials, params, new_cookie_text)
          return
      message = 'Invalid user name or password.'
    # not logged in
    specials['_message'] = message
    self._SendTemplateResponse('/login.gtl', specials, params)

  def _DoLogout(self, cookie, specials, params):
    """Handles the /logout url: clears the cookie.

    Args:
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters.
    """
    (cookie, new_cookie_text) = (
        self._CreateCookie('GRUYERE', None))
    self._DoHome(cookie, specials, params, new_cookie_text)

  def _Do(self, cookie, specials, params):
    """Handles the home page (http://localhost/).

    Args:
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters.
    """
    self._DoHome(cookie, specials, params)

  def _DoHome(self, cookie, specials, params, new_cookie_text=None):
    """Renders the home page.

    Args:
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters.
      new_cookie_text: New cookie.
    """
    database = self._GetDatabase()
    specials[SPECIAL_COOKIE] = cookie
    if cookie and cookie.get(COOKIE_UID):
      specials[SPECIAL_PROFILE] = database.get(cookie[COOKIE_UID])
    else:
      specials.pop(SPECIAL_PROFILE, None)
    self._SendTemplateResponse(
        '/home.gtl', specials, params, new_cookie_text)

  def _DoBadUrl(self, path, cookie, specials, params):
    """Handles invalid urls: displays an appropriate error message.

    Args:
      path: The invalid url.
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters.
    """
    self._SendError('Invalid request: %s' % (path,), cookie, specials, params)

  def _DoQuitserver(self, cookie, specials, params):
    """Handles the /quitserver url for administrators to quit the server.

    Args:
      cookie: The cookie for this request. (unused)
      specials: Other special values for this request. (unused)
      params: Cgi parameters. (unused)
    """
    global quit_server
    quit_server = True
    self._SendTextResponse('Server quit.', None)

  def _AddParameter(self, name, params, data_dict, default=None):
    """Transfers a value (with a default) from the parameters to the data."""
    if params.get(name):
      data_dict[name] = params[name][0]
    elif default is not None:
      data_dict[name] = default

  def _GetParameter(self, params, name, default=None):
    """Gets a parameter value with a default."""
    if params.get(name):
      return params[name][0]
    return default

  def _GetSnippets(self, cookie, specials, create=False):
    """Returns all of the user's snippets."""
    database = self._GetDatabase()
    try:
      profile = database[cookie[COOKIE_UID]]
      if create and 'snippets' not in profile:
        profile['snippets'] = []
      snippets = profile['snippets']
    except (KeyError, TypeError):
      _Log('Error getting snippets')
      return None
    return snippets

  def _DoNewsnippet2(self, cookie, specials, params):
    """Handles the /newsnippet2 url: actually add the snippet.

    Args:
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters.
    """
    snippet = self._GetParameter(params, 'snippet')
    if not snippet:
      self._SendError('No snippet!', cookie, specials, params)
    else:
      snippets = self._GetSnippets(cookie, specials, True)
      if snippets is not None:
        snippets.insert(0, snippet)
    self._SendRedirect('/snippets.gtl', specials[SPECIAL_UNIQUE_ID])

  def _DoDeletesnippet(self, cookie, specials, params):
    """Handles the /deletesnippet url: delete the indexed snippet.

    Args:
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters.
    """
    index = self._GetParameter(params, 'index')
    snippets = self._GetSnippets(cookie, specials)
    try:
      del snippets[int(index)]
    except (IndexError, TypeError, ValueError):
      self._SendError(
          'Invalid index (%s)' % (index,),
          cookie, specials, params)
      return
    self._SendRedirect('/snippets.gtl', specials[SPECIAL_UNIQUE_ID])

  def _DoSaveprofile(self, cookie, specials, params):
    """Saves the user's profile.

    Args:
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters.

    If the 'action' cgi parameter is 'new', then this is creating a new user
    and it's an error if the user already exists. If action is 'update', then
    this is editing an existing user's profile and it's an error if the user
    does not exist.
    """

    # build new profile
    profile_data = {}
    uid = self._GetParameter(params, 'uid', cookie[COOKIE_UID])
    newpw = self._GetParameter(params, 'pw')
    self._AddParameter('name', params, profile_data, uid)
    self._AddParameter('pw', params, profile_data)
    self._AddParameter('is_author', params, profile_data)
    self._AddParameter('is_admin', params, profile_data)
    self._AddParameter('private_snippet', params, profile_data)
    self._AddParameter('icon', params, profile_data)
    self._AddParameter('web_site', params, profile_data)
    self._AddParameter('color', params, profile_data)

    # Each case below has to set either error or redirect
    database = self._GetDatabase()
    message = None
    new_cookie_text = None
    action = self._GetParameter(params, 'action')
    if action == 'new':
      if uid in database:
        message = 'User already exists.'
      else:
        profile_data['pw'] = newpw
        database[uid] = profile_data
        (cookie, new_cookie_text) = self._CreateCookie('GRUYERE', uid)
        message = 'Account created.'  # error message can also indicates success
    elif action == 'update':
      if uid not in database:
        message = 'User does not exist.'
      elif (newpw and database[uid]['pw'] != self._GetParameter(params, 'oldpw')
            and not cookie.get(COOKIE_ADMIN)):
        # must be admin or supply old pw to change password
        message = 'Incorrect password.'
      else:
        if newpw:
          profile_data['pw'] = newpw
        database[uid].update(profile_data)
        redirect = '/'
    else:
      message = 'Invalid request'
    _Log('SetProfile(%s, %s): %s' %(str(uid), str(action), str(message)))
    if message:
      self._SendError(message, cookie, specials, params, new_cookie_text)
    else:
      self._SendRedirect(redirect, specials[SPECIAL_UNIQUE_ID])

  def _SendHtmlResponse(self, html, new_cookie_text=None):
      """Sends the provided HTML response with appropriate headers.
  
      Args:
        html: The response HTML.
        new_cookie_text: New cookie to set.
      """
      # Send the response headers
      #self.send_response(200)
      self.send_header('Content-type', 'text/html')
      self.send_header('Pragma', 'no-cache')
  
      # Debugging output for the cookie
      if new_cookie_text:
          print(f"Setting cookie: {new_cookie_text}")  # Debug print to see the cookie text
          self.send_header('Set-Cookie', new_cookie_text)
      else:
          print("No new cookie to set.")  # Indicate that no cookie is being set
  
      self.send_header('X-XSS-Protection', '0')
  
      # Instead of ending headers and writing to wfile, we simply collect the response body

  
      # Write the HTML response to the response body
      #self.send_response(200)
      self.write(html.encode())  # Collect the HTML as bytes
      #print("html: " + html)
      self.send_response(200)
  


  def _SendTextResponse(self, text, new_cookie_text=None):
    """Sends a verbatim text response."""

    self._SendHtmlResponse('<pre>' + html.escape(text) + '</pre>', new_cookie_text)

  def _SendTemplateResponse(self, filename, specials, params,
                            new_cookie_text=None):
    """Sends a response using a gtl template.

    Args:
      filename: The template file.
      specials: Other special values for this request.
      params: Cgi parameters.
      new_cookie_text: New cookie to set.
    """
    f = None
    try:
      f = _Open(RESOURCE_PATH, filename)
      template = f.read()
    finally:
      if f: f.close()
    
    #print("Template: " + template)
    self._SendHtmlResponse(
        gtl.ExpandTemplate(template, specials, params),
        new_cookie_text)

  def _SendFileResponse(self, filename, cookie, specials, params):
      """Sends the contents of a file.

      Args:
        filename: The file to send.
        cookie: The cookie for this request.
        specials: Other special values for this request.
        params: CGI parameters.
      """
      content_type = None
      if filename.endswith('.gtl'):
          self._SendTemplateResponse(filename, specials, params)
          return

      name_only = filename[filename.rfind('/'):]
      extension = name_only[name_only.rfind('.'):]

      if '.' not in extension:
          content_type = 'text/plain'
      elif extension in RESOURCE_CONTENT_TYPES:
          content_type = RESOURCE_CONTENT_TYPES[extension]
      else:
          self._SendError(
              'Unrecognized file type (%s).' % (filename,),
              cookie, specials, params)
          return

      f = None
      try:
          f = _Open(RESOURCE_PATH, filename, 'rb')
          file_contents = f.read()  # Read the file contents into memory

          #self.send_response(200)  # Send the response status
          self.send_header('Content-type', content_type)  # Set the content type
          # Always cache static resources
          self.send_header('Cache-control', 'public, max-age=7200')
          self.send_header('X-XSS-Protection', '0')
          #self.send_response(200)


          # Write the file contents to the response body
          self.write(file_contents)  # Collect the file contents as bytes
          self.send_response(200)
      finally:
          if f:
              f.close()  # Ensure the file is closed properly


  def _SendError(self, message, cookie, specials, params, new_cookie_text=None):
    """Sends an error message (using the error.gtl template).

    Args:
      message: The error to display.
      cookie: The cookie for this request. (unused)
      specials: Other special values for this request.
      params: Cgi parameters.
      new_cookie_text: New cookie to set.
    """
    specials['_message'] = message
    self._SendTemplateResponse(
        '/error.gtl', specials, params, new_cookie_text)

  def _CreateCookie(self, cookie_name, uid):
    """Creates a cookie for this user.
  
    Args:
      cookie_name: Cookie to create.
      uid: The user.
  
    Returns:
      (cookie, new_cookie_text).
    """
    if uid is None:
        print("Creating NULL cookie: uid is None")
        return (self.NULL_COOKIE, cookie_name + '=; path=/')
    
    database = self._GetDatabase()
    profile = database[uid]
  
    is_author = 'author' if profile.get('is_author', False) else ''
    is_admin = 'admin' if profile.get('is_admin', False) else ''
  
    c = {COOKIE_UID: uid, COOKIE_ADMIN: is_admin, COOKIE_AUTHOR: is_author}
    c_data = '%s|%s|%s' % (uid, is_admin, is_author)
  
    h_data = str(hash(cookie_secret + c_data) & 0x7FFFFFF)
    c_text = '%s=%s|%s; path=/' % (cookie_name, h_data, c_data)
  
    # Debugging outputs
    print(f"Creating cookie: {cookie_name}")
    print(f"UID: {uid}, is_admin: {is_admin}, is_author: {is_author}")
    print(f"Cookie text: {c_text}")
  
    return (c, c_text)
  

  def _GetCookie(self, cookie_name):
    """Reads, verifies and parses the cookie.

    Args:
      cookie_name: The cookie to get.

    Returns:
      a dict containing user, is_admin, and is_author if the cookie
      is present and valid. Otherwise, None.
    """
    cookies = self.request_headers.get('Cookie')
    if isinstance(cookies, str):
      for c in cookies.split(';'):
        matched_cookie = self._MatchCookie(cookie_name, c)
        if matched_cookie:
          return self._ParseCookie(matched_cookie)
    return self.NULL_COOKIE

  def _MatchCookie(self, cookie_name, cookie):
    """Matches the cookie.

    Args:
      cookie_name: The name of the cookie.
      cookie: The full cookie (name=value).

    Returns:
      The cookie if it matches or None if it doesn't match.
    """
    try:
      (cn, cd) = cookie.strip().split('=', 1)
      if cn != cookie_name:
        return None
    except (IndexError, ValueError):
      return None
    return cd

  def _ParseCookie(self, cookie):
    """Parses the cookie and returns NULL_COOKIE if it's invalid.

    Args:
      cookie: The text of the cookie.

    Returns:
      A map containing the values in the cookie.
    """
    try:
      (hashed, cookie_data) = cookie.split('|', 1)
      # global cookie_secret
      if hashed != str(hash(cookie_secret + cookie_data) & 0x7FFFFFF):
        return self.NULL_COOKIE
      values = cookie_data.split('|')
      return {
          COOKIE_UID: values[0],
          COOKIE_ADMIN: values[1] == 'admin',
          COOKIE_AUTHOR: values[2] == 'author',
      }
    except (IndexError, ValueError):
      return self.NULL_COOKIE

  def _DoReset(self, cookie, specials, params):  # debug only; resets this db
    """Handles the /reset url for administrators to reset the database.

    Args:
      cookie: The cookie for this request. (unused)
      specials: Other special values for this request. (unused)
      params: Cgi parameters. (unused)
    """
    self._ResetDatabase()
    self._SendTextResponse('Server reset to default values...', None)
    
  def _DoUpload2(self, cookie, specials, params):
      """Handles the /upload2 URL: finish the upload and save the file.
  
      Args:
          cookie: The cookie for this request.
          specials: Other special values for this request.
          params: CGI parameters. (unused)
      """
      (filename, file_data) = self._ExtractFileFromRequest()
      directory = self._MakeUserDirectory(cookie[COOKIE_UID])
  
      message = None
      url = None
      try:
          with open(f"{directory}/{filename}", 'wb') as f:
              print(f"Writing file to: {directory}/{filename}")
              f.write(file_data)
              print("File write completed successfully.")
  
          # Get host and port from the WSGI environment
          host = self.environ.get('HTTP_HOST', 'localhost')
          #port = self.environ.get('SERVER_PORT', '80')  # Default to 80 if not specified
  
          # Generate the URL for the uploaded file
          url = f'http://{host}/{cookie[COOKIE_UID]}/{filename}'
          print(f"File URL generated: {url}")
      except IOError as ex:
          message = f'Couldn\'t write file {filename}: {ex}'
          print(f"IOError occurred: {message}")
          self._Log(message)
  
      specials['_message'] = message
      self._SendTemplateResponse('/upload2.gtl', specials, {'url': url})
  
  
  def _ExtractFileFromRequest(self):
      """Extracts the file from an upload request.
  
      Returns:
        (filename, file_data)
      """
      print("Starting _ExtractFileFromRequest...")
  
      content_type = self.request_headers.get('Content-Type', '')
      print(f"Received Content-Type: {content_type}")
      
      if not content_type.startswith('multipart/form-data'):
          raise ValueError("Expected multipart/form-data content type.")
  
      # Read the input stream
      content_length = int(self.request_headers.get('Content-Length', 0))
      body = self.rfile.read(content_length)
  
      # Parse the multipart data
      boundary = content_type.split('=')[1].encode('utf-8')
      parts = body.split(b'--' + boundary)
  
      # Find the part that contains the uploaded file
      for part in parts:
          if b'Content-Disposition' in part and b'filename="' in part:
              headers, file_data = part.split(b'\r\n\r\n', 1)
              # Extract the filename
              filename = self._get_filename_from_headers(headers)
              file_data = file_data.rstrip(b'\r\n')  # Remove trailing CRLF
              print(f"Upload file: {filename}, size: {len(file_data)} bytes")
              return (filename, file_data)
  
      raise KeyError("No file part found in the request.")
  

  def _get_filename_from_headers(self, headers):
      """Extract the filename from the Content-Disposition header."""
      header_str = headers.decode('utf-8')
      for line in header_str.splitlines():
          if line.startswith('Content-Disposition'):
              # Extract filename from the header
              for part in line.split(';'):
                  if 'filename=' in part:
                      return part.split('=')[1].strip('"')
      return None
  

  def _MakeUserDirectory(self, uid):
    """Creates a separate directory for each user to avoid upload conflicts.

    Args:
      uid: The user to create a directory for.

    Returns:
      The new directory path (/uid/).
    """

    directory = RESOURCE_PATH + os.sep + str(uid) + os.sep
    try:
      print('mkdir: ', directory)
      os.mkdir(directory)
      # throws an exception if directory already exists,
      # however exception type varies by platform
    except Exception:
      pass  # just ignore it if it already exists
    return directory

  def _SendRedirect(self, url, unique_id):
      """Sends a 302 redirect.

      Automatically adds the unique_id.

      Args:
        url: The location to redirect to which must start with '/'.
        unique_id: The unique id to include in the url.
      """
      if not url:
          url = '/'

      #url = '/' + unique_id + url  # Build the redirect URL
      #self.send_response(302)  # Set the response status to 302
      self.send_header('Location', url)  # Set the Location header
      self.send_header('Pragma', 'no-cache')  # No cache
      self.send_header('Content-type', 'text/html')  # Content type
      self.send_header('X-XSS-Protection', '0')  # XSS protection header
      self.send_response(302)

      # Prepare the response body for the redirect message
      res = f'''<!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML//EN'>
      <html><body>
      <title>302 Redirect</title>
      Redirected <a href="{url}">here</a>
      </body></html>'''

      # Write the response body
      self.write(res.encode())  # Collect the response message as bytes


  def _GetHandlerFunction(self, path):
    try:
      return getattr(GruyereRequestHandler, '_Do' + path[1:].capitalize())
    except AttributeError:
      return None
  
  def do_POST(self):  # part of BaseHTTPRequestHandler interface
    print(f"Handling POST request: {self.path}")  # Debug print for POST request
    self.DoGetOrPost()
  
  def do_GET(self):  # part of BaseHTTPRequestHandler interface
    print(f"Handling GET request: {self.path}")  # Debug print for GET request
    self.DoGetOrPost()
  
  def DoGetOrPost(self):
    """Validate an http get or post request and call HandleRequest."""
  
    path = self.path  # Use the path from WSGIHandler
    query = self.query  # Use the query string from WSGIHandler
    print(f"Request details: method={self.command}, path={path}, query={query}, server_unique_id={server_unique_id}")  # Debug info
  
    self.HandleRequest(path, query, server_unique_id)
  

     #Network Security settings
  
      #allowed_ips = ['127.0.0.1']
  #
      #request_ip = self.client_address[0]
      #if request_ip not in allowed_ips:
      #  print((
      #      'DANGER! Request from bad ip: ' + request_ip), file=sys.stderr)
      #  _Exit('bad_ip')
  
      #if (server_unique_id not in path
      #    and path != '/favicon.ico'):
      #  if path == '' or path == '/':
      #    self._SendRedirect('/', server_unique_id)
      #    return
      #  else:
      #    print((
      #        'DANGER! Request without unique id: ' + path), file=sys.stderr)
      #    #_Exit('bad_id')
  
      #path = path.replace('/' + server_unique_id, '', 1)
  
      #self.HandleRequest(path, query, server_unique_id)

  def HandleRequest(self, path, query, unique_id):
    """Handles an http request."""
    
    print(f"Handling request: path={path}, query={query}, unique_id={unique_id}")
    path = urllib.parse.unquote(path)
    
    if not path:
        self._SendRedirect('/', server_unique_id)
        return
    
    params = urllib.parse.parse_qs(query)  # url.query
    specials = {}
    cookie = self._GetCookie('GRUYERE')
    
    # Debugging output for cookie retrieval
    print(f"Retrieved cookie: {cookie}")
    
    database = self._GetDatabase()
    specials[SPECIAL_COOKIE] = cookie
    specials[SPECIAL_DB] = database
    specials[SPECIAL_PROFILE] = database.get(cookie.get(COOKIE_UID))
    specials[SPECIAL_PARAMS] = params
    specials[SPECIAL_UNIQUE_ID] = unique_id
    
    if path in self._PROTECTED_URLS and not cookie[COOKIE_ADMIN]:
        self._SendError('Invalid request', cookie, specials, params)
        return
    
    try:
        handler = self._GetHandlerFunction(path)
        if callable(handler):
            (handler)(self, cookie, specials, params)
        else:
            try:
                self._SendFileResponse(path, cookie, specials, params)
            except IOError:
                self._DoBadUrl(path, cookie, specials, params)
    except KeyboardInterrupt:
        _Exit('KeyboardInterrupt')
  
  


def _Log(message):
  print(message, file=sys.stderr)

class WSGIHandler(GruyereRequestHandler):
    """WSGI handler that integrates with the WSGI server."""

    def __init__(self, environ, start_response):
        # Initialize base class
        self.environ = environ
        self.start_response = start_response
        self.requestline = f"{environ['REQUEST_METHOD']} {environ['PATH_INFO']} HTTP/1.1"
        self.command = environ['REQUEST_METHOD']
        self.path = environ['PATH_INFO']
        self.query = environ.get('QUERY_STRING', '')  # Get the query string directly
        self.request_version = "HTTP/1.1"  # Set the request version
        self.request_headers = self._build_request_headers(environ)
        self.response_headers = {}  # Separate dictionary for response headers
        self.rfile = environ['wsgi.input']  # Prepare input stream
        self.response_body = []  # Initialize an empty list to collect response body data
    
    def _build_request_headers(self, environ):
        """Build headers from WSGI environ for incoming request headers."""
        request_headers = {}
        # Process HTTP headers from the client request
        for key, value in environ.items():
            if key.startswith('HTTP_'):
                header_key = key[5:].replace('_', '-').title()
                request_headers[header_key] = value
                    
        # Add any non-HTTP headers explicitly
        if 'CONTENT_TYPE' in environ:
            request_headers['Content-Type'] = environ['CONTENT_TYPE']
        if 'CONTENT_LENGTH' in environ:
            request_headers['Content-Length'] = environ['CONTENT_LENGTH']
        
        return request_headers
    
    
    def send_header(self, key, value):
        """Send a header."""
        print(f"Sending header: {key}: {value}")  # Debugging output
        self.response_headers[key] = value
    
    def send_response(self, code):
        """Send an HTTP response."""
        headers_list = [(key, value) for key, value in self.response_headers.items()]  # Prepare headers
        self.start_response(f"{code} {self.responses[code][0]}", headers_list)
    
        # Debugging output for the response headers
        print(f"Sending response: {code} {self.responses[code][0]}")
        print("Response headers:")
        for header in headers_list:
            print(f"  {header[0]}: {header[1]}")
        
        self.response_headers.clear()  # Clear headers after sending
    

    def write(self, data):
        """Collect response data."""
        self.response_body.append(data)

    def flush(self):
        """Flush the collected response data."""
        # Combine the collected data into a bytes object
        response_data = b''.join(self.response_body)
        return response_data  # Return response data for WSGI to send




def application(environ, start_response):
    """WSGI application using the GruyereRequestHandler."""
    #global stored_data

    # Remove hop-by-hop headers
    environ.pop('HTTP_CONNECTION', None)

    handler = WSGIHandler(environ, start_response)

    # Call the method based on the request method
    if handler.command in ['GET', 'POST']:
        if handler.command == 'GET':
            handler.do_GET()  # This should be defined in GruyereRequestHandler
        else:
            handler.do_POST()  # This should be defined in GruyereRequestHandler
    else:
        handler.send_response(405)  # Method Not Allowed
        return [b"405 Method Not Allowed"]

    # Collect the response body and flush it
    response_body = handler.flush()  # Get the combined response data

    # Save the database after handling the request
    _SaveDatabase(stored_data)

    return [response_body]  # Return the collected response as bytes




stored_data = _LoadDatabase()

#from wsgiref.simple_server import make_server
#
#def main():
#    """Main function to serve the WSGI application."""
#    #global stored_data
#    #stored_data = _LoadDatabase()
#    # Set the host and port for the server
#    host = 'localhost'
#    port = 8000
#
#    # Create a WSGI server
#    httpd = make_server(host, port, application)
#
#    print(f"Serving on http://{host}:{port}...")
#    
#    # Serve until process is killed
#    try:
#        httpd.serve_forever()
#    except KeyboardInterrupt:
#        print("\nShutting down the server...")
#    finally:
#        httpd.server_close()
#        print("Server closed.")
#
#if __name__ == "__main__":
#    main()

