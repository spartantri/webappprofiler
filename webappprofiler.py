#!/usr/bin/env python
# -------------------------------------------------------------------------------
# Name:        WebApp Profiler for ZAP
# Purpose:     Script for parsing persistent ZAP session file
#
# Author:      spartantri
#
# Created:     17/06/2016
# Copyright:   (c) mleos 2016
# License:     GPLv3
# -------------------------------------------------------------------------------
import re
import sqlite3
import time
import urlparse
import ast
# import xml.etree.cElementTree as ET
# import logging
# from pprint import pprint
from zapv2 import ZAPv2
from http_parser.pyparser import HttpParser
from tabulate import tabulate
from xml.etree import ElementTree
from xml.etree.ElementTree import Element, SubElement, Comment, tostring
from bs4 import BeautifulSoup

# from sys import stdout
# from sets import Set
# from urlparse import urlparse

# Initialization variables
zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})
parseablecodes = (200, 301, 302, 304, 401, 500, 501)
simple_regexes = {}
complex_regexes = {}
blacklist_regexes = {}
when_everything_goes_bad_regexes = {}
# Working database
db = sqlite3.connect('../ZAPParser.sqlite', timeout=11)
cur = db.cursor()
# Set print_details to generate and print row array in memory
print_details = 0
output_file = 'test.xml'
audit_log = 'modsec_audit.log'
id_site = 0
modsecurity_starting_ruleid = 9990000

def init_db(cur, zero=False):
    """Initialize database for aggregation.

    Initialize database to use aggregation capabilites for complex arrays."""
    # Database Structure
    profiledb = {'sites': 'CREATE TABLE IF NOT EXISTS sites (id_site INTEGER PRIMARY KEY, site TEXT, UNIQUE (site))',
                 'messages': 'CREATE TABLE IF NOT EXISTS messages (id_message INTEGER PRIMARY KEY, ' +
                             'requestHeader TEXT, requestBody TEXT, responseHeader TEXT, responseBody TEXT, ' +
                             'cookieParams TEXT, note TEXT)',
                 'resources': 'CREATE TABLE IF NOT EXISTS resources (id_resource INTEGER PRIMARY KEY, ' +
                              'id_site INTEGER, resource TEXT, public TEXT, scheme TEXT, method TEXT, ' +
                              'min_requestsize INTEGER, max_requestsize INTEGER, min_responsesize INTEGER, ' +
                              'max_responsesize INTEGER, UNIQUE (id_site, resource, scheme, method))',
                 'headers': 'CREATE TABLE IF NOT EXISTS headers (id_header INTEGER PRIMARY KEY, ' +
                            'id_resource INTEGER, header TEXT, required TEXT, regex TEXT, UNIQUE(id_resource, header))',
                 'grouping_resources': 'CREATE TABLE IF NOT EXISTS grouping_resources (id_group INTEGER PRIMARY KEY, ' +
                                       'group_name TEXT, regex TEXT)',
                 'parameters': 'CREATE TABLE IF NOT EXISTS parameters (id_parameters INTEGER PRIMARY KEY, ' +
                               'id_resource INTEGER, parameter TEXT, required TEXT, regex_pos TEXT, regex_neg TEXT, ' +
                               'encoding TEXT, sanitize TEXT, UNIQUE(id_resource, parameter))',
                 'cookies': 'CREATE TABLE IF NOT EXISTS cookies (id_cookie INTEGER PRIMARY KEY, ' +
                            'id_resource INTEGER, cookie TEXT, required TEXT, regex TEXT, flags TEXT, path TEXT,' +
                            'expiry TEXT, encoding TEXT, sanitize TEXT, UNIQUE(id_resource,cookie))',
                 'regexes': 'CREATE TABLE IF NOT EXISTS regexes (id_regexes INTEGER PRIMARY KEY, ' +
                            'name TEXT, purpose TEXT, regex TEXT, UNIQUE(name))',
                 'summary': 'CREATE TABLE IF NOT EXISTS summary (id_message INTEGER PRIMARY KEY, scheme TEXT, ' +
                            'method TEXT, resource TEXT, num_parameter INTEGER, parameters TEXT, regex_pos TEXT, ' +
                            'regex_neg TEXT, num_httpheader INTEGER, httpheaders TEXT, regex_httpheader_pos TEXT, ' +
                            'regex_httpheader_neg TEXT, num_cookies INTEGER, cookies TEXT, regex_cookie_pos TEXT, ' +
                            'regex_cookie_neg TEXT)'}
    if zero:
        for table in profiledb:
            cur.execute('DROP TABLE IF EXISTS ' + table)
    for table in profiledb:
        cur.execute(profiledb[table])
    return


def mandatory_header(filtered, http_header):
    """Define mandatory http headers.

    Define mandatory http headers"""
    mandatory_headers = {'HOST': filtered, 'USER-AGENT': True, 'REFERER': True}
    if http_header in mandatory_headers:
        return mandatory_headers[http_header]
    return False


def mandatory_parameter(filtered, parameter):
    """Define mandatory parameters.

    Define mandatory parameters"""
    mandatory_parameters = {'Username': True, 'Password': True, 'SessionID': True}
    if parameter in mandatory_parameters:
        return mandatory_parameters[parameter]
    return False


def mandatory_cookie(filtered, cookie):
    """Define mandatory cookie.

    Define mandatory cookie"""
    mandatory_cookies = {'SessionID': True}
    if cookie in mandatory_cookies:
        return mandatory_cookies[cookie]
    return False

def parse_http(rsp):
    """Define parser.

    Define HttpParser"""
    p = HttpParser()
    p.execute(rsp, len(rsp))
    return p


def find_id(zapid):
    """Find zap request id.

    Find the request id in the persistent session file that matches the index."""
    requests = zap.core.messages()
    for idx, r in enumerate(requests):
        if int(r["id"]) == zapid:
            return idx
    return False


def site_filter():
    """Set a site filter.

    Lists all the sites and ask to choose one to set it as a filter for the data extraction."""
    while True:
        try:
            site_list = []
            for idx, site in enumerate(zap.core.sites):
                site_list.append(urlparse.urlparse(site).netloc)
                print idx, urlparse.urlparse(site).netloc
            site_filter = int(raw_input("Coose a site : "))
            print "Setting site filter to: %s" % (site_list[site_filter])
            return str(site_list[site_filter])
        except:
            print "Wrong selection, try again"
            time.sleep(2)


def regex_builder():
    """Setup global regex variables.

    Creates the global variables including the different regular expressions to use in pattern identification."""
    global simple_regexes, complex_regexes, blacklist_regexes, when_everything_goes_bad_regexes
    # Simple regexes
    simple_regexes = {'0numeric': '[\d]+', '1alphabetic': '[a-zA-Z]+', '2hex': '[a-fA-F0-9]+',
                      '3alphanumeric': '[a-zA-Z0-9]+', 'punctuation': '[,\.\'\-_]+', '5b64': '[a-zA-Z0-9+/=]+'}
    simple_regexes.update({'6numeric_punctuation': '{0}{1}'.format(simple_regexes['punctuation'],
                                                                   simple_regexes['0numeric'])})
    simple_regexes.update({'7alphabetic_punctuation': '{0}{1}'.format(simple_regexes['punctuation'],
                                                                      simple_regexes['1alphabetic'])})
    simple_regexes.update({'8alphanumeric_punctuation': "{0}{1}".format(simple_regexes['punctuation'],
                                                                        simple_regexes['3alphanumeric'])})
    # Complex regexes
    octet = ' 25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}?'
    ip_regex = {'ips': '\b(?:' + octet + '\.){3}(?:' + octet + ')\b'}
    complex_regexes.update(ip_regex)
    date_m = '(?:0?[1-9]|1[012])'
    date_d = '(?:0?[1-9]|[12][0-9]|3[01])'
    date_Y = '(?:19|20)?[0-9]{2}'
    date_y = '[0-9]{2})'
    date_separator = '([- /.])'
    date_regex = {'datemdY': date_m + date_separator + date_d + '\1' + date_Y,
                  'dateYdm': date_Y + date_separator + date_d + '\1' + date_m,
                  'datedmY': date_d + date_separator + date_m + '\1' + date_Y}
    email_regex = {'email': '[a-zA-Z0-9_\.\+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-\.]+'}
    base64_regex = {'base64': '(?:[a-zA-Z0-9+/]{3})*(?:[a-zA-Z0-9+/]{1}==|[a-zA-Z0-9+/]{2}=)?'}
    complex_regexes.update(date_regex)
    complex_regexes.update(email_regex)
    complex_regexes.update(base64_regex)
    # Other regexes
    blacklist_regexes = {'command': '[&;|\$`]', 'redirect': '[<>]', 'path': '[/\\\\]', 'group': '[\(\)\{\}]'}
    when_everything_goes_bad_regexes = {'hailmary': '.*'}


def regex_positive(match_this):
    """Identify which regex better matches the expresion.

        Identify which PCRE regex better matches a given value to use for validation using modsecurity rules."""
    global simple_regexes, complex_regexes, blacklist_regexes, when_everything_goes_bad_regexes
    regex_begin = '^['
    payload_lenght = str(len(match_this))
    regex_trail = ']{' + payload_lenght + '}$'
    for regex_test in sorted(simple_regexes.keys()):
        regex = regex_begin + simple_regexes[regex_test] + regex_trail
        if re.match(regex, match_this):
            return regex_test, payload_lenght
    return 'hailmary', payload_lenght


def regex_negative(match_this):
    """Identify possible problematic characters.

    Identify characters or expressions that may cause problems with filtering."""
    global simple_regexes, complex_regexes, blacklist_regexes, when_everything_goes_bad_regexes
    matches = []
    regex_begin = '['
    regex_trail = ']+'
    for regex_test in blacklist_regexes.keys():
        regex = regex_begin + blacklist_regexes[regex_test] + regex_trail
        if re.search(regex, match_this):
            matches.append(regex_test)
    return matches


def regex_specific(match_this, regex_test):
    """Identify specific regex matches.

        Identify if a particular regex in the global variables matches the expresion."""
    global simple_regexes, complex_regexes, blacklist_regexes, when_everything_goes_bad_regexes
    payload_lenght = str(len(match_this))
    if regex_test in simple_regexes:
        # .has_key(regex_test):
        if re.match(simple_regexes[regex_test], match_this):
            payload_lenght = str(len(match_this))
            return regex_test, payload_lenght
    elif regex_test in complex_regexes:
        # .has_key(regex_test):
        if re.match(complex_regexes[regex_test], match_this):
            return regex_test, payload_lenght
    return 'hailmary', when_everything_goes_bad_regexes['hailmary']


def regex_comparer(regex1, regex2):
    if regex1[0] > regex2[0]:
        return regex1
    else:
        return regex2
    pass


def make_sets(rows):
    pass


def write_message(requests, cookieparams='', note=''):
    """Write messages into database.

            Write messages from requests and responses into database."""
    # if isinstance(foo, basestring):
    #    foo.encode('utf8')
    # else:
    #    unicode(foo).encode('utf8')
    requestheader = unicode(requests["requestHeader"])
    requestbody = unicode(requests["requestBody"])
    responseheader = unicode(requests["responseHeader"])
    responsebody = unicode(requests["responseBody"])
    db.execute('INSERT INTO messages (id_message, requestHeader, requestBody, responseHeader, responseBody,' +
               'cookieParams, note) VALUES (?, ?, ?, ?, ?, ?, ?)',
               (int(requests["id"]), requestheader, requestbody, responseheader, responsebody, cookieparams, note))
    db.commit()
    return


def write_headers(id_resource, item_details, detected_headers):
    # header = ['id_resource', 'header', 'regex+', 'regex-']
    # row_summary = []
    for detail in item_details:
        http_headers = detail[8]
        http_headers_regex_pos = ast.literal_eval(detail[9])
        http_headers_regex_neg = ast.literal_eval(detail[10])
        # row_summary.append([id_resource, http_headers, http_headers_regex_pos, http_headers_regex_neg])
        for http_header in http_headers_regex_pos:
            if http_header in detected_headers:
                if http_headers_regex_pos[http_header] == detected_headers[http_header]:
                    pass
                else:
                    print 'Type mismatch:', http_header, http_headers_regex_pos[http_header], \
                        detected_headers[http_header],
                    detected_headers[http_header] = regex_comparer(http_headers_regex_pos[http_header],
                                                                   detected_headers[http_header])
                    print ' Updated to: ', detected_headers[http_header]
            else:
                detected_headers[http_header] = http_headers_regex_pos[http_header]
    # print tabulate([line for line in row_summary], headers=header)
    for http_header in detected_headers:
        cur.execute('INSERT OR IGNORE INTO headers (id_resource, header, regex) VALUES (?, ?, ?)',
                    (id_resource, http_header, detected_headers[http_header]))
        db.commit()
    return detected_headers


def write_cookies(id_resource, item_details, detected_cookies):
    # import Cookie
    # cookies = Cookie.SimpleCookie()
    # cookies.load(item_details)
    for detail in item_details:
        cookies = detail[12]
        cookie_regex_pos = ast.literal_eval(detail[13])
        cookie_regex_neg = ast.literal_eval(detail[14])
        for cookie in cookie_regex_pos:
            if cookie in detected_cookies:
                if cookie_regex_pos[cookie] == detected_cookies[cookie]:
                    pass
                else:
                    print 'Type mismatch:', cookie, cookie_regex_pos[cookie], \
                        detected_cookies[cookie],
                    detected_cookies[cookie] = regex_comparer(cookie_regex_pos[cookie],
                                                              detected_cookies[cookie])
                    print ' Updated to: ', detected_cookies[cookie]
            else:
                detected_cookies[cookie] = cookie_regex_pos[cookie]
    for cookie in detected_cookies:
        cur.execute('INSERT OR IGNORE INTO cookies (id_resource, cookie, regex) VALUES (?, ?, ?)',
                    (id_resource, cookie, detected_cookies[cookie]))
    return detected_cookies


def write_parameters(id_resource, item_details, detected_parameters):
    # header = ['id_resource', 'argument', 'regex+', 'regex-']
    # row_summary = []
    for detail in item_details:
        parameters = detail[4]
        parameters_regex_pos = ast.literal_eval(detail[5])
        parameters_regex_neg = ast.literal_eval(detail[6])
        # row_summary.append([id_resource, parameters, parameters_regex_pos, parameters_regex_neg])
        for parameter in parameters_regex_pos:
            if parameter in detected_parameters:
                if parameters_regex_pos[parameter] == detected_parameters[parameter]:
                    pass
                else:
                    print 'Type mismatch:', parameter, parameters_regex_pos[parameter], detected_parameters[parameter],
                    detected_parameters[parameter] = regex_comparer(parameters_regex_pos[parameter],
                                                                    detected_parameters[parameter])
                    print ' Updated to: ', detected_parameters[parameter]
            else:
                detected_parameters[parameter] = parameters_regex_pos[parameter]
    # print tabulate([line for line in row_summary], headers=header)
    for parameter in detected_parameters:
        cur.execute('INSERT OR IGNORE INTO parameters (id_resource, parameter, regex_pos) VALUES (?, ?, ?)',
                    (id_resource, parameter, detected_parameters[parameter]))
        db.commit()
    return detected_parameters


def write_regexes():
    global simple_regexes, complex_regexes, blacklist_regexes, when_everything_goes_bad_regexes
    all_regexes = {}
    all_regexes.update(simple_regexes)
    all_regexes.update(complex_regexes)
    all_regexes.update(blacklist_regexes)
    all_regexes.update(when_everything_goes_bad_regexes)
    for item in all_regexes:
        cur.execute('INSERT OR IGNORE INTO regexes (name, regex) VALUES (?, ?)', (item, all_regexes[item]))
        db.commit()
    return


def parse_summary(filtered):
    detected_parameters, detected_headers, detected_cookies = {}, {}, {}
    global id_site
    cur.execute('SELECT DISTINCT scheme, method, resource FROM summary')
    items_to_parse = cur.fetchall()
    site = str(filtered)
    cur.execute('INSERT OR IGNORE INTO sites (site) VALUES (?)', (site,))
    db.commit()
    id_site = cur.lastrowid
    # cur.execute('SELECT id_site from sites WHERE site=?', (site,))
    # id_site = int(cur.fetchone()[0])
    for item in items_to_parse:
        cur.execute('INSERT OR IGNORE INTO resources (id_site, scheme, method, resource) VALUES (?, ?, ?, ?)',
                    (id_site, item[0], item[1], item[2]))
        db.commit()
        id_resource = cur.lastrowid
        cur.execute('SELECT DISTINCT scheme, method, resource, num_parameter, parameters, regex_pos, regex_neg, ' +
                    'num_httpheader, httpheaders, regex_httpheader_pos, regex_httpheader_neg, num_cookies, cookies, ' +
                    'regex_cookie_pos, regex_cookie_neg FROM summary ' +
                    'WHERE scheme=? and method=? and resource=?', (item[0], item[1], item[2]))
        item_details = cur.fetchall()
        detected_headers = write_headers(id_resource, item_details, detected_headers)
        detected_parameters = write_parameters(id_resource, item_details, detected_parameters)
        detected_cookies = write_cookies(id_resource, item_details,detected_cookies)
        # print id_resource
        # print detected_parameters
        # print detected_headers
    pass


def parse_cookies(cookies):
    """Parse cookies.

                    Parse cookies, and return dictionary with cookie name as key and all details as value."""
    import Cookie
    parsed_cookies = {}
    # print cookies
    cookie_string = str(cookies)
    cookie_list = cookie_string.split(';')
    # cookie_list = Cookie.SimpleCookie()
    # cookie_list.load(cookies)
    for item in cookie_list:
        # print type(item), item, item.split('=',1)[0], item.split('=',1)[1]
        parsed_cookies.update({item.split('=', 1)[0].strip(): item.split('=', 1)[1]})
    # print parsed_cookies
    return parsed_cookies


def get_source():
    if audit_log:
        return auditlog_reader()
    else:
        return zap.core.messages()

def parse_connection_database(filtered):
    """Parse contents and dump into database.

                Parse contents, summarize data and dump into database."""
    header = ['ID', 'SCHEME', 'METHOD', 'URI', '#ARG', 'ARGS', 'REGEX+', 'REGEX-', '#HEA', 'HEAD', 'HREGEX+', 'HREGEX-',
              '#COO', 'COOK', 'CREGEX+', 'CREGEX-']
    rows = []
    source = get_source()
    for requests in source:
        p = parse_http(requests["responseHeader"])
        if p.get_status_code() in parseablecodes:
            p = parse_http(requests["requestHeader"])
            url = p.get_url()
            url_parsed = urlparse.urlparse(url)
            url_netloc = url_parsed.netloc
            if filtered == url_netloc or filtered == 'auditlog':
                method = p.get_method()
                # tuple (1, 1)
                version = p.get_version()
                uri = p.get_path()
                querystring = p.get_query_string()
                wsgi_environ = p.get_wsgi_environ()
                parsed_cookies = {}
                if 'HTTP_HOST' in wsgi_environ:
                    # if wsgi_environ.has_key("HTTP_HOST"):
                    http_host = wsgi_environ['HTTP_HOST']
                if 'HTTP_ORIGIN' in wsgi_environ:
                    # if wsgi_environ.has_key("HTTP_ORIGIN"):
                    http_origin = wsgi_environ['HTTP_ORIGIN']
                if 'HTTP_REFERER' in wsgi_environ:
                    # if wsgi_environ.has_key("HTTP_REFERER")
                    http_referer = wsgi_environ['HTTP_REFERER']
                if 'HTTP_ACCEPT' in wsgi_environ:
                    # if wsgi_environ.has_key("HTTP_ACCEPT"):
                    http_accept = wsgi_environ['HTTP_ACCEPT']
                if 'HTTP_COOKIE' in wsgi_environ:
                    cookies = wsgi_environ['HTTP_COOKIE']
                    parsed_cookies = parse_cookies(cookies)
                    # TO BE USED IN LOOP SIMILAR TO querystring_arguments
                url_scheme = url_parsed.scheme
                querystring_arguments = urlparse.parse_qs(querystring)
                regex_request_positive = {}
                regex_request_negative = {}
                regex_request_http_positive = {}
                regex_request_http_negative = {}
                regex_request_cookie_positive = {}
                regex_request_cookie_negative = {}
                for argument in querystring_arguments:
                    regex = regex_positive(str(querystring_arguments[argument][0]))
                    # print str(querystring_arguments[argument][0])
                    # print regex
                    if regex[0] == 'hailmary':
                        regex_bad = regex_negative(str(querystring_arguments[argument][0]))
                        regex_request_negative.update({str(argument): regex_bad})
                    elif regex[0] == '5b64':
                        regex = regex_specific(str(querystring_arguments[argument][0]), 'base64')
                    regex_request_positive.update({str(argument): regex[0]})
                for httpheader in p.get_headers():
                    regex = regex_positive(str(p.get_headers()[httpheader]))
                    if regex[0] == 'hailmary':
                        regex_bad = regex_negative(str(p.get_headers()[httpheader]))
                        regex_request_http_negative.update({str(httpheader): regex_bad})
                    elif regex[0] == '5b64':
                        regex = regex_specific(str(p.get_headers()[httpheader]), 'base64')
                    regex_request_http_positive.update({str(httpheader): regex[0]})
                    # print httpheader, regex[0], regex_bad
                # print len(p.get_headers()), p.get_headers() ,regex_request_http_positive, regex_request_http_negative
                for cookie in parsed_cookies:
                    regex = regex_positive(str(parsed_cookies[cookie]))
                    # print regex, str(parsed_cookies[cookie])
                    if regex[0] == 'hailmary':
                        regex_bad = regex_negative(str(parsed_cookies[cookie]))
                        regex_request_cookie_negative.update({str(cookie): regex_bad})
                    elif regex[0] == '5b64':
                        regex = regex_specific(str(parsed_cookies[cookie]), 'base64')
                    regex_request_cookie_positive.update({str(cookie): regex[0]})
                    # print cookie, regex[0], regex_bad
                # if len(parsed_cookies) > 0:
                    # print len(parsed_cookies), parsed_cookies ,regex_request_cookie_positive, regex_request_cookie_negative
                if print_details == 1:
                    row = [int(requests["id"]), url_scheme, str(method), str(uri), len(querystring_arguments),
                           querystring_arguments, regex_request_positive, regex_request_negative, len(p.get_headers()),
                           p.get_headers(), regex_request_http_positive, regex_request_http_negative,
                           len(parsed_cookies.keys()), parsed_cookies.keys(), regex_request_cookie_positive,
                           regex_request_cookie_negative]
                    rows.append(row)
                    # %d, "%s", "%s", "%s", %d, "%s", "%s", "%s"
                    # print row[0], re.escape(row[1]), re.escape(row[2]), re.escape(row[3]), row[4],row[5],row[6],row[7]
                db.execute('INSERT INTO summary (id_message, scheme, method, resource, num_parameter, parameters, ' +
                           'regex_pos, regex_neg, num_httpheader, httpheaders, regex_httpheader_pos, ' +
                           'regex_httpheader_neg, num_cookies, cookies, regex_cookie_pos, regex_cookie_neg) ' +
                           'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                           (int(requests["id"]), url_scheme, str(method), str(uri), len(querystring_arguments),
                            str(querystring_arguments.keys()), str(regex_request_positive), str(regex_request_negative),
                            len(p.get_headers()), str(p.get_headers().keys()), str(regex_request_http_positive),
                            str(regex_request_http_negative), len(parsed_cookies.keys()), str(parsed_cookies.keys()),
                            str(regex_request_cookie_positive), str(regex_request_cookie_negative)))
                db.commit()
                write_message(requests)
    if print_details == 1:
        print 'HOST :', filtered
        rows.sort(key=lambda x: x[3])
        print tabulate([line for line in rows], headers=header)
    return


def parse_locations(filtered):
    """Parse contents and dump into database.

                Parse contents, summarize data and dump into database."""
    global id_site
    write_output = open(output_file, 'w')
    write_output.write('<?xml version="1.0"?>')
    write_output.write('<?xml-stylesheet type="text/xsl" version="2.0" href="simplerules.xslt" ?>')
    xml_profile = Element('Profile')
    # xml_tree = ElementTree(xml_profile)
    cur.execute('SELECT id_resource, resource, scheme, method ' +
                'FROM resources WHERE id_site=(?) ' +
                'ORDER BY scheme, resource, method', (id_site,))
    locations = cur.fetchall()
    for location in locations:
        id_resource = location[0]
        resource = location[1]
        scheme = location[2]
        method = location[3]
        cur.execute('SELECT parameter, regex_pos, regex ' +
                    'FROM parameters, regexes ' +
                    'WHERE parameters.id_resource=? and regexes.name=parameters.regex_pos ' +
                    'ORDER BY parameter', (id_resource,))
        parameters = cur.fetchall()
        xml_location = SubElement(xml_profile, 'Location')
        xml_location.set('name', resource)
        xml_scheme = SubElement(xml_location, 'Scheme')
        xml_scheme.set('value', scheme)
        xml_method = SubElement(xml_location, 'Method')
        xml_method.set('value', method)
        # print id_resource, resource, scheme, method
        for parameter in parameters:
            arg = parameter[0]
            regex_pos = parameter[1]
            regex = parameter[2]
            xml_parameter = SubElement(xml_method, 'Parameter')
            xml_parameter.set('name', arg)
            xml_parameter.set('regex', regex)
            if method == 'GET':
                xml_parameter.set('scope', 'header')
            if method == 'POST':
                xml_parameter.set('scope', 'body')
            mandatory_check = mandatory_parameter(filtered, parameter)
            if mandatory_check is not False:
                xml_parameter.set('required', 'True')
                if mandatory_check is not True:
                    SubElement(xml_parameter, 'Parameter', name=parameter, value=mandatory_check)
            else:
                xml_parameter.set('required', 'False')
            # print arg, regex_pos, regex
        cur.execute('SELECT header, headers.regex as regex_pos, regexes.regex ' +
                    'FROM headers, regexes ' +
                    'WHERE headers.id_resource=? and regexes.name=headers.regex ' +
                    'ORDER BY header', (id_resource,))
        headers = cur.fetchall()
        for header in headers:
            http_header = header[0]
            regex_pos = header[1]
            regex = header[2]
            xml_header = SubElement(xml_method, 'Header')
            xml_header.set('name', http_header)
            xml_header.set('regex', regex)
            mandatory_check = mandatory_header(filtered, http_header)
            if mandatory_check is not False:
                xml_header.set('required', 'True')
                if mandatory_check is not True:
                    SubElement(xml_header, 'Header', name=http_header, value=mandatory_check)
            else:
                xml_header.set('required', 'False')
            # print http_header, regex_pos, regex
        cur.execute('SELECT cookie, cookies.regex as regex_pos, regexes.regex ' +
                    'FROM cookies, regexes ' +
                    'WHERE cookies.id_resource=? and regexes.name=cookies.regex ' +
                    'ORDER BY cookie', (id_resource,))
        cookies = cur.fetchall()
        for cookie in cookies:
            http_cookie = cookie[0]
            regex_pos = cookie[1]
            regex = cookie[2]
            xml_cookie = SubElement(xml_method, 'Cookie')
            xml_cookie.set('name', http_cookie)
            xml_cookie.set('regex', regex)
            mandatory_check = mandatory_cookie(filtered, http_cookie)
            if mandatory_check is not False:
                xml_cookie.set('required', 'True')
                if mandatory_check is not True:
                    SubElement(xml_cookie, 'Cookie', name=http_cookie, value=mandatory_check)
            else:
                xml_cookie.set('required', 'False')
                # print http_header, regex_pos, regex
    write_output.write(xml_prettify(tostring(xml_profile)))
    write_output.close()
    return


def parse_locations2(filtered):
    """Parse contents and dump into database.

                Parse contents, summarize data and dump into database."""
    global id_site
    item_id = modsecurity_starting_ruleid
    write_output = open(output_file, 'w')
    write_output.write('<?xml version="1.0"?>')
    write_output.write('<?xml-stylesheet type="text/xsl" version="2.0" href="SimpleTransformation.xslt" ?>')
    xml_profile = Element('Profile')
    xml_context = SubElement(xml_profile, 'Context')
    # xml_tree = ElementTree(xml_profile)
    cur.execute('SELECT id_resource, resource, scheme, method ' +
                'FROM resources WHERE id_site=(?) ' +
                'ORDER BY scheme, resource, method', (id_site,))
    locations = cur.fetchall()
    for location in locations:
        id_resource = location[0]
        resource = location[1]
        scheme = location[2]
        method = location[3]
        cur.execute('SELECT parameter, regex_pos, regex ' +
                    'FROM parameters, regexes ' +
                    'WHERE parameters.id_resource=? and regexes.name=parameters.regex_pos ' +
                    'ORDER BY parameter', (id_resource,))
        parameters = cur.fetchall()
        xml_location = SubElement(xml_context, 'Resource')
        xml_location.set('name', resource)
        xml_scheme = SubElement(xml_location, 'Scheme')
        xml_scheme.set('value', scheme)
        xml_method = SubElement(xml_location, 'Method')
        xml_method.set('value', method)
        # print id_resource, resource, scheme, method
        for parameter in parameters:
            arg = parameter[0]
            regex_pos = parameter[1]
            regex = parameter[2]
            xml_parameter = SubElement(xml_method, 'Parameter')
            xml_parameter.set('name', arg)
            xml_parameter.set('regexp', regex)
            xml_parameter.set('id', str(item_id))
            item_id += 1
            if method == 'GET':
                xml_parameter.set('scope', 'header')
            if method == 'POST':
                xml_parameter.set('scope', 'body')
            mandatory_check = mandatory_parameter(filtered, parameter)
            if mandatory_check is not False:
                xml_parameter.set('required', 'True')
                if mandatory_check is not True:
                    SubElement(xml_parameter, 'Parameter', name=parameter, value=mandatory_check)
            else:
                xml_parameter.set('required', 'False')
            # print arg, regex_pos, regex
        cur.execute('SELECT header, headers.regex as regex_pos, regexes.regex ' +
                    'FROM headers, regexes ' +
                    'WHERE headers.id_resource=? and regexes.name=headers.regex ' +
                    'ORDER BY header', (id_resource,))
        headers = cur.fetchall()
        for header in headers:
            http_header = header[0]
            regex_pos = header[1]
            regex = header[2]
            xml_header = SubElement(xml_method, 'Header')
            xml_header.set('name', http_header)
            xml_header.set('regexp', regex)
            xml_header.set('id', str(item_id))
            item_id += 1
            mandatory_check = mandatory_header(filtered, http_header)
            if mandatory_check is not False:
                xml_header.set('required', 'True')
                if mandatory_check is not True:
                    SubElement(xml_header, 'Header', name=http_header, value=mandatory_check)
            else:
                xml_header.set('required', 'False')
            # print http_header, regex_pos, regex
        cur.execute('SELECT cookie, cookies.regex as regex_pos, regexes.regex ' +
                    'FROM cookies, regexes ' +
                    'WHERE cookies.id_resource=? and regexes.name=cookies.regex ' +
                    'ORDER BY cookie', (id_resource,))
        cookies = cur.fetchall()
        for cookie in cookies:
            http_cookie = cookie[0]
            regex_pos = cookie[1]
            regex = cookie[2]
            xml_cookie = SubElement(xml_method, 'Cookie')
            xml_cookie.set('name', http_cookie)
            xml_cookie.set('regexp', regex)
            xml_cookie.set('id', str(item_id))
            item_id += 1
            mandatory_check = mandatory_cookie(filtered, http_cookie)
            if mandatory_check is not False:
                xml_cookie.set('required', 'True')
                if mandatory_check is not True:
                    SubElement(xml_cookie, 'Cookie', name=http_cookie, value=mandatory_check)
            else:
                xml_cookie.set('required', 'False')
                # print http_header, regex_pos, regex
    write_output.write(tostring(xml_profile))
    write_output.close()
    return

def xml_prettify(xml, encoding=None, formatter="minimal"):
    soup = BeautifulSoup(xml, 'lxml')
    r = re.compile(r'^(\s*)', re.MULTILINE)
    return r.sub(r'\1\1\1\1', soup.prettify(encoding, formatter))


def auditlog_reader():
    messages = []
    lines = ['']
    id = 1
    pattern_requestheader = re.compile('--([a-f0-9]{8})-B-(.+?)--[a-f0-9]{8}', re.MULTILINE|re.DOTALL)
    pattern_requestbody = re.compile('--([a-f0-9]{8})-C-(.+?)--[a-f0-9]{8}', re.MULTILINE|re.DOTALL)
    pattern_responseheader = re.compile('--([a-f0-9]{8})-F-(.+?)--[a-f0-9]{8}', re.MULTILINE|re.DOTALL)
    pattern_responsebody = re.compile('--([a-f0-9]{8})-E-(.+?)--[a-f0-9]{8}', re.MULTILINE|re.DOTALL)
    pattern_end = re.compile('^--[a-f0-9]{8}-Z-')
    with open(audit_log, 'r') as f:
        for line in f:
            if re.match(pattern_end, line):
                testline = lines[-1]
                requestheader = pattern_requestheader.search(testline)
                requestbody = pattern_requestbody.search(testline)
                responseheader = pattern_responseheader.search(testline)
                responsebody = pattern_responsebody.search(testline)
                if not requestheader:
                    requestheader = ''
                else:
                    requestheader = requestheader.group(2)[2:]
                if not requestbody:
                    requestbody = ''
                else:
                    requestbody = requestbody.group(2)[2:]
                if not responseheader:
                    responseheader = ''
                else:
                    responseheader = responseheader.group(2)[2:]
                if not responsebody:
                    responsebody = ''
                else:
                    responsebody = responsebody.group(2)[2:]
                record = {u'requestBody': unicode(requestbody), u'requestHeader': unicode(requestheader),
                          u'responseHeader': unicode(responseheader), u'responseBody': unicode(responsebody),
                          u'id': id}
                id += 1
                messages.append(record)
                lines.append('')
            else:
                lines[-1] += line.replace('\n','\r\n')
    return messages


def main():
    '''Main function outputs items to create positive security model.

    This function will extract from the ZAP session file for a given site all the different URI, parameters,
    cookies, headers and types into a XML output to be later transformed into modsecurity rules that follow a
    positive security model.
    #ZAP messages is a list of dict {id,requestHeader,requestBody,responseHeader,responseBody,cookieParams,note}
    #every element in the dict is a unicode value
    '''
    regex_builder()
    if audit_log:
        filtered = 'auditlog'
    else:
        filtered = site_filter()
    init_db(cur, True)
    write_regexes()
    parse_connection_database(filtered)
    parse_summary(filtered)
    print 'HOST :', filtered
    cur.execute('SELECT DISTINCT scheme, method, resource, num_parameter, parameters, regex_pos, regex_neg, ' +
                'num_httpheader, httpheaders, regex_httpheader_pos, regex_httpheader_neg, num_cookies, cookies, ' +
                'regex_cookie_pos, regex_cookie_neg FROM summary')
    summary = cur.fetchall()
    # header_summary = ['scheme', 'method', 'resource', 'num_parameter', 'parameters', 'regex_pos', 'regex_neg']
    header_summary = ['SCHEME', 'METHOD', 'URI', '#ARG', 'ARGS', 'REGEX+', 'REGEX-', '#HEA', 'HEAD', 'HREGEX+',
                      'HREGEX-', '#COO', 'COOK', 'CREGEX+', 'CREGEX-']
    rows_summary = []
    for summary_record in summary:
        row_summary = []
        for summary_field in xrange(0, len(summary_record)):
            row_summary.append(summary_record[summary_field])
        rows_summary.append(row_summary)
    print 'Records : %d' % (len(rows_summary))
    print tabulate([line for line in rows_summary], headers=header_summary)
    parse_locations2(filtered)
    pass


if __name__ == '__main__':
    main()
