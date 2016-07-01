#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:        WebApp Profiler for ZAP
# Purpose:     Script for parsing persistent ZAP session file
#
# Author:      spartantri
#
# Created:     17/06/2016
# Copyright:   (c) mleos 2016
# License:     GPLv2
#-------------------------------------------------------------------------------
import time, urlparse, re, logging, sqlite3
from pprint import pprint
from zapv2 import ZAPv2
from http_parser.pyparser import HttpParser
from tabulate import tabulate
from sys import stdout
#from sets import Set
#from urlparse import urlparse

#Initialization variables
zap = ZAPv2()
parseablecodes=(200,301,302,304,401,500,501)
simple_regexes = {}
complex_regexes = {}
blacklist_regexes = {}
when_everything_goes_bad_regexes = {}
db = sqlite3.connect('ZAPParser.sqlite',timeout=11)
cur=db.cursor()


def init_db(cur,zero=False):
    '''Initialize database for aggregation.

    Initialize database to use aggregation capabilites for complex arrays.'''
    #Database Structure
    profiledb = {'sites' : 'CREATE TABLE IF NOT EXISTS sites (id_site INTEGER PRIMARY KEY, site TEXT)', \
                 'messages' : 'CREATE TABLE IF NOT EXISTS messages (id_message INTEGER PRIMARY KEY, ' +
                              'requestHeader TEXT, requestBody TEXT, responseHeader TEXT, responseBody TEXT, ' +
                              'cookieParams TEXT, note TEXT)', \
                 'resources' : 'CREATE TABLE IF NOT EXISTS resources (id_resource INTEGER PRIMARY KEY, ' +
                               'id_site INTEGER, resource TEXT, public TEXT, method TEXT, min_requestsize INTEGER, ' +
                               'max_requestsize INTEGER, min_responsesize INTEGER, max_responsesize INTEGER)', \
                 'headers' : 'CREATE TABLE IF NOT EXISTS headers (id_header INTEGER PRIMARY KEY, ' +
                             'id_resource INTEGER, header TEXT, required TEXT, regex TEXT)', \
                 'grouping_resources' : 'CREATE TABLE IF NOT EXISTS grouping_resources (id_group INTEGER PRIMARY KEY, ' +
                                        'group_name TEXT, regex TEXT)', \
                 'parameters' : 'CREATE TABLE IF NOT EXISTS parameters (id_parameters INTEGER PRIMARY KEY, ' +
                                'id_resource INTEGER, parameter TEXT, required TEXT, regex TEXT, method TEXT, ' +
                                'encoding TEXT, sanitize TEXT)', \
                 'cookies' : 'CREATE TABLE IF NOT EXISTS cookies (id_cookie INTEGER PRIMARY KEY, ' +
                             'id_resource INTEGER, cookie TEXT, required TEXT, regex TEXT, flags TEXT, path TEXT,' +
                             'expiry TEXT, encoding TEXT, sanitize TEXT)', \
                 'regexes' : 'CREATE TABLE IF NOT EXISTS regexes (id_regexes INTEGER PRIMARY KEY, ' +
                                        'name TEXT, purpose TEXT, regex TEXT)', \
                 'summary' : 'CREATE TABLE IF NOT EXISTS summary (id_message INTEGER PRIMARY KEY, scheme TEXT, method TEXT, ' +
                             'resource TEXT, num_parameter INTEGER, parameters TEXT, regex_pos TEXT, regex_neg TEXT)'}
    if zero:
        for table in profiledb:
            cur.execute('DROP TABLE IF EXISTS '+table)
    for table in profiledb:
        cur.execute(profiledb[table])
    return


def parse_http(rsp):
    '''Define parser.

    Define HttpParser'''
    p=HttpParser()
    p.execute(rsp,len(rsp))
    return p


def find_id(zapid):
    '''Find zap request id.

    Find the request id in the persistent session file that matches the index.'''
    for idx,r in enumerate(requests):
        if int(r["id"]) == zapid:
            return idx
    return False


def site_filter():
    '''Set a site filter.

    Lists all the sites and ask to choose one to set it as a filter for the data extraction.'''
    while True:
        try:
            site_list=[]
            for idx,site in enumerate(zap.core.sites):
                site_list.append(urlparse.urlparse(site).netloc)
                print idx, urlparse.urlparse(site).netloc
            site_filter= int(raw_input("Coose a site : "))
            print "Setting site filter to: %s" % (site_list[site_filter])
            return str(site_list[site_filter])
        except:
            print "Wrong selection, try again"
            time.sleep(2)


def regex_builder():
    '''Setup global regex variables.

    Creates the global variables including the different regular expressions to use in pattern identification.'''
    global simple_regexes, complex_regexes, blacklist_regexes, when_everything_goes_bad_regexes
    #Simple regexes
    simple_regexes = {'0numeric':'\d', '1alphabetic':'a-zA-Z', '2hex':'a-fA-F0-9', '3alphanumeric':'a-zA-Z0-9', \
                      'punctuation':',\.\'\-_', '5b64':'a-zA-Z0-9+/='}
    simple_regexes.update({'6numeric_punctuation':simple_regexes['punctuation']+simple_regexes['0numeric']})
    simple_regexes.update({'7alphabetic_punctuation': simple_regexes['punctuation'] + simple_regexes['1alphabetic']})
    simple_regexes.update({'8alphanumeric_punctuation': simple_regexes['punctuation'] + simple_regexes['3alphanumeric']})
    #Complex regexes
    octet='25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}?'
    ip_regex = {'ips':'\b(?:'+octet+'\.){3}(?:'+octet+')\b'}
    complex_regexes.update(ip_regex)
    date_m = '(?:0?[1-9]|1[012])'
    date_d = '(?:0?[1-9]|[12][0-9]|3[01])'
    date_Y = '(?:19|20)?[0-9]{2}'
    date_y = '[0-9]{2})'
    date_separator = '([- /.])'
    date_regex = {'datemdY':date_m+date_separator+date_d+'\1'+date_Y, \
                  'dateYdm':date_Y+date_separator+date_d+'\1'+date_m, \
                  'datedmY':date_d+date_separator+date_m+'\1'+date_Y}
    email_regex = {'email':'[a-zA-Z0-9_\.\+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-\.]+'}
    base64_regex = {'base64':'(?:[a-zA-Z0-9+/]{3})*(?:[a-zA-Z0-9+/]{1}==|[a-zA-Z0-9+/]{2}=)?'}
    complex_regexes.update(date_regex)
    complex_regexes.update(email_regex)
    complex_regexes.update(base64_regex)
    #Other regexes
    blacklist_regexes = {'command': '&;|\$`', 'redirect': '<>', 'path': '/\\\\', 'group': '\(\)\{\}'}
    when_everything_goes_bad_regexes = {'hailmary': '.*'}


def regex_positive(match_this):
    '''Identify which regex better matches the expresion.

        Identify which PCRE regex better matches a given value to use for validation using modsecurity rules.'''
    global simple_regexes, complex_regexes, blacklist_regexes, when_everything_goes_bad_regexes
    regex_begin = '^['
    payload_lenght = str(len(match_this))
    regex_trail = ']{'+payload_lenght+'}$'
    for regex_test in sorted(simple_regexes.keys()):
        regex = regex_begin+simple_regexes[regex_test]+regex_trail
        if re.match(regex, match_this):
            return regex_test, payload_lenght
    return 'hailmary', payload_lenght


def regex_negative(match_this):
    '''Identify possible problematic characters.

    Identify characters or expressions that may cause problems with filtering.'''
    global simple_regexes, complex_regexes, blacklist_regexes, when_everything_goes_bad_regexes
    matches = []
    regex_begin = '['
    regex_trail = ']+'
    for regex_test in blacklist_regexes.keys():
        regex = regex_begin+blacklist_regexes[regex_test]+regex_trail
        if re.search(regex, match_this):
            matches.append(regex_test)
    return matches


def regex_specific(match_this, regex_test):
    '''Identify specific regex matches.

        Identify if a particular regex in the global variables matches the expresion.'''
    global simple_regexes, complex_regexes, blacklist_regexes, when_everything_goes_bad_regexes
    payload_lenght = str(len(match_this))
    if simple_regexes.has_key(regex_test):
        if re.match(simple_regexes[regex_test], match_this):
            payload_lenght = str(len(match_this))
            return regex_test, payload_lenght
    elif complex_regexes.has_key(regex_test):
        if re.match(complex_regexes[regex_test], match_this):
            return regex_test, payload_lenght
    return 'hailmary', when_everything_goes_bad_regexes['hailmary']


def make_sets(rows):
    from sets import Set

    pass

def main():
    '''Main function outputs items to create positive security model.

    This function will extract from the ZAP session file for a given site all the different URI, parameters,
    cookies, headers and types into a XML output to be later transformed into modsecurity rules that follow a
    positive security model.
    #ZAP messages is a list of dict {id,requestHeader,requestBody,responseHeader,responseBody,cookieParams,note}
    #every element in the dict is a unicode value
    '''
    regex_builder()
    filtered=site_filter()
    init_db(cur, True)
    header = ['ID', 'SCHEME', 'METHOD', 'URI', '#ARG', 'ARGS', 'REGEX+', 'REGEX-']
    rows = []
    for requests in zap.core.messages():
        p=parse_http(requests["responseHeader"])
        if p.get_status_code() in parseablecodes:
            p=parse_http(requests["requestHeader"])
            url=p.get_url()
            url_parsed = urlparse.urlparse(url)
            url_netloc=url_parsed.netloc
            if filtered == url_netloc:
                method=p.get_method()
                # tuple (1, 1)
                version=p.get_version()
                uri=p.get_path()
                querystring=p.get_query_string()
                wsgi_environ=p.get_wsgi_environ()
                if wsgi_environ.has_key("HTTP_HOST"):
                    http_host=wsgi_environ["HTTP_HOST"]
                if wsgi_environ.has_key("HTTP_ORIGIN"):
                    http_origin=wsgi_environ["HTTP_ORIGIN"]
                if wsgi_environ.has_key("HTTP_REFERER"):
                    http_referer=wsgi_environ["HTTP_REFERER"]
                if wsgi_environ.has_key("HTTP_ACCEPT"):
                    http_accept=wsgi_environ["HTTP_ACCEPT"]
                url_scheme=url_parsed.scheme
                querystring_arguments=urlparse.parse_qs(querystring)
                regex_request_positive = {}
                regex_request_negative = {}
                for argument in querystring_arguments:
                    regex = regex_positive(str(querystring_arguments[argument][0]))
                    #print str(querystring_arguments[argument][0])
                    #print regex
                    if regex[0] == 'hailmary':
                        regex_bad = regex_negative(str(querystring_arguments[argument][0]))
                        regex_request_negative.update({str(argument): regex_bad})
                    elif regex[0] == '5b64':
                        regex = regex_specific(str(querystring_arguments[argument][0]),'base64')
                    regex_request_positive.update({str(argument): regex[0]})
                row = [int(requests["id"]), url_scheme, str(method), str(uri), len(querystring_arguments), \
                       querystring_arguments, regex_request_positive, regex_request_negative]
                rows.append(row)
                #%d, "%s", "%s", "%s", %d, "%s", "%s", "%s"
                #print row[0], re.escape(row[1]), re.escape(row[2]), re.escape(row[3]), row[4], row[5], row[6], row[7]
                db.execute('INSERT INTO summary (id_message, scheme, method, resource, num_parameter, parameters, ' +
                           'regex_pos, regex_neg) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                           (int(requests["id"]), url_scheme, str(method), str(uri), len(querystring_arguments),
                            str(querystring_arguments.keys()), str(regex_request_positive), str(regex_request_negative)))
                db.commit()
    print 'HOST :', filtered
    rows.sort(key=lambda x: x[3])
    print tabulate([line for line in rows], headers=header)
    print 'HOST :', filtered
    cur.execute('SELECT DISTINCT scheme, method, resource, num_parameter, parameters, regex_pos, regex_neg FROM summary')
    summary = cur.fetchall()
    header_summary = ['scheme', 'method', 'resource', 'num_parameter', 'parameters', 'regex_pos', 'regex_neg']
    rows_summary = []
    for summary_record in summary:
        row_summary = []
        for summary_field in xrange(0,len(summary_record)):
            row_summary.append(summary_record[summary_field])
        rows_summary.append(row_summary)
    print 'Records : %d' % (len(rows_summary))
    print tabulate([line for line in rows_summary], headers=header_summary)

    pass

if __name__ == '__main__':
    main()
