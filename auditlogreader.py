#!/usr/bin/env python
# -------------------------------------------------------------------------------
# Name:        Modsecurity Audit log parser
# Purpose:     Parse native modsecurity audit log and return as an array similar to ZAP database connection
#
# Author:      spartantri
#
# Created:     20/08/2016
# Copyright:   (c) spartantri 2016
# License:     Apache License Version 2.0
# -------------------------------------------------------------------------------
import re
audit_log = 'modsec_audit.log'


def auditlog_reader():
    messages = []
    lines = ['']
    pattern_start = re.compile('--[a-f0-9]{8}-A-')
    pattern_requestheader = re.compile('--([a-f0-9]{8})-B-(.+?)--[a-f0-9]{8}', re.MULTILINE|re.DOTALL)
    pattern_requestbody = re.compile('--([a-f0-9]{8})-C-(.+?)--[a-f0-9]{8}', re.MULTILINE|re.DOTALL)
    pattern_responseheader = re.compile('--([a-f0-9]{8})-F-(.+?)--[a-f0-9]{8}', re.MULTILINE|re.DOTALL)
    pattern_responsebody = re.compile('--([a-f0-9]{8})-E-(.+?)--[a-f0-9]{8}', re.MULTILINE|re.DOTALL)
    pattern_end = re.compile('^--[a-f0-9]{8}-Z-')
    pattern_txid = re.compile('--([a-f0-9]{8})-[ABCDEFGHIJKZ]-')
    with open(audit_log, 'r') as f:
        for line in f:
            if re.match(pattern_end, line):
                testline = lines[-1]
                txid = pattern_txid.search(testline).group(1)
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
                          u'id': txid}
                messages.append(record)
                print record['responseHeader']
                lines.append('')
            else:
                lines[-1] += line\
                    # .replace('\r','\\r').replace('\n','\\n')
    return messages

def main():
    x = auditlog_reader()
    pass

if __name__ == '__main__':
    main()
