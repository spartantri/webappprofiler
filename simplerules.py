#!/usr/bin/env python
# -------------------------------------------------------------------------------
# Name:        Modsecurity simple rule generator
# Purpose:     Modsecurity simple rule generation from xml and xslt
#
# Author:      spartantri
#
# Created:     19/08/2016
# Copyright:   (c) spartantri 2016
# License:     GPLv3
# -------------------------------------------------------------------------------
import re
from lxml import etree

modsecurity_starting_ruleid = 9980000

# data = open('simplerules.xslt')
data = open('SimpleTransformation.xslt')
xslt_content = data.read()
xslt_root = etree.XML(xslt_content)
dom = etree.parse('test.xml')
transform = etree.XSLT(xslt_root)
result = transform(dom)
f = open('modsec.rules.tmp', 'w')
f.write(str(result))
f = open('modsec.rules.tmp', 'r')
rules = open('modsec.rules', 'w')
for line in f:
    rule_id = ''.join(['id:', str(modsecurity_starting_ruleid)])
    line = line.replace('id:9931733', rule_id)
    rules.write(line)
    if rule_id in line:
        modsecurity_starting_ruleid += 1
f.close()
rules.close()