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


def transform_xml(input_xml, transformation_xslt, modsecurity_starting_ruleid=9980000, verbose=False):
    from lxml import etree
    import re
    data = open(transformation_xslt)
    xslt_content = data.read()
    xslt_root = etree.XML(xslt_content)
    dom = etree.parse(input_xml)
    transform = etree.XSLT(xslt_root)
    result = transform(dom)
    if verbose == True:
        print 'Writing temporary file... (modsec.rules.tmp)'
    f = open('modsec.rules.tmp', 'w')
    f.write(str(result))
    f = open('modsec.rules.tmp', 'r')
    rules = open('modsec.rules', 'w')
    rule_count = 0
    print 'Writing modsecurity rules file... (modsec.rules)'
    for line in f:
        rule_id = ''.join(['id:', str(modsecurity_starting_ruleid)])
        line = line.replace('id:9931733', rule_id)
        rules.write(line)
        if rule_id in line:
            modsecurity_starting_ruleid += 1
            if verbose == True:
                print 'Generated rule', rule_id
            rule_count += 1
        else:
            writing_id = re.search('(id:\d+)', line)
            if writing_id:
                if verbose == True:
                    print 'Generated rule', writing_id.group(1)
                rule_count += 1
    print 'Generated {0} rules'.format(rule_count)
    f.close()
    rules.close()


def main():
    transform_xml('test.xml', 'SimpleTransformation.xslt', 9980000, False)
    pass


if __name__ == '__main__':
    main()
