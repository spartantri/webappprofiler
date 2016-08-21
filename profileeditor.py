#!/usr/bin/env python
# -------------------------------------------------------------------------------
# Name:        Profile editor
# Purpose:     Script for modifying the profile to set attributes, add and remove elements
#
# Author:      spartantri
#
# Created:     20/08/2016
# Copyright:   (c) spartantri 2016
# License:     Apache License Version 2.0
# -------------------------------------------------------------------------------
import xml.dom.minidom


def transform_xml(input_xml):
    xml_content = xml.dom.minidom.parse(input_xml)
    pretty_xml_as_string = xml_content.toprettyxml()
    return pretty_xml_as_string


def main():
    print transform_xml('test.xml')
    pass


if __name__ == '__main__':
    main()

