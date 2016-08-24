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
from xml.etree.ElementTree import Element, SubElement, Comment, tostring
import xml.etree.ElementTree as ET

input_file = 'test.xml'
usage = '''Usage:
    input [file]                   - Change/Display input file
    print [pretty]                 - Print (Pretty) input file
    location [add|remove}          - Location List/Add/Remove
    set [location|method]          - Display/Set current working Location/Method
    parameter [add|remove]         - Display/add/remove arguments
    cookie [add|remove]            - Display/add/remove cookies
    sessioncookie [add|remove]     - Display/add/remove sessioncookies
    header [add|remove]            - Display/add/remove headers
    exit                           - Exit'''
location = '*'
method = '*'

def transform_xml(input_xml):
    xml_content = xml.dom.minidom.parse(input_xml)
    pretty_xml_as_string = xml_content.toprettyxml()
    return pretty_xml_as_string


def set_print():
    global location, method
    print 'Location set to: %s' % (location)
    print 'Method set to  : %s' % (method)
    return


def set_location(adjust='*'):
    global location
    if adjust == '*':
        location = raw_input("Enter location * for all : ").split(' ')[0]
    else:
        location = adjust
    set_print()
    return


def set_method(adjust='*'):
    global method
    allowed_methods = ['GET', 'POST', 'PUT', 'OPTIONS', 'DELETE', 'HEAD', '*']
    while True:
        if adjust == '*':
            method = raw_input("Enter method * for all : ").split(' ')[0].upper()
        else:
            method = adjust
        if method in allowed_methods:
            set_print()
            return
        else:
            print 'Allowed methods are * or :', allowed_methods
            adjust = '*'


def location_print():
    tree = ET.parse(input_file)
    root = tree.getroot()
    for xml_item in root.iter('Resource'):
        print xml_item.get('name')
    return


def location_add():
    tree = ET.parse(input_file)
    root = tree.getroot()
    xml_context = root.find('Context')
    xml_location = SubElement(xml_context, 'Resource')
    resource = raw_input("Enter location : ").split(' ')[0]
    xml_location.set('name', resource)
    scheme = raw_input("http or https (default) : ").split(' ')[0]
    xml_scheme = SubElement(xml_location, 'Scheme')
    if resource.lower() == 'http':
        xml_scheme.set('value', scheme)
    else:
        xml_scheme.set('value', 'https')
    #xml_method = SubElement(xml_location, 'Method')
    #xml_method.set('value', method)
    for xml_item in root.iter('Resource'):
        print xml_item.get('name')
    tree.write(input_file)
    return


def location_remove():
    tree = ET.parse(input_file)
    root = tree.getroot()
    removed = 0
    resource = raw_input("Enter location : ").split(' ')[0]
    for xml_item in reversed(xrange(len(root[0]))):
        if root[0][xml_item].get('name') == resource:
            print 'Removing : ', root[0][xml_item].get('name')
            tree.getroot()[0].remove(root[0][xml_item])
            removed += 1
    if removed > 0:
        tree.write(input_file)
        print 'Removed %d locations' % (removed)
    else:
        print 'Not found'
    return


def print_warning(element):
    if location == '*':
        print 'Location set to * will print the %s from all locations in the profile' % (element)
    if method == '*':
        print 'Method set to * will print the %s from all methods' % (element)
    return


def element_print(element):
    global location, method
    tree = ET.parse(input_file)
    root = tree.getroot()
    print '%s check:' % (str(element).capitalize())
    print_warning(element)
    for xml_location in root.findall('Context/Resource'):
        if xml_location.get('name') == location or location == '*':
            for xml_method in xml_location:
                if xml_method.tag == 'Method':
                    if xml_method.get('value') == method or method == '*':
                        print xml_location.get('name')
                        print ' ', xml_method.tag, xml_method.get('value')
                        for x in xml_method.findall(str(element).capitalize()):
                            print '   ', x.tag, x.attrib
    return


def element_add(element):
    global location, method
    tree = ET.parse(input_file)
    root = tree.getroot()
    elements_added = 0
    print 'Adding %s :' % (str(element).capitalize())
    print_warning(element)
    arg = raw_input("Enter %s name : " % (element)).split(' ')[0]
    regex = raw_input("Enter regex : ").split(' ')[0]
    for xml_location in root.findall('Context/Resource'):
        if xml_location.get('name') == location or location == '*':
            for xml_method in xml_location:
                if xml_method.tag == 'Method':
                    if xml_method.get('value') == method or method == '*':
                        print xml_location.get('name')
                        xml_element = SubElement(xml_method, element)
                        xml_element.set('name', arg)
                        xml_element.set('regexp', regex)
                        xml_element.set('id', '9931733')
                        elements_added += 1
    if elements_added > 0:
        print 'Added %d %s' % (elements_added, element)
    else:
        print 'Location %s or Method %s not available' % (location, method)
    tree.write(input_file)
    return


def element_remove(element):
    global location, method
    tree = ET.parse(input_file)
    root = tree.getroot()
    elements_removed = 0
    print 'Adding %s :' % (str(element).capitalize())
    print_warning(element)
    arg = raw_input("Enter %s name : " % (element)).split(' ')[0]
    regex = raw_input("Enter regex [any]: ").split(' ')[0]
    for xml_location in root.findall('Context/Resource'):
        if xml_location.get('name') == location or location == '*':
            for xml_method in xml_location:
                if xml_method.tag == 'Method':
                    if xml_method.get('value') == method or method == '*':
                        for deleteme in xml_method.findall(element):
                            if deleteme.get('name') == arg:
                                xml_method.remove(deleteme)
                                elements_removed += 1

                        # print tree.getroot().getchildren(), xml_method.getchildren()
                        #print xml_method.getparent().index(xml_method)
                        #elements_removed += 1

    if elements_removed > 0:
        print 'Removed %d %s' % (elements_removed, element)
    else:
        print 'Location %s or Method %s not available' % (location, method)
    tree.write(input_file)
    return


def main():
    global input_file, location, method
    options = {'parameter': 'Parameter', 'cookie': 'Cookie', 'sessioncookie': 'SessionCookie', 'header': 'Header'}
    while True:
        selected_option = raw_input("Enter action [help] : ").split(' ')
        if selected_option[0].lower() == 'help':
            print usage
        elif selected_option[0].lower() == 'input':
            if len(selected_option) > 1:
                input_file = raw_input("Input file : ")
            print 'Current input file: %s' % (input_file)
        elif selected_option[0].lower() == 'print':
            if len(selected_option) > 1 :
                if selected_option[1].lower() == 'pretty':
                    print transform_xml(input_file)
            else:
                with open(input_file) as f:
                    for line in f:
                        print line,
                print ''
        elif selected_option[0].lower() == 'set':
            if len(selected_option) == 1:
                set_print()
            else:
                if selected_option[1].lower() == 'location':
                    if len(selected_option) > 2:
                        set_location(selected_option[2])
                    else:
                        set_location()
                elif selected_option[1].lower() == 'method':
                    if len(selected_option) > 2:
                        set_method(str(selected_option[2]).upper())
                    else:
                        set_method()
        elif selected_option[0].lower() == 'location':
            if len(selected_option) == 1:
                location_print()
            else:
                if selected_option[1].lower() == 'add':
                    location_add()
                elif selected_option[1].lower() == 'remove':
                    location_remove()
        elif selected_option[0].lower() in ['parameter', 'cookie', 'sessioncookie', 'header']:
            if len(selected_option) == 1:
                element_print(options[selected_option[0].lower()])
            else:
                if selected_option[1].lower() == 'add':
                    element_add(options[selected_option[0].lower()])
                elif selected_option[1].lower() == 'remove':
                    element_remove(options[selected_option[0].lower()])
        elif selected_option[0].lower() == 'exit':
            exit()


if __name__ == '__main__':
    main()

