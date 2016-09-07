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
from xml.etree.ElementTree import SubElement, tostring
import xml.etree.ElementTree as ET
import re

input_file = 'test.xml'
usage = '''Usage:
    input [file]                               - Change/Display input file
    set [location|method] [target]             - Display/Set current working Location/Method
    print [pretty]                             - Print (Pretty) input file
    location [add|remove] [target]             - Location List/Add/Remove
       method [add|remove] [target]            - Location List/Add/Remove
          cookie [add|remove] [target]         - Display/add/remove cookies
          header [add|remove] [target]         - Display/add/remove headers
          parameter [add|remove] [target]      - Display/add/remove arguments
          sessioncookie [add|remove] [target]  - Display/add/remove sessioncookies
    history [#]                                - Display command history
    exit                                       - Exit'''
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
            print 'Allowed methods are *', allowed_methods
            adjust = '*'


def location_print():
    tree = ET.parse(input_file)
    root = tree.getroot()
    for xml_item in root.iter('Resource'):
        print xml_item.get('name')
    return


def location_add(target=False):
    tree = ET.parse(input_file)
    root = tree.getroot()
    xml_context = root.find('Context')
    xml_location = SubElement(xml_context, 'Resource')
    if not target:
        resource = raw_input("Enter location : ").split(' ')[0]
        scheme = raw_input("http or https (default) : ").split(' ')[0]
        if scheme.lower() == 'http':
            scheme = 'http'
        else:
            scheme = 'https'
        print 'Confirm values'
        print 'Location : %s' % resource
        print 'Method   : %s' % method
        print 'Scheme   : %s' % scheme
        confirmation = str(raw_input("Accept values : Y/N").split(' ')[0]).upper()
        if confirmation != 'Y':
            print ' Aborting...'
            return
    else:
        resource = str(target).split(' ')[0]
        scheme = 'https'
    xml_location.set('name', resource)
    xml_scheme = SubElement(xml_location, 'Scheme')
    xml_scheme.set('value', scheme)
    # for xml_item in root.iter('Resource'):
    #    print xml_item.get('name')
    tree.write(input_file)
    return


def location_remove(target=False):
    tree = ET.parse(input_file)
    root = tree.getroot()
    removed = 0
    if not target:
        resource = raw_input("Enter location : ").split(' ')[0]
        print 'Confirm values'
        print 'Location : %s' % resource
        print 'Method   : %s' % method
        confirmation = str(raw_input("Accept values : Y/N").split(' ')[0]).upper()
        if confirmation != 'Y':
            print ' Aborting...'
            return
    else:
        resource = str(target).split(' ')[0]
    for xml_item in reversed(xrange(len(root[0]))):
        if root[0][xml_item].get('name') == resource:
            print 'Removing : ', root[0][xml_item].get('name')
            tree.getroot()[0].remove(root[0][xml_item])
            removed += 1
    if removed > 0:
        tree.write(input_file)
        print 'Removed %d locations' % removed
    else:
        print 'Not found'
    return


def method_print():
    global location
    tree = ET.parse(input_file)
    root = tree.getroot()
    print 'Method check:'
    print_warning('Method')
    for xml_location in root.findall('Context/Resource'):
        if xml_location.get('name') == location or location == '*':
            for xml_method in xml_location:
                if xml_method.tag == 'Method':
                    if xml_method.get('value') == method or method == '*':
                        print xml_location.get('name')
                        print ' ', xml_method.tag, xml_method.get('value')
    return


def method_add(target=False):
    global location
    tree = ET.parse(input_file)
    root = tree.getroot()
    allowed_methods = ['GET', 'POST', 'PUT', 'OPTIONS', 'DELETE', 'HEAD']
    add_method = 1
    elements_added = 0
    print 'Adding Method :'
    print_warning('Method')
    if not target:
        arg = raw_input("Enter Method name : ").split(' ')[0].upper()
        if arg not in allowed_methods:
            print 'Non standard method selected!'
        print 'Confirm values'
        print 'Location : %s' % location
        print 'Method   : %s' % method
        confirmation = str(raw_input("Accept values : Y/N ").split(' ')[0]).upper()
        if confirmation != 'Y':
            print ' Aborting...'
            return
    else:
        arg = target
    for xml_location in root.findall('Context/Resource'):
        if xml_location.get('name') == location or location == '*':
            for xml_method in xml_location:
                if xml_method.tag == 'Method':
                    if xml_method.get('value') == arg:
                        print '%s already have that method!' % xml_location.get('name')
                        add_method = 0
            if add_method == 1:
                xml_element = SubElement(xml_location, 'Method')
                xml_element.set('value', arg)
                elements_added += 1
            add_method = 1
    if elements_added > 0:
        print 'Added %d Methods' % elements_added
    else:
        print 'Location %s not available or %s Method already existing' % (location, arg)
    tree.write(input_file)
    return


def method_remove(target=False):
    global location, method
    tree = ET.parse(input_file)
    root = tree.getroot()
    elements_removed = 0
    element = 'Method'
    print 'Removing %s :' % element
    print_warning(element)
    if not target:
        arg = raw_input("Enter %s name * for all in scope: " % element).split(' ')[0].upper()
        print 'Confirm values'
        print 'Location : %s' % location
        print 'Method   : %s' % arg
        confirmation = str(raw_input("Accept values : Y/N ").split(' ')[0]).upper()
        if confirmation != 'Y':
            print ' Aborting...'
            return
        elif confirmation == 'Y' and arg == '*':
            confirmation = str(raw_input("Delete all methods in %s location : Y/N " % location).split(' ')[0]).upper()
            if confirmation != 'Y':
                print ' Aborting...'
                return
    else:
        arg = target
    for xml_location in root.findall('Context/Resource'):
        if xml_location.get('name') == location or location == '*':
            for xml_method in xml_location:
                if xml_method.tag == 'Method':
                    if xml_method.get('value') == arg or arg == '*':
                        xml_location.remove(xml_method)
                        elements_removed += 1
    if elements_removed > 0:
        print 'Removed %d %s' % (elements_removed, element)
    else:
        print 'Location %s or Method %s not available' % (location, method)
    tree.write(input_file)
    return


def print_warning(element):
    if location == '*':
        print 'Location set to * will print the %s from all locations in the profile' % element
    if method == '*' and element != 'Method':
        print 'Method set to * will print the %s from all methods' % element
    return


def element_print(element):
    global location, method
    tree = ET.parse(input_file)
    root = tree.getroot()
    print '%s check:' % element
    print_warning(element)
    for xml_location in root.findall('Context/Resource'):
        if xml_location.get('name') == location or location == '*':
            for xml_method in xml_location:
                if xml_method.tag == 'Method':
                    if xml_method.get('value') == method or method == '*':
                        print xml_location.get('name')
                        print ' ', xml_method.tag, xml_method.get('value')
                        for x in xml_method.findall(element):
                            print '   ', x.tag, x.attrib
    return


def element_add(element, target=False, regex='any'):
    global location, method
    tree = ET.parse(input_file)
    root = tree.getroot()
    elements_added = 0
    print 'Adding %s :' % element
    print_warning(element)
    if not target:
        arg = raw_input("Enter %s name : " % element).split(' ')[0]
        regex = raw_input("Enter regex [any] : ").split(' ')[0]
        if regex == 'any' or regex == '':
            regex == '.*'
        print 'Confirm values'
        print 'Location : %s' % location
        print 'Method   : %s' % method
        print '%s : %s' % (element, arg)
        print 'Regex    : %s' % regex
        confirmation = str(raw_input("Accept values : Y/N ").split(' ')[0]).upper()
        if confirmation != 'Y':
            print ' Aborting...'
            return
    else:
        arg = target
        if regex == 'any':
            regex = '.*'
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
                        for xml_parameterlist in xml_method.findall('ParameterList'):
                            xml_parameterlist.set('parameter_list','|'.join([
                                xml_parameterlist.get('parameter_list'), re.escape(arg)]))
                        if not xml_method.findall('ParameterList'):
                            xml_element = SubElement(xml_method, 'ParameterList')
                            xml_element.set('parameter_list', re.escape(arg))
    if elements_added > 0:
        print 'Added %d %s' % (elements_added, element)
    else:
        print 'Location %s or Method %s not available' % (location, method)
    tree.write(input_file)
    return


def element_remove(element, target=False, regex='any'):
    global location, method
    tree = ET.parse(input_file)
    root = tree.getroot()
    elements_removed = 0
    print 'Removing %s :' % element
    print_warning(element)
    if not target:
        arg = raw_input("Enter %s name : " % element).split(' ')[0]
        regex = raw_input("Enter regex [any] : ").split(' ')[0]
        if regex == '':
            regex = 'any'
        print 'Confirm values'
        print 'Location : %s' % location
        print 'Method   : %s' % method
        print '%s : %s' % (element, arg)
        print 'Regex    : %s' % regex
        confirmation = str(raw_input("Accept values : Y/N ").split(' ')[0]).upper()
        if confirmation != 'Y':
            print ' Aborting...'
            return
    else:
        arg = target
    for xml_location in root.findall('Context/Resource'):
        if xml_location.get('name') == location or location == '*':
            for xml_method in xml_location:
                if xml_method.tag == 'Method':
                    if xml_method.get('value') == method or method == '*':
                        for deleteme in xml_method.findall(element):
                            if deleteme.get('name') == arg and (deleteme.get('regexp') == regex or regex == 'any'):
                                xml_method.remove(deleteme)
                                elements_removed += 1
    if elements_removed > 0:
        print 'Removed %d %s' % (elements_removed, element)
    else:
        print 'Location %s or Method %s not available' % (location, method)
    tree.write(input_file)
    return


def interactive_menu():
    global input_file, location, method
    options = {'parameter': 'Parameter', 'cookie': 'Cookie', 'sessioncookie': 'SessionCookie', 'header': 'Header'}
    command_history = []
    while True:
        selected_option = raw_input("Enter action [help] : ").split(' ')
        selected_qty = len(selected_option)
        command = False
        action = False
        target = False
        regex = 'any'
        if selected_qty > 0:
            command = selected_option[0].lower()
            action = False
            target = False
        if selected_qty > 1:
            action = selected_option[1]
            target = False
        if selected_qty > 2:
            target = selected_option[2]
        if selected_qty > 3:
            regex = selected_option[3]
        if command != 'history':
            command_history.append(selected_option)
        if command == 'help':
            print usage
        elif command == 'input':
            if not action:
                print 'Current input file : %s' % input_file
                input_file = raw_input("Input file : ")
                # check if file exist
            else:
                print 'Changed input file to : %s' % input_file
        elif command == 'print':
            if action == 'pretty':
                print transform_xml(input_file)
            else:
                with open(input_file) as f:
                    for line in f:
                        print line,
                print ''
        elif command == 'set':
            if not action:
                set_print()
            else:
                if action == 'location':
                    if target:
                        set_location(target)
                    else:
                        set_location()
                elif action == 'method':
                    if target:
                        set_method(str(target).upper())
                    else:
                        set_method()
        elif command == 'location':
            if not action:
                location_print()
            else:
                if action == 'add':
                    if target:
                        location_add(target)
                    else:
                        location_add()
                elif action == 'remove':
                    if target:
                        location_remove(target)
                    else:
                        location_remove()
        elif command in ['parameter', 'cookie', 'sessioncookie', 'header']:
            if not action:
                element_print(options[command])
            else:
                if action == 'add':
                    if target:
                        element_add(options[command], target, regex)
                    else:
                        element_add(options[command])
                elif action == 'remove':
                    if target:
                        element_remove(options[command], target, regex)
                    else:
                        element_remove(options[command])
        elif command == 'method':
            if not action:
                method_print()
            else:
                if action == 'add':
                    method_add(target.upper())
                elif action == 'remove':
                    method_remove(target.upper())
        elif command == 'history':
            if not action:
                for idx, line in enumerate(command_history):
                    print idx, ':', ' '.join(line)
            else:
                if action.isdigit():
                    cmd_list = len(command_history)
                    cmd_show = int(action)
                    if cmd_show >= cmd_list:
                        cmd_show = cmd_list
                    for idx, line in enumerate(command_history[-cmd_show:]):
                        print cmd_list+idx-cmd_show, ':', ' '.join(line)
        elif command == 'exit':
            exit()


def main():
    pass


if __name__ == '__main__':
    interactive_menu()

