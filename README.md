# webappprofiler
Profiling web applications and generated positive security modsecurity rules automatically

The script may generate an application profile either from modsecurity audit log or by connecting to owasp zed attack
proxy and retrieving the messages exchanges with a given web site.

The script will generate both an xml application profile and a set of modsecurity rules to validate every argument,
header, cookie and session cookie present in the profile, the profile will be then used to generate using xslt
transformation.


#  PREREQUISITES:
python 2.7
zap 2.5
modsecurity 2.5 and above for running the rules, tested in modsecurity 2.9
python libraries:
    pip install python-owasp-zap-v2.4
    pip install http-parser
    pip install tabulate

USAGE:
 ./webappprofiler.py
 ...SNIP...
  20 www.somesite

 Coose a site : 20
 Setting site filter to: www.somesite
 HOST : www.somesite
 Records : 139
 SCHEME    METHOD    URI
 --------  --------  --------------------------------------------
 https     GET       /
 https     GET       /courses/special

   #ARG  ARGS    REGEX+                                  REGEX-
 ------  ------  --------------------------------------  --------
      0  []      {}                                      {}
      0  []      {}                                      {}

   #HEA  HEAD
 ------  ---------------------------------------------------------------------------------------
      6  ['ACCEPT', 'COOKIE', 'CONNECTION', 'ACCEPT-LANGUAGE', 'USER-AGENT', 'HOST']
      7  ['ACCEPT', 'REFERER', 'ACCEPT-LANGUAGE', 'USER-AGENT', 'CONNECTION', 'COOKIE', 'HOST']

 HREGEX+
 --------------------------------------------------------------------------------------------------------------
 {'CONNECTION': "('7alphabetic_punctuation', '10')", 'ACCEPT-LANGUAGE': "('7alphabetic_punctuation', '5')",
  'COOKIE': "('hailmary', '261')", 'HOST': "('7alphabetic_punctuation', '12')", 'ACCEPT': "('hailmary', '37')",
  'USER-AGENT': "('hailmary', '68')"}
 {'CONNECTION': "('7alphabetic_punctuation', '10')", 'ACCEPT-LANGUAGE': "('7alphabetic_punctuation', '5')",
  'REFERER': "('hailmary', '55')", 'HOST': "('7alphabetic_punctuation', '12')", 'COOKIE': "('hailmary', '744')",
  'ACCEPT': "('hailmary', '37')", 'USER-AGENT': "('hailmary', '68')"}

 HREGEX-
 -------------------------------------------------------------------------------------------------------------
 {'COOKIE': ['command'], 'ACCEPT': ['path'], 'USER-AGENT': ['path', 'command', 'group']}
 {'COOKIE': ['command'], 'REFERER': ['path'], 'ACCEPT': ['path'], 'USER-AGENT': ['path', 'command', 'group']}

 #COO    COOK                                                          CREGEX+
 ------  ------------------------------------------------------------  ---------------------------------------------
      4  ['__utma', '__utmz', '__utmc', 'sans']                        {'__utma': "('6numeric_punctuation', '54')",
                                                                        '__utmz': "('hailmary', '134')",
                                                                        '__utmc': "('0numeric', '9')",
                                                                        'sans': "('2hex', '32')"}
      5  ['QSI_HistorySession', '__utma', '__utmz', '__utmc', 'sans']  {'__utma': "('6numeric_punctuation', '54')",
                                                                        'QSI_HistorySession': "('hailmary', '462')",
                                                                        '__utmc': "('0numeric', '9')",
                                                                        '__utmz': "('hailmary', '134')",
                                                                        'sans': "('2hex', '32')"}

 CREGEX-
 -------------------------------------------------
 {'__utmz': ['command']}
 {'QSI_HistorySession': [], '__utmz': ['command']}
 ...SNIP...


# The simplerules script may be used independently from the webappprofiler, modify the xml profile to modify/add/remove
locations, arguments, headers, cookies, scores, ids.
./simplerules.py
 Writing modsecurity rules file... (modsec.rules)
 Generated 2739 rules


# The SimpleTransformation xslt contains the rule template used to generate the rules populating the data in the xml file
fields.

 Generating the profile from a raw audit log is slower than a direct zap connection, some times zap can give issues
 if spider features or attacks are performed over the same instance, it is better to use a separate instance for
 spidering.


# Sample XML profile extract:
<?xml version="1.0" ?>
<?xml-stylesheet type="text/xsl" version="2.0" href="SimpleTransformation.xslt" ?>
<Profile>
	<Context>
	    <Meta-Inf Author="WebAppProfiler - Author" Version="1472457127.72" />
		<Resource name="/">
			<Scheme value="https"/>
			<Method value="GET">
				<Header id="9990000" name="ACCEPT-LANGUAGE" regexp="^[,\.'\-_a-zA-Z]{5}$" required="False"/>
				<Header id="9990001" name="CONNECTION" regexp="^[,\.'\-_a-zA-Z]{10}$" required="False"/>
				<Header id="9990002" name="HOST" regexp="^[,\.'\-_a-zA-Z]{13}$" required="True">
					<Header name="HOST" value="www.somesite"/>
				</Header>
				<Cookie id="9990003" name="wikiToken" regexp="^[a-fA-F0-9]{32}$" required="False"/>
				<Cookie id="9990004" name="wikiUserID" regexp="^[\d]{5}$" required="False"/>
				<Cookie id="9990005" name="wikiUserName" regexp="^[a-zA-Z]{7}$" required="False"/>
			</Method>
		</Resource>


# profileeditor script purpose is to modify the xml profile easily to modify/add/remove in bulk elements from the
profile instead of going manually over the file manually.

./profileeditor.py
Enter action [help] : help
Usage:
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
    exit                                       - Exit


#Mantaining the profiles:
Use profileeditor to add missing locations, methods, arguments, cookies, or headers, to fit the application then run
simplerules script to generate the modified rule set.

Extract from the audit log the missing locations:
$ egrep -o "Invalid URL requested! (%{METHOD}) - (%{FILENAME}) with ARGS:(%{ARGUMENTS})

Extract arguments not listed in the profile:
$ egrep -o "\[id.+Found new parameter '/.+/' in [^\"]+" modsec_audit.log |
  sed -rn "s,\[id (.+)\].+Found.+'/(.+)/' in (.+),\1 \2 \3,p" |sort |uniq -c |sort -nr

Extract the values of the arguments:
$ egrep -o "%{ARGUMENT}=.+" modsec_audit.log |sort |uniq

TODO:
- Response profiling
- Pattern identification over multiple transactions rather than individual transaction matching
- Support actions and highly customizable rules
- Add features into the profile editor modify/add/remove elements and attributes to customize ModSecurity rules
- Improve SimpleTransformation xslt to do better and more configurable rules