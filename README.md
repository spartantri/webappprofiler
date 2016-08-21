# webappprofiler
Profiling web applications and generated positive security modsecurity rules automatically

The script may generate an application profile either from modsecurity audit log or by connecting to owasp zed attack
proxy and retrieving the messages exchanges with a given web site.

The script will generate both an xml application profile and a set of modsecurity rules to validate every argument,
header, cookie and session cookie present in the profile, the profile will be then used to generate using xslt
transformation.

 ./webappprofiler.py
 ...SNIP...
 19 www.owasp.org
 20 www.sans.org

 Coose a site : 20
 Setting site filter to: www.sans.org
 HOST : www.sans.org
 Records : 139
 SCHEME    METHOD    URI                                                             #ARG  ARGS    REGEX+                                  REGEX-      #HEA  HEAD                                                                                                                                       HREGEX+                                                                                                                                                                                                                                                                                                                                                                                                                           HREGEX-                                                                                                                                   #COO  COOK                                                                              CREGEX+                                                                                                                                                                                                                                                          CREGEX-
 --------  --------  ------------------------------------------------------------  ------  ------  --------------------------------------  --------  ------  -----------------------------------------------------------------------------------------------------------------------------------------  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------  --------------------------------------------------------------------------------------------------------------------------------------  ------  --------------------------------------------------------------------------------  ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------  -------------------------------------------------
 https     GET       /                                                                  0  []      {}                                      {}             6  ['ACCEPT', 'COOKIE', 'CONNECTION', 'ACCEPT-LANGUAGE', 'USER-AGENT', 'HOST']                                                                {'CONNECTION': "('7alphabetic_punctuation', '10')", 'ACCEPT-LANGUAGE': "('7alphabetic_punctuation', '5')", 'COOKIE': "('hailmary', '261')", 'HOST': "('7alphabetic_punctuation', '12')", 'ACCEPT': "('hailmary', '37')", 'USER-AGENT': "('hailmary', '68')"}                                                                                                                                                                      {'COOKIE': ['command'], 'ACCEPT': ['path'], 'USER-AGENT': ['path', 'command', 'group']}                                                      4  ['__utma', '__utmz', '__utmc', 'sans']                                            {'__utma': "('6numeric_punctuation', '54')", '__utmz': "('hailmary', '134')", '__utmc': "('0numeric', '9')", 'sans': "('2hex', '32')"}                                                                                                                           {'__utmz': ['command']}
 ...SNIP...
 https     GET       /courses/special                                                   0  []      {}                                      {}             7  ['ACCEPT', 'REFERER', 'ACCEPT-LANGUAGE', 'USER-AGENT', 'CONNECTION', 'COOKIE', 'HOST']                                                     {'CONNECTION': "('7alphabetic_punctuation', '10')", 'ACCEPT-LANGUAGE': "('7alphabetic_punctuation', '5')", 'REFERER': "('hailmary', '55')", 'HOST': "('7alphabetic_punctuation', '12')", 'COOKIE': "('hailmary', '744')", 'ACCEPT': "('hailmary', '37')", 'USER-AGENT': "('hailmary', '68')"}                                                                                                                                     {'COOKIE': ['command'], 'REFERER': ['path'], 'ACCEPT': ['path'], 'USER-AGENT': ['path', 'command', 'group']}                                 5  ['QSI_HistorySession', '__utma', '__utmz', '__utmc', 'sans']                      {'__utma': "('6numeric_punctuation', '54')", 'QSI_HistorySession': "('hailmary', '462')", '__utmc': "('0numeric', '9')", '__utmz': "('hailmary', '134')", 'sans': "('2hex', '32')"}                                                                              {'QSI_HistorySession': [], '__utmz': ['command']}
 https     GET       /critical-security-controls/                                       0  []      {}                                      {}             7  ['ACCEPT', 'REFERER', 'ACCEPT-LANGUAGE', 'USER-AGENT', 'CONNECTION', 'COOKIE', 'HOST']                                                     {'CONNECTION': "('7alphabetic_punctuation', '10')", 'ACCEPT-LANGUAGE': "('7alphabetic_punctuation', '5')", 'REFERER': "('hailmary', '49')", 'HOST': "('7alphabetic_punctuation', '12')", 'COOKIE': "('hailmary', '2290')", 'ACCEPT': "('hailmary', '37')", 'USER-AGENT': "('hailmary', '68')"}                                                                                                                                    {'COOKIE': ['command'], 'REFERER': ['path'], 'ACCEPT': ['path'], 'USER-AGENT': ['path', 'command', 'group']}                                 7  ['__utmz', 'sans', '__utma', '__utmb', '__utmc', '__utmt', 'QSI_HistorySession']  {'__utmz': "('hailmary', '134')", 'sans': "('2hex', '32')", '__utma': "('6numeric_punctuation', '54')", '__utmb': "('6numeric_punctuation', '27')", '__utmc': "('0numeric', '9')", '__utmt': "('0numeric', '1')", 'QSI_HistorySession': "('hailmary', '1962')"}  {'__utmz': ['command'], 'QSI_HistorySession': []}
 https     GET       /critical-vulnerability-recaps                                     0  []      {}                                      {}             7  ['ACCEPT', 'REFERER', 'ACCEPT-LANGUAGE', 'USER-AGENT', 'CONNECTION', 'COOKIE', 'HOST']                                                     {'CONNECTION': "('7alphabetic_punctuation', '10')", 'ACCEPT-LANGUAGE': "('7alphabetic_punctuation', '5')", 'REFERER': "('hailmary', '40')", 'HOST': "('7alphabetic_punctuation', '12')", 'COOKIE': "('hailmary', '2316')", 'ACCEPT': "('hailmary', '37')", 'USER-AGENT': "('hailmary', '68')"}                                                                                                                                    {'COOKIE': ['command'], 'REFERER': ['path'], 'ACCEPT': ['path'], 'USER-AGENT': ['path', 'command', 'group']}                                 7  ['__utmz', 'sans', '__utma', '__utmb', '__utmc', '__utmt', 'QSI_HistorySession']  {'__utmz': "('hailmary', '134')", 'sans': "('2hex', '32')", '__utma': "('6numeric_punctuation', '54')", '__utmb': "('6numeric_punctuation', '27')", '__utmc': "('0numeric', '9')", '__utmt': "('0numeric', '1')", 'QSI_HistorySession': "('hailmary', '1988')"}  {'__utmz': ['command'], 'QSI_HistorySession': []}
 https     GET       /css2/common/bootstrap/main.css                                    1  ['v']   {'v': "('6numeric_punctuation', '3')"}  {}             7  ['ACCEPT', 'REFERER', 'ACCEPT-LANGUAGE', 'USER-AGENT', 'CONNECTION', 'COOKIE', 'HOST']                                                     {'CONNECTION': "('7alphabetic_punctuation', '10')", 'ACCEPT-LANGUAGE': "('7alphabetic_punctuation', '5')", 'REFERER': "('hailmary', '38')", 'HOST': "('7alphabetic_punctuation', '12')", 'COOKIE': "('hailmary', '548')", 'ACCEPT': "('hailmary', '13')", 'USER-AGENT': "('hailmary', '68')"}                                                                                                                                     {'COOKIE': ['command'], 'REFERER': ['path'], 'ACCEPT': ['path'], 'USER-AGENT': ['path', 'command', 'group']}                                 5  ['QSI_HistorySession', '__utma', '__utmz', '__utmc', 'sans']                      {'__utma': "('6numeric_punctuation', '54')", 'QSI_HistorySession': "('hailmary', '266')", '__utmc': "('0numeric', '9')", '__utmz': "('hailmary', '134')", 'sans': "('2hex', '32')"}                                                                              {'QSI_HistorySession': [], '__utmz': ['command']}
 https     GET       /css2/common/design/styles_sans.css                                1  ['v']   {'v': "('6numeric_punctuation', '3')"}  {}             7  ['ACCEPT', 'REFERER', 'ACCEPT-LANGUAGE', 'USER-AGENT', 'CONNECTION', 'COOKIE', 'HOST']                                                     {'CONNECTION': "('7alphabetic_punctuation', '10')", 'ACCEPT-LANGUAGE': "('7alphabetic_punctuation', '5')", 'REFERER': "('hailmary', '21')", 'HOST': "('7alphabetic_punctuation', '12')", 'COOKIE': "('hailmary', '261')", 'ACCEPT': "('hailmary', '13')", 'USER-AGENT': "('hailmary', '68')"}                                                                                                                                     {'COOKIE': ['command'], 'REFERER': ['path'], 'ACCEPT': ['path'], 'USER-AGENT': ['path', 'command', 'group']}                                 4  ['__utma', '__utmz', '__utmc', 'sans']                                            {'__utma': "('6numeric_punctuation', '54')", '__utmz': "('hailmary', '134')", '__utmc': "('0numeric', '9')", 'sans': "('2hex', '32')"}                                                                                                                           {'__utmz': ['command']}
...SNIP...

 Writing modsecurity rules file... (modsec.rules)
 Generated 2739 rules

The simplerules script may be used independently from the webappprofiler, modify the xml profile to modify/add/remove
locations, arguments, headers, cookies, scores, ids.

The SimpleTransformation xslt contains the rule template used to generate the rules populating the data in the xml file
fields.

 Generating the profile from a raw audit log is slower than a direct zap connection, some times zap can give issues
 if spider features or attacks are performed over the same instance, it is better to use a separate instance for
 spidering.

 XML profile extract:
 <?xml version="1.0" ?>
<?xml-stylesheet type="text/xsl" version="2.0" href="SimpleTransformation.xslt" ?>
<Profile>
	<Context>
		<Resource name="/">
			<Scheme value="https"/>
			<Method value="GET">
				<Header id="9990000" name="ACCEPT-LANGUAGE" regexp="^[,\.'\-_a-zA-Z]{5}$" required="False"/>
				<Header id="9990001" name="CONNECTION" regexp="^[,\.'\-_a-zA-Z]{10}$" required="False"/>
				<Header id="9990002" name="HOST" regexp="^[,\.'\-_a-zA-Z]{13}$" required="True">
					<Header name="HOST" value="www.owasp.org"/>
				</Header>
				<Cookie id="9990003" name="wikiToken" regexp="^[a-fA-F0-9]{32}$" required="False"/>
				<Cookie id="9990004" name="wikiUserID" regexp="^[\d]{5}$" required="False"/>
				<Cookie id="9990005" name="wikiUserName" regexp="^[a-zA-Z]{7}$" required="False"/>
			</Method>
		</Resource>

The profileeditor script purpose is to modify the xml profile easily to modify/add/remove in bulk elements from the
profile instead of going manually over the file manually

TODO:
- Response profiling
- Pattern identification over multiple transactions rather than individual transaction matching
- Support actions and highly customizable rules
- Add features into the profile editor modify/add/remove elements in bulk
- Improve SimpleTransformation xslt to do better and more configurable rules