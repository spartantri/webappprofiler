<?xml version="1.0" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text"/>
<xsl:template match="/Profile">
# $Id: SimpleTransformation.xslt 6 2016-08-22 12:38 spartantri@gmail.com $
#
# This rule set has been compiled using xslt transformation includes rules for:
#   Parameters, Headers, Session Cookies and Cookies checked for each registered resource
#
# Rules compatible with modsecurity 2.5 to 2.9+
#
# License:     Apache License Version 2.0
# Based on $Id: SimpleTransformation.xslt 55 2007-10-03 22:50:56Z chris@jwall.org $
#
<xsl:apply-templates><xsl:with-param name="path" select="''"/></xsl:apply-templates>

   &lt;LocationMatch &quot;^.*$&quot;&gt;
        #SecRule &amp;TX:METHOD_CHECKED  "!@gt 0" "id:9931733,auditlog,phase:2,log,msg:'Invalid URL requested! %{REQUEST_METHOD} - %{REQUEST_FILENAME} with ARGS:%{ARGS_NAMES}',redirect:UnknownURLRequested.html"
        SecRule &amp;TX:METHOD_CHECKED  "!@gt 0" "id:9931733,auditlog,phase:2,log,msg:'Invalid URL requested! %{REQUEST_METHOD} - %{REQUEST_FILENAME} with ARGS:%{ARGS_NAMES}',pass"
   &lt;/LocationMatch&gt;
</xsl:template>

<xsl:template match="Meta-Inf"># Meta-Information
#   Author : <xsl:value-of select="./@Author" />
#   Version: <xsl:value-of select="./@Version" />
 
 
SecDefaultAction phase:2,t:none,pass,log
#debuggen
</xsl:template>
<xsl:template match="SessionCookie">

#
# Session-Handling    
#
<xsl:choose>
<xsl:when test="./@ratio &gt; 0 and ./@score &gt; 0">
<xsl:if test="count(@required) > 0">    SecRule &amp;REQUEST_COOKIES:<xsl:value-of select="./@name"/> "@eq 0" "id:9931733,phase:1,setvar:tx.score=+<xsl:value-of select="./@ratio" />,pass,msg:'Missing required session cookie <xsl:value-of select="./@name"/>'"</xsl:if>
    SecRule REQUEST_COOKIES:<xsl:value-of select="./@name" /> &quot;!@rx <xsl:value-of select="./@regexp"/>&quot; "<xsl:if test="./@id = ''">id:9931733,</xsl:if><xsl:if test="./@id != ''">id:<xsl:value-of select="./@id"/>,</xsl:if>phase:1,t:none,t:urlDecode,pass,setvar:tx.score=+<xsl:value-of select="@score"/>"
</xsl:when>
<xsl:otherwise>
<xsl:if test="count(@required) > 0">    SecRule &amp;REQUEST_COOKIES:<xsl:value-of select="./@name"/> "@eq 0" "id:9931733,phase:1,setvar:tx.score=+10,pass,msg:'Missing required session cookie <xsl:value-of select="./@name"/>'"</xsl:if>
    SecRule REQUEST_COOKIES:<xsl:value-of select="./@name" /> &quot;!@rx <xsl:value-of select="./@regexp"/>&quot; "<xsl:if test="./@id = ''">id:9931733,</xsl:if><xsl:if test="./@id != ''">id:<xsl:value-of select="./@id"/>,</xsl:if>phase:1,t:none,t:urlDecode,pass,setvar:tx.score=+10"
</xsl:otherwise>
</xsl:choose>

SecRule REQUEST_COOKIES:<xsl:value-of select="./@name" /> &quot;@rx <xsl:value-of select="./@regexp"/>&quot; "id:9931733,phase:1,t:none,pass,setsid:%{REQUEST_COOKIES:<xsl:value-of select="@name"/>}"

</xsl:template>

<xsl:template match="Resource">
<xsl:if test="count(./*) - count(./Resource) > 0">
  <xsl:variable name="path"><xsl:for-each select="ancestor-or-self::Resource"><xsl:if test="./@name != ''"><xsl:value-of select="concat('',./@name)" /></xsl:if></xsl:for-each></xsl:variable>
  &lt;LocationMatch &quot;^<xsl:value-of select="$path"/>$&quot;&gt;
    #
    # mypath: <xsl:value-of select="$path"/> 
    # resource-specific rules 
    #
    <xsl:apply-templates select="Method" />

    #
    # the control-section
    #
    SecRule &amp;TX:METHOD_CHECKED "@eq 0" "id:9931733,setvar:tx.score=+1,log,auditlog,msg:'Fatal:_Invalid_request-method_for_URL_<xsl:value-of select="$path" />'"
    SecRule TX:SCORE "@gt 0" "id:9931733,log,auditlog,msg:'transaction-score is %{TX.SCORE}'"
    
    SecRule SESSION:SCORE "@gt 2" "id:9931733,log,auditlog,msg:'Session score is %{SESSION.SCORE}!'"
  &lt;/LocationMatch&gt;
</xsl:if>
<xsl:apply-templates select="Resource" />
</xsl:template>

<!--                                                      -->
<!--  The following template creates a parameter-check    -->
<!--                                                      -->
<xsl:template match="Parameter">
<xsl:choose>
<xsl:when test="./@ratio &gt; 0 and ./@score &gt; 0">
<xsl:if test="count(@required) > 0">    SecRule &amp;ARGS:<xsl:value-of select="./@name"/> "@eq 0" "id:9931733,phase:2,setvar:tx.score=+<xsl:value-of select="./@ratio" />,pass,msg:'Missing required parameter <xsl:value-of select="./@name"/>'"</xsl:if>
    SecRule ARGS:<xsl:value-of select="./@name" /> &quot;!@rx <xsl:value-of select="./@regexp"/>&quot; "<xsl:if test="./@id = ''">id:9931733,</xsl:if><xsl:if test="./@id != ''">id:<xsl:value-of select="./@id"/>,</xsl:if>phase:2,t:none,t:urlDecode,pass,setvar:tx.score=+<xsl:value-of select="@score"/>"
</xsl:when>
<xsl:otherwise>
<xsl:if test="count(@required) > 0">    SecRule &amp;ARGS:<xsl:value-of select="./@name"/> "@eq 0" "id:9931733,phase:2,setvar:tx.score=+10,pass,msg:'Missing required parameter <xsl:value-of select="./@name"/>'"</xsl:if>
    SecRule ARGS:<xsl:value-of select="./@name" /> &quot;!@rx <xsl:value-of select="./@regexp"/>&quot; "<xsl:if test="./@id = ''">id:9931733,</xsl:if><xsl:if test="./@id != ''">id:<xsl:value-of select="./@id"/>,</xsl:if>phase:2,t:none,t:urlDecode,pass,setvar:tx.score=+1"
</xsl:otherwise>
</xsl:choose>
<xsl:apply-templates />
</xsl:template>

<!--                                                      -->
<!--  The following template creates a parameterlist-check    -->
<!--                                                      -->
<xsl:template match="ParameterList">
<xsl:if test="count(@parameter_list) > 0">    SecRule ARGS_NAMES "@rx ^(.*)$" "chain,<xsl:if test="./@id = ''">id:9931733,</xsl:if><xsl:if test="./@id != ''">id:<xsl:value-of select="./@id"/>,</xsl:if>phase:2,capture,t:urlDecode,t:lowercase,pass,setvar:tx.parameter_name='/%{tx.1}/',msg:'Found new parameter %{tx.parameter_name} in %{REQUEST_METHOD} - %{REQUEST_FILENAME}'"
    SecRule TX:parameter_name "!@rx (<xsl:value-of select="./@parameter_list"/>)" "t:none,setvar:tx.score=+10,setvar:tx.new_parameter=1"
</xsl:if>
<xsl:apply-templates />
</xsl:template>

<!--                                                      -->
<!--  The following template creates a method-check       -->
<!--                                                      -->
<xsl:template match="Method">
    SecRule REQUEST_METHOD &quot;!@rx ^<xsl:value-of select="./@value"/>$&quot; "id:9931733,phase:2,t:none,log,auditlog,skip:<xsl:value-of select="count(child::*) + 1 + count(child::Parameter)"/>"
    SecAction "id:9931733,setvar:tx.method_checked=1,pass,nolog,noauditlog"
    <xsl:apply-templates select="Parameter|ParameterList|CreateToken|CheckToken|SessionCookie|Cookie|Header"/>
</xsl:template>
<xsl:template match="Cookie">
<xsl:choose>
<xsl:when test="./@ratio &gt; 0 and ./@score &gt; 0">
<xsl:if test="count(@required) > 0">    SecRule &amp;REQUEST_COOKIES:<xsl:value-of select="./@name"/> "@eq 0" "id:9931733,phase:2,setvar:tx.score=+<xsl:value-of select="./@ratio" />,pass,msg:'Missing required cookie <xsl:value-of select="./@name"/>'"</xsl:if>
    SecRule REQUEST_COOKIES:<xsl:value-of select="./@name" /> &quot;!@rx <xsl:value-of select="./@regexp"/>&quot; "<xsl:if test="./@id = ''">id:9931733,</xsl:if><xsl:if test="./@id != ''">id:<xsl:value-of select="./@id"/>,</xsl:if>phase:2,t:none,t:urlDecode,pass,setvar:tx.score=+<xsl:value-of select="@score"/>"
</xsl:when>
<xsl:otherwise>
<xsl:if test="count(@required) > 0">    SecRule &amp;REQUEST_COOKIES:<xsl:value-of select="./@name"/> "@eq 0" "id:9931733,phase:2,setvar:tx.score=+10,pass,msg:'Missing required cookie <xsl:value-of select="./@name"/>'"</xsl:if>
    SecRule REQUEST_COOKIES:<xsl:value-of select="./@name" /> &quot;!@rx <xsl:value-of select="./@regexp"/>&quot; "<xsl:if test="./@id = ''">id:9931733,</xsl:if><xsl:if test="./@id != ''">id:<xsl:value-of select="./@id"/>,</xsl:if>phase:2,t:none,t:urlDecode,pass,setvar:tx.score=+3"
</xsl:otherwise>
</xsl:choose>
</xsl:template>

<xsl:template match="Header">
<xsl:choose>
<xsl:when test="./@ratio &gt; 0 and ./@score &gt; 0">
<xsl:if test="count(@required) > 0">    SecRule &amp;REQUEST_HEADERS:<xsl:value-of select="./@name"/> "@eq 0" "id:9931733,phase:2,setvar:tx.score=+<xsl:value-of select="./@ratio" />,pass,msg:'Missing required header <xsl:value-of select="./@name"/>'"</xsl:if>
    SecRule REQUEST_HEADERS:<xsl:value-of select="./@name" /> &quot;!@rx <xsl:value-of select="./@regexp"/>&quot; "<xsl:if test="./@id = ''">id:9931733,</xsl:if><xsl:if test="./@id != ''">id:<xsl:value-of select="./@id"/>,</xsl:if>phase:2,t:none,t:urlDecode,pass,setvar:tx.score=+<xsl:value-of select="@score"/>"
</xsl:when>
<xsl:otherwise>
<xsl:if test="count(@required) > 0">    SecRule &amp;REQUEST_HEADERS:<xsl:value-of select="./@name"/> "@eq 0" "id:9931733,phase:2,setvar:tx.score=+10,pass,msg:'Missing required header <xsl:value-of select="./@name"/>'"</xsl:if>
    SecRule REQUEST_HEADERS:<xsl:value-of select="./@name" /> &quot;!@rx <xsl:value-of select="./@regexp"/>&quot; "<xsl:if test="./@id = ''">id:9931733,</xsl:if><xsl:if test="./@id != ''">id:<xsl:value-of select="./@id"/>,</xsl:if>phase:2,t:none,t:urlDecode,pass,setvar:tx.score=+1"
</xsl:otherwise>
</xsl:choose>
</xsl:template>

<xsl:template match="text()">
  <xsl:value-of select="normalize-space(.)"/>
</xsl:template>
</xsl:stylesheet>
