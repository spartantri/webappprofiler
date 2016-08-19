<?xml version="1.0" ?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="2.0">

<xsl:template match="/">
    SecDefaultAction phase:2,t:none,pass,log,noauditlog
    <xsl:for-each select="html/body/profile/location">
        SecRule URI &quot;!@eq <xsl:value-of select="name"/>&quot; &quot;id:1,skipafter:END_<xsl:value-of select="name"/>&quot;
        <xsl:for-each select="method">
            SecRule REQUEST_METHOD &quot;!@eq <xsl:value-of select="location"/> <xsl:value-of select="method"/>&quot; &quot;id:2,skipafter:END_<xsl:value-of select="name"/>_<xsl:value-of select="method"/>&quot;
            <xsl:for-each select="parameter">
                SecRule &amp;ARGS:<xsl:value-of select="name"/> &quot;@eq 0&quot; &quot;id:3,msg:'Missing argument <xsl:value-of select="name"/>'&quot;
                SecRule ARGS:<xsl:value-of select="name"/> &quot;!@rx <xsl:value-of select="regex"/>&quot; &quot;id:4,msg:'Argument <xsl:value-of select="name"/> have strange value %{matched_var}'&quot;
            </xsl:for-each>
            <xsl:for-each select="header">
                Place header here
            </xsl:for-each>
            <xsl:for-each select="cookie">
                Place cookie here
            </xsl:for-each>
        SecMarker END_<xsl:value-of select="name"/>_<xsl:value-of select="method"/>
        </xsl:for-each>
    SecMarker END_<xsl:value-of select="name"/>
    </xsl:for-each>
</xsl:template>
</xsl:stylesheet>