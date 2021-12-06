#!/usr/bin/env python3



##############
# JAVA TERMS #
##############

# Input and Output Streams
streams = ["Java.io", "java.util.zip", "java.util.jar", "FileInputStream", "ObjectInputStream", "FilterInputStream", "PipedInputStream", "SequenceInputStream", "StringBufferInputStream", "BufferedReader", "ByteArrayInputStream", "CharArrayReader", "ObjectInputStream", "PipedInputStream", "StreamTokenizer", "getResourceAsStream", "java.io.FileReader", "java.io.FileWriter", "java.io.RandomAccessFile", "java.io.Filev", "java.io.FileOutputStream", "mkdir", "renameTo"]

# Servlets
servlets = ['javax.servlet.*', 'getParameterNames', 'getParameterValues', 'getParameter', 'getParameterMap', 'getScheme', 'getProtocol', 'getContentType', 'getServerName', 'getRemoteAddr', 'getRemoteHost', 'getRealPath', 'getLocalName', 'getAttribute', 'getAttributeNames', 'getLocalAddr', 'getAuthType', 'getRemoteUser', 'getCookies', 'isSecure', 'HttpServletRequest', 'getQueryString', 'getHeaderNames', 'getHeaders', 'getPrincipal', 'getUserPrincipal', 'isUserInRole', 'getInputStream', 'getOutputStream', 'getWriter\raddCookie\raddHeader\rsetHeader\rsetAttribute\rputValue', 'javax.servlet.http.Cookie', 'getName\rgetPath', 'getDomain', 'getComment', 'getMethod', 'getPath', 'getReader', 'getRealPath', 'getRequestURI', 'getRequestURL', 'getServerName', 'getValue', 'getValueNames', 'getRequestedSessionId']

XXS = ['javax.servlet.ServletOutputStream.print', 'javax.servlet.jsp.JspWriter.print', 'java.io.PrintWriter.print']

response_splitting = ['javax.servlet.http.HttpServletResponse.sendRedirect', 'addHeader', 'setHeader']

redirection = ['sendRedirect', 'setStatus', 'addHeader', 'setHeader']

database = ['jdbc', 'createStatement', 'executeQuery', 'select', 'insert', 'update', 'delete', 'execute', 'executestatement', 'java.sql.Connection.prepareStatement', 'java.sql.Connection.prepareCall', 'java.sql.ResultSet.getString', 'java.sql.ResultSet.getObject', 'java.sql.Statement.executeUpdate', 'java.sql.Statement.executeQuery', 'java.sql.Statement.execute', 'java.sql.Statement.addBatch']

SSL = ['com.sun.net.ssl', 'SSLContext', 'SSLSocketFactory', 'TrustManagerFactory', 'HttpsURLConnection', 'KeyManagerFactory']




###############
# C/C++ TERMS #
###############


'''
Banned string copy functions and replacements
StrSafe Replacement: String*1Copy or String*CopyEx (For StrSafe, * should be replaced with Cch (character count) or Cb (byte count))
Safe CRT Replacement: strcpy_s
'''
c_string_copy = ['strcpy', 'strcpyA', 'strcpyW', 'wcscpy', '_tcscpy', '_mbscpy', 'StrCpy', 'StrCpyA', 'StrCpyW', 'lstrcpy', 'lstrcpyA', 'lstrcpyW', '_tccpy', '_mbccpy', '_ftcscpy', 'strncpy', 'wcsncpy', '_tcsncpy', '_mbsncpy', '_mbsnbcpy', 'StrCpyN', 'StrCpyNA', 'StrCpyNW', 'StrNCpy', 'strcpynA', 'StrNCpyA', 'StrNCpyW', 'lstrcpyn', 'lstrcpynA', 'lstrcpynW']

'''
Banned string concatenation functions and replacements
StrSafe Replacement: String.Cat or String*CatEx
SafeCRT Replacement: strcat_s
'''

c_string_concat = ['lstrcatn', 'strcat', 'strcatA', 'strcatW', 'wcscat', '_tcscat', '_mbscat', 'StrCat', 'StrCatA', 'StrCatW', 'lstrcat', 'lstrcatA', 'lstrcatW', 'StrCatBuff', 'StrCatBuffA', 'StrCatBuffW', 'StrCatChainW', '_tccat', '_mbccat', '_ftcscat', 'strncat', 'wcsncat', '_tcsncat', '_mbsncat', '_mbsnbcat', 'StrCatN', 'StrCatNA', 'StrCatNW', 'StrNCat', 'StrNCatA', 'StrNCatW', 'lstrncat', 'lstrcatnA', 'lstrcatnW', 'lstrcatn']

'''
Banned sprintf functions and replacements
StrSafe Replacement: String*Printf or String*PrintfEx
SafeCRT Replacement: sprintf_s

Recommended: wnsprintf, wnsprintfA, wnsprintfW, _snwprintf, snprintf, sntprintf _vsnprintf, vsnprintf, _vsnwprintf, _vsntprintf, wvnsprintf, wvnsprintfA, wvnsprintfW
'''
c_sprintf = ['sprintfW', 'sprintfA', 'wsprintf', 'wsprintfW', 'wsprintfA', 'sprintf', 'swprintf', '_stprintf', 'wvsprintf', 'wvsprintfA', 'wvsprintfW', 'vsprintf', '_vstprintf', 'vswprintf']

'''
Banned "n" string copy functions and replacements
StrSafe Replacement: String*CopyN or String*CopyNEx
Safe CRT Replacement: strncpy_s
'''

c_n_string_copy = ['strncpy', 'wcsncpy', '_tcsncpy', '_mbsncpy', '_mbsnbcpy', 'StrCpyN', 'StrCpyNA', 'StrCpyNW', 'StrNCpy', 'strcpynA', 'StrNCpyA', 'StrNCpyW', 'lstrcpyn', 'lstrcpynA', 'lstrcpynW', '_fstrncpy']

'''
Banned "n" string concatenation functions and replacements
StrSafe Replacement: String*CatN or String*CatNEx
Safe CRT Replacement: strncat_s

Developers frequently replace functions like strcpy with the counted "n" version, such as strncpy. This practice is not recommended. In our experience, the "n" functions are also hard to secure (Howard 2004), so we have banned their use in new code.
'''
c_n_string_concat = ['strncat', 'wcsncat', '_tcsncat', '_mbsncat', '_mbsnbcat', 'StrCatN', 'StrCatNA', 'StrCatNW', 'StrNCat', 'StrNCatA', 'StrNCatW', 'lstrncat', 'lstrcatnA', 'lstrcatnW', 'lstrcatn', '_fstrncat']

####################
#	JavaScript TERMS #
####################


'''
Ajax and JavaScript have brought functionality back to the client side, which has brought a number of old security issues back to the forefront. The following keywords relate to API calls used to manipulate user state or the control the browser. The event of AJAX and other Web 2.0 paradigms has pushed security concerns back to the client side, but not excluding traditional server side security concerns.
'''
js_function = ['eval(', 'document.cookie ', 'document.referrer ', 'document.attachEvent ', 'document.body ', 'document.body.innerHtml ', 'document.body.innerText ', 'document.close ', 'document.create ', 'document.createElement ', 'document.execCommand ', 'document.forms[0].action ', 'document.location ', 'document.open ', 'document.URL ', 'document.URLUnencoded', 'document.write ', 'document.writeln ', 'location.hash ', 'location.href ', 'location.search ', 'window.alert ', 'window.attachEvent ', 'window.createRequest ', 'window.execScript ', 'window.location ', 'window.open ', 'window.navigate ', 'window.setInterval ', 'window.setTimeout ', 'XMLHTTP']

#############
#	PHP TERMS #
#############


'''
PHP
'''
php_function = ['exec(']
