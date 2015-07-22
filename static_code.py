#!/usr/bin/python

#	Static Code Checker - static_code
# 	Written by bwhunan
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by  
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#   
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.        
#                                                        
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>


import sys, io, re, os, StringIO, datetime
from iffy_code import streams, servlets, XXS, response_splitting, redirection, database, SSL, c_string_copy, c_string_concat, c_sprintf, c_n_string_copy, c_n_string_concat, js_function

now = datetime.datetime.now()
mypath = ""
results = ""
search_types = ""
count = 0

def banner():
	print "######################################################################################"
	print "#                                Static Code Checker                                 #"
	print "#                                     by bwhunan                                     #"
	print "#                         blend of original and borrowed code                        #"
	print "######################################################################################"
	print "\n"

banner()
answer = raw_input("Is %s the directory you want to work with? [Yes or No]\n" % os.getcwd())
if answer == "Yes" or answer == "":
	topdir = os.getcwd()
else:
	topdir = raw_input("Enter the path to the files you want to check.\n")
exten = raw_input("Enter the extension you are searching for. \nChoices: .class, .c, .cpp, .cc, .h, .hpp, .exe, .dll, .js\nOr you may enter 'All C' to search for all c associated files.\n")

c_list = [".c", ".cc", ".h", ".cpp", ".hpp", ".exe", ".dll"]


def step(ext, dirname, names):
    ext = ext.lower()
 
    for name in names:
        if name.lower().endswith(ext):
            # This will print all the paths specific to the extension chosen above
            #print os.path.join(dirname, name)
            global results
            results += os.path.join(dirname, name)+'\n'

if exten == "All C":
	for extens in c_list:            
		os.path.walk(topdir, step, extens)
else:
	os.path.walk(topdir, step, exten)
		
s = StringIO.StringIO(results.strip())

with open("results.txt", "a") as results:
		results.write("\n{0}\nSearch results for {1} related files in {2}.\n".format(str(now), exten, topdir))

for filename in s:
	with open(filename.strip(), 'r') as f:
		search_file = f.read()
		
	if exten == ".class":
		with open("results.txt", 'a') as results:
			#results.write("\n{0} file found:\n".format(exten))	
			for term in streams:
				if term in search_file:
					print("%s: IFFY STREAM METHOD - %s") % (filename.strip().replace(topdir, ""), term)
					count += 1
					with open('results.txt', 'a') as results:
							results.write(filename.strip().replace(topdir, "") + " IFFY STREAM METHOD:" + term + "\n")
		
			for term in servlets:
				if term in search_file:
					print("%s: IFFY SERVLET METHOD - %s") % (filename.strip().replace(topdir, ""), term)
					count += 1
					with open('results.txt', 'a') as results:
							results.write(filename.strip().replace(topdir, "") + " IFFY SERVLET METHOD:" + term + "\n")
			for term in XXS:
				if term in search_file:
					print("%s: IFFY XXS METHOD - %s") % (filename.strip().replace(topdir, ""), term)
					count += 1
					with open('results.txt', 'a') as results:
							results.write(filename.strip().replace(topdir, "") + " IFFY XSS METHOD:" + term + "\n")
			for term in response_splitting:
				if term in search_file:
					print("%s: IFFY RESPONSE SPLITTING METHOD - %s") % (filename.strip().replace(topdir, ""), term)
					count += 1
					with open('results.txt', 'a') as results:
							results.write(filename.strip().replace(topdir, "") + " IFFY RESPONSE SPLITTING METHOD:" + term + "\n")
			for term in redirection:
				if term in search_file:
					print("%s: IFFY REDIRECTION METHOD - %s") % (filename.strip().replace(topdir, ""), term)
					count += 1
					with open('results.txt', 'a') as results:
							results.write(filename.strip().replace(topdir, "") + " IFFY REDIRECTION METHOD:" + term + "\n")
			for term in database:
				if term in search_file:
					print("%s: IFFY DATABASE METHOD - %s") % (filename.strip().replace(topdir, ""), term)
					count += 1
					with open('results.txt', 'a') as results:
							results.write(filename.strip().replace(topdir, "") + " IFFY DATABASE METHOD:" + term + "\n")
			for term in SSL:
				if term in search_file:
					print("%s: IFFY SSL METHOD - %s") % (filename.strip().replace(topdir, ""), term)
					count += 1
					with open('results.txt', 'a') as results:
							results.write(filename.strip().replace(topdir, "") + " IFFY SSL METHOD:" + term + "\n")
	
	if exten == ".c" or exten == ".cc" or exten == ".cpp" or exten == ".h" or exten == ".hpp" or exten == "All C":
		#print("Questionable artifact(s) found in %s:" % topdir)
		for term in c_string_copy:
			if term in search_file:
				print("%s: BANNED STRING COPY FUNCTION - %s") % (filename.strip().replace(topdir, ""), term)
				count += 1
				with open('results.txt', 'a') as results:
						results.write(filename.strip().replace(topdir, "") + " BANNED STRING COPY FUNCTION:" + term + "\n")
		
		for term in c_string_concat:
			if term in search_file:
				print("%s: BANNED STRING CONCATENATION FUNCTION - %s") % (filename.strip().replace(topdir, ""), term)
				count += 1
				with open('results.txt', 'a') as results:
						results.write(filename.strip().replace(topdir, "") + " BANNED STRING CONCATENATION FUNCTION:" + term + "\n")
		
		for term in c_sprintf:
			if term in search_file:
				print("%s: BANNED PRINT FUNCTION - %s") % (filename.strip().replace(topdir, ""), term)
				count += 1
				with open('results.txt', 'a') as results:
						results.write(filename.strip().replace(topdir, "") + " BANNED PRINT FUNCTION:" + term + "\n")
		
		for term in c_n_string_copy:
			if term in search_file:
				print("%s: BANNED STRING COPY FUNCTION - %s") % (filename.strip().replace(topdir, ""), term)
				count += 1
				with open('results.txt', 'a') as results:
						results.write(filename.strip().replace(topdir, "") + " BANNED STRING COPY FUNCTION:" + term + "\n")
		
		for term in c_n_string_concat:
			if term in search_file:
				print("%s: BANNED STRING CONCATENATION FUNCTION - %s") % (filename.strip().replace(topdir, ""), term)
				count += 1
				with open('results.txt', 'a') as results:
						results.write(filename.strip().replace(topdir, "") + " BANNED STRING CONCATENATION FUNCTION:" + term + "\n")
		
	if exten == ".js":
		for term in js_function:
			if term in search_file:
				print("%s: IFFY JAVASCRIPT FUNCTION - %s") % (filename.strip().replace(topdir, ""), term)
				count += 1
				with open('results.txt', 'a') as results:
						results.write(filename.strip().replace(topdir, "") + " IFFY JAVASCRIPT FUNCTION:" + term + "\n")	
		
if count <= 0:
	with open("results.txt", 'a') as results:
		print("Finished")
		print("\nNo {0} files found.\n".format(exten))
		results.write("Finished\nNo {0} files found.\n".format(exten))
else:
	with open("results.txt", 'a') as results:
		print("Finished")
		print("\n%s questionable artifact(s) found in %s" % (count,topdir))
		if exten == ".c" or exten == ".cc" or exten == ".cpp" or exten == ".h" or exten == ".hpp" or exten == "All C":
			print("These {0} occurrences are using functions that are prohibited according DoD Application & Development STIG Guidance.\n".format(count))
			print("For more information on these banned functions, visit https://msdn.microsoft.com/en-us/library/bb288454.aspx")
			results.write("Finished\nA total of {0} occurrences have been found that violate STIG and Microsoft guidance.\n".format(count))
			results.write("For more information, visit https://msdn.microsoft.com/en-us/library/bb288454.aspx")
				
