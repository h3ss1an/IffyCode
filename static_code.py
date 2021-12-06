#!/usr/bin/env python3

import argparse
import sys
import io
import os
import datetime
from iffy_code import streams, servlets, XXS, response_splitting, redirection, database, SSL, c_string_copy, c_string_concat, c_sprintf, c_n_string_copy, c_n_string_concat, js_function, php_function

parser = argparse.ArgumentParser(
	usage="%(prog)s -c",
	description="Use one or more arguments to search for potentially vulnerable functions."
)
parser.add_argument('-c', '--c_cplusplus', action='store_true', help='C and C++ search', required=False)
parser.add_argument('-j', '--java', action='store_true', help='Java search', required=False)
parser.add_argument('-js', '--javascript', action='store_true', help='JavaScript search', required=False)
parser.add_argument('-php', '--php', action='store_true', help='PHP search', required=False)
args = parser.parse_args()

now = datetime.datetime.now()
mypath = ""
results = ""
count = 0

def banner():
	print("######################################################################################")
	print("#                                Static Code Checker                                 #")
	print("#                                   by Will Harmon                                   #")
	print("#                                                                                    #")
	print("######################################################################################")
	print("\n")
# function to take care of the directory walking
def stepper(path, file_extensions):
	file_list = []
	for root, dir_names, file_names in os.walk(path):
		for file in file_names:
			for extension in file_extensions:
				# Only add specific file to file_list if the extension matches
				if file.rsplit(".")[-1] == extension:
					file_list.append(os.path.join(root, file))
	return file_list

def c_code(topdir):
	with open("results.txt", "a") as results:
			results.write("\n{0}\nIffy Code search results for C code.\n".format(str(now)))
	count = 0
	print("In the c_code function!\n")
	c_extension_list = ["c", "cc", "h", "cpp", "hpp"]
	file_list = stepper(topdir, c_extension_list)
	print("[+] Discovered {} C type files.\nContinuing analysis for potentially vulnerable functions.\n".format(len(file_list)))

	for filename in file_list:
		#print(filename)
		if (filename.split(".")[-1] == "exe"):
			break
		if (filename.split(".")[-1] == "dll"):
			break
		else:
			with open(filename.strip(), "r", encoding="utf-8", errors="ignore") as f:
				for term in c_string_copy:
					linenum = 0
					for line in f:
						linenum += 1
						if term in line:
							print("Filename: {}".format(filename))
							print("BANNED STRING COPY FUNCTION: {}, line: {}".format(term,linenum))
							print("Line: {}".format(line.strip()))
							count += 1

							with open('results.txt', 'a') as results:
								results.write(filename + "\nBANNED STRING COPY FUNCTION: {}, line: {}\n".format(term, str(linenum)))

				for term in c_string_concat:
					linenum = 0
					for line in f:
						linenum += 1
						if term in line:
							print("Filename: {}".format(filename))
							print("BANNED STRING CONCATENATION FUNCTION: {}, line: {}".format(term, str(linenum)))
							print("Line: {}".format(line.strip()))
							count += 1

							with open('results.txt', 'a') as results:
								results.write(filename + "\nBANNED STRING CONCATENATION FUNCTION: {}, line: {}\n".format(term, str(linenum)))


				for term in c_sprintf:
					linenum = 0
					for line in f:
						linenum += 1
						if term in line:
							print("Filename: {}".format(filename))
							print("BANNED PRINT FUNCTION: {}, line: {}".format(term, str(linenum)))
							print("Line: {}".format(line.strip()))
							count += 1

							with open('results.txt', 'a') as results:
								results.write(filename + "\nBANNED PRINT FUNCTION: {}, line: {}\n".format(term, str(linenum)))

				for term in c_n_string_copy:
					linenum = 0
					for line in f:
						linenum += 1
						if term in line:
							print("Filename: {}".format(filename))
							print("BANNED STRING COPY FUNCTION: {}, line: {}".format(term, str(linenum)))
							print("Line: {}".format(line.strip()))
							count += 1

							with open('results.txt', 'a') as results:
								results.write(filename + "\nBANNED STRING COPY FUNCTION: {}, line: {}\n".format(term, str(linenum)))

				for term in c_n_string_concat:
					linenum = 0
					for line in f:
						linenum += 1
						if term in line:
							print("Filename: {}".format(filename))
							print("BANNED STRING CONCATENATION FUNCTION: {}, line: {}".format(term, str(linenum)))
							print("Line: {}".format(line.strip()))
							count += 1

							with open('results.txt', 'a') as results:
								results.write(filename + "\nBANNED STRING CONCATENATION FUNCTION: {}, line: {}\n".format(term, str(linenum)))
	with open('results.txt', 'a') as results:
		results.write("---------------------------------------------------------\n")
		results.write("[+] Total banned C functions found: {}.\n".format(str(count)))
		if count > 0:
			results.write("These {0} occurrences are using functions that are prohibited according DoD Application & Development STIG Guidance.\n".format(count))
			results.write("For more information on these banned functions, visit https://msdn.microsoft.com/en-us/library/bb288454.aspx.\n")
	print("---------------------------------------------------------")
	print("[+] Total banned C functions found: {}".format(str(count)))
	if count > 0:
		print("These {0} occurrences are using functions that are prohibited according DoD Application & Development STIG Guidance.\n".format(count))
		print("For more information on these banned functions, visit https://msdn.microsoft.com/en-us/library/bb288454.aspx")

def java_code(topdir):
	with open("results.txt", "a") as results:
			results.write("\n{0}\nIffy Code search results for Java code.\n".format(str(now)))
	count = 0
	print("In the java_code function!\n")
	java_extension_list = ["class", "java"]
	file_list = stepper(topdir, java_extension_list)
	print("[+] Discovered {} Java type files.\nContinuing analysis for potentially vulnerable functions.\n".format(len(file_list)))

	for filename in file_list:
		with open(filename.strip(), "r", encoding="utf-8", errors="ignore") as f:
			for term in streams:
				linenum = 0
				for line in f:
					linenum += 1
					if term in line:
						print("Filename: {}".format(filename))
						print("IFFY STREAM METHOD: {}, line: {}".format(term,linenum))
						print("Line: {}".format(line.strip()))
						count += 1
						with open('results.txt', 'a') as results:
							results.write(filename + "\nIFFY STREAM METHOD: {}, line: {}\n".format(term, str(linenum)))

			for term in servlets:
				linenum = 0
				for line in f:
					linenum += 1
					if term in line:
						print("Filename: {}".format(filename))
						print("IFFY SERVLET METHOD: {}, line: {}".format(term, linenum))
						print("Line: {}".format(line.strip()))
						count += 1
						with open('results.txt', 'a') as results:
							results.write(filename + "\nIFFY SERVLET METHOD: {}, line: {}\n".format(term, str(linenum)))

			for term in XXS:
				linenum = 0
				for line in f:
					linenum += 1
					if term in line:
						print("Filename: {}".format(filename))
						print("IFFY XSS METHOD: {}, line: {}".format(term, linenum))
						print("Line: {}".format(line.strip()))
						count += 1
						with open('results.txt', 'a') as results:
							results.write(filename + "\nIFFY XSS METHOD: {}, line: {}\n".format(term, str(linenum)))

			for term in response_splitting:
				linenum = 0
				for line in f:
					linenum += 1
					if term in line:
						print("Filename: {}".format(filename))
						print("IFFY RESPONSE SPLITTING METHOD: {}, line: {}".format(term, str(linenum)))
						print("Line: {}".format(line.strip()))
						count += 1
						with open('results.txt', 'a') as results:
							results.write(filename + "\nIFFY RESPONSE SPLITTING METHOD: {}, line: {}\n".format(term, str(linenum)))

			for term in redirection:
				linenum = 0
				for line in f:
					linenum += 1
					if term in line:
						print("Filename: {}".format(filename))
						print("IFFY REDIRECTION METHOD: {}, line: {}".format(term, str(linenum)))
						print("Line: {}".format(line.strip()))
						count += 1
						with open('results.txt', 'a') as results:
							results.write(filename + "\nIFFY REDIRECTION METHOD: {}, line: {}\n".format(term, str(linenum)))

			for term in database:
				linenum = 0
				for line in f:
					linenum += 1
					if term in line:
						print("Filename: {}".format(filename))
						print("IFFY DATABASE METHOD: {}, line: {}".format(term, str(linenum)))
						print("Line: {}".format(line.strip()))
						count += 1
						with open('results.txt', 'a') as results:
							results.write(filename + "\nIFFY DATABASE METHOD: {}, line: {}\n".format(term, str(linenum)))

			for term in SSL:
				linenum = 0
				for line in f:
					linenum += 1
					if term in line:
						print("Filename: {}".format(filename))
						print("IFFY SSL METHODD: {}, line: {}".format(term, str(linenum)))
						print("Line: {}".format(line.strip()))
						count += 1
						with open('results.txt', 'a') as results:
							results.write(filename + "\nIFFY SSL METHODD: {}, line: {}\n".format(term, str(linenum)))

	with open('results.txt', 'a') as results:
		results.write("---------------------------------------------------------\n")
		results.write("[+] Total iffy Java functions found: {}.\n".format(str(count)))

	print("---------------------------------------------------------")
	print("[+] Total iffy Java functions found: {}".format(str(count)))

def php_code(topdir):
	with open("results.txt", "a") as results:
			results.write("\n{0}\nIffy Code search results for PHP code.\n".format(str(now)))
	count = 0
	print("In the php_code function!\n")
	php_extension_list = ["phtml", "php3", "php4", "php5", "phps"]
	file_list = stepper(topdir, php_extension_list)
	print("[+] Discovered {} PHP type files.\nContinuing analysis for potentially vulnerable functions.\n".format(len(file_list)))

	for filename in file_list:
		with open(filename.strip(), "r", encoding="utf-8", errors="ignore") as f:
			for term in php_function:
				linenum = 0
				for line in f:
					linenum += 1
					if term in line:
						print("Filename: {}".format(filename))
						print("POTENTIAL EXEC FUNCTION: {}, line: {}".format(term,linenum))
						print("Line: {}".format(line.strip()))
						count += 1
						with open('results.txt', 'a') as results:
							results.write(filename + "\nPOTENTIAL EXEC FUNCTION: {}, line: {}\n".format(term, str(linenum)))

	with open('results.txt', 'a') as results:
		results.write("---------------------------------------------------------\n")
		results.write("[+] Total iffy PHP functions found: {}.\n".format(str(count)))

	print("---------------------------------------------------------")
	print("[+] Total iffy PHP functions found: {}".format(str(count)))

def js_code(topdir):
	with open("results.txt", "a") as results:
			results.write("\n{0}\nIffy Code search results for JavaScript code.\n".format(str(now)))
	count = 0
	print("In the js_code function!\n")
	js_extension_list = ["js"]
	file_list = stepper(topdir, js_extension_list)
	print("[+] Discovered {} JavaScript type files.\nContinuing analysis for potentially vulnerable functions.\n".format(len(file_list)))

	for filename in file_list:
		with open(filename.strip(), "r", encoding="utf-8", errors="ignore") as f:
			for term in js_function:
				linenum = 0
				for line in f:
					linenum += 1
					if term in line:
						print("Filename: {}".format(filename))
						print("IFFY JAVASCRIPT FUNCTION: {}, line: {}".format(term,linenum))
						print("Line: {}".format(line.strip()))
						count += 1
						with open('results.txt', 'a') as results:
							results.write(filename + "\nIFFY JAVASCRIPT FUNCTION: {}, line: {}\n".format(term, str(linenum)))

	with open('results.txt', 'a') as results:
		results.write("---------------------------------------------------------\n")
		results.write("[+] Total iffy JavaScript functions found: {}.\n".format(str(count)))

	print("---------------------------------------------------------")
	print("[+] Total iffy JavaScript functions found: {}".format(str(count)))

def main():
	banner()
	if len(sys.argv) < 2:
		print("At least one argument is required. Use -h for help.")
		sys.exit(0)

	answer = input("Is {} the directory you want to work with? [Yes or No]\n".format(os.getcwd()))
	if answer == "Yes" or answer == "":
		topdir = os.getcwd()
	else:
		topdir = input("Enter the path to the files you want to check.\n")

	if args.c_cplusplus:
		c_code(topdir)
	if args.java:
		java_code(topdir)
	if args.javascript:
		js_code(topdir)
	if args.php:
		php_code(topdir)

if __name__ == '__main__':
    main()
