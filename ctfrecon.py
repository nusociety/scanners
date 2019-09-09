#! /usr/bin/python3

import sys, os, getopt, pydoc, subprocess
from libnmap.parser import NmapParser

#-------------CSV Identifiers--------------
ID = 0
FILE = 1
DESCRIPTION = 2
DATE = 3
AUTHOR = 4
TYPE = 5
PLATFORM = 6
PORT = 7
#---My Identifiers appended to index results list---
SEARCHKEY = 8
SEARCHQUERY = 9

SSPATH = '/usr/share/exploitdb/' #searchsploit root dir
#------------------OPTIONS----------------
unixOptions = "d:i:x:"
gnuOptions = ["deep=", "index=", "nmapXML="]

class nmapParsedHost:
    def __init__(self, hostAddress=None, hostMAC=None, hostVendor=None, osFingerprint=None):
        self.hostAddress = hostAddress 
        self.hostMAC = hostMAC 
        self.hostVendor = hostVendor 
        self.osFingerprint = osFingerprint 
        self.serviceNames = []
        self.serviceFingerprints = []
        self.servicePorts = []
        self.serviceStates = []
        self.serviceBanners = []
        self.OSmatches = []
    def addServiceName(self, sName):
        self.serviceNames.append(sName)
    def addServiceFingerprint(self, sFingerprint):
        self.serviceFingerprints.append(sFingerprint)
    def addServicePort(self, sPort):
        self.servicePorts.append(sPort)
    def addServiceState(self, sState):
        self.serviceStates.append(sState)
    def addServiceBanner(self, serviceBanner):
        self.serviceBanners.append(serviceBanner)
    def addOSmatch(self, OSmatch):
        self.OSmatches.append(OSmatch)

def open_CSV(PATH):   #open, read all lines from CSV index
    if os.path.isfile(PATH) == True:
        exploitCSV = open(PATH)
        lines = exploitCSV.readlines()
        exploitCSV.close()    
        return lines
    else:
        print(PATH + ' does not exist!')
        sys.exit()
    
def search_exploits(searchStr, csvIndex):   #traverse CSV index and search all files referenced for searchStr - can be dict or string
    indexResults = [] 

    for line in csvIndex[1:]:                                           #loop through each line in the index 
        tmpStrip = line.strip('\n')           
        tmp = tmpStrip.split(',')                                           #pull each value into a list
        exploitsFilePath = SSPATH + tmp[FILE]                           #set to current lines file value 
        if os.path.isfile(exploitsFilePath) == True:                    #make sure file exists, skip if it doesn't
            with open(exploitsFilePath, 'r') as exploitFILE:
                try:
                    exploitContent = exploitFILE.read()
                    exploitContentLower = exploitContent.lower()
                    if isinstance(searchStr, dict):   #if searchStr is a dictionary, search all values, otherwise search for a string
                        for searchKey in searchStr:
                            for searchQuery in searchStr[searchKey]:
                                search = exploitContentLower.find(searchQuery.lower())
                                if search != -1:
                                    tmp.append(searchKey)
                                    tmp.append(searchQuery)
                                    indexResults.append(tmp)
                                    break
                    else:
                        search = exploitContentLower.find(searchStr.lower())
                        if search != -1:
                            tmp.append("Deep Search")
                            tmp.append(searchStr)
                            indexResults.append(tmp)
                            break       #break to prevent duplicate results
                except:
                    print('Some sort of error occured: ',  sys.exc_info()[0])  #TODO: Do proper error handling here
                exploitFILE.close
        else:
            print('Skipping ' + exploitsFilePath + '  Does not exist!')
    return indexResults

def search_exploits_index(searchStr, csvIndex):    #search only the CSV index for searchStr - can be dict or string
    indexResults = []

    for line in csvIndex[1:]:
        lineLower = line.lower()
        if isinstance(searchStr, dict):
            for searchKey in searchStr:
                for searchQuery in searchStr[searchKey]:
                    search = lineLower.find(searchQuery.lower())
                    if search != -1:
                        tmpStrip = line.strip('\n')
                        tmp = tmpStrip.split(',')   #turning into multidimensional array so display_esults can read it correctly
                        tmp.append(searchKey)
                        tmp.append(searchQuery)
                        indexResults.append(tmp)
        else:
            search = lineLower.find(searchStr.lower())

            if search != -1:               
                tmp = line.split(',')    #turning into multidimensional array so display_esults can read it correctly
                tmp.append("Index Search")
                tmp.append(searchStr)
                indexResults.append(tmp)
    return indexResults

def parse_nmap(xmlNmapPaths):   #TODO: make xmlNmapPath a list of paths and parse through all xml files in list
    parsedHosts = [] 
    x = 0
    for path in xmlNmapPaths:
        if os.path.isfile(path):
            nmap_data = NmapParser.parse_fromfile(path)
            for host in nmap_data.hosts:
                parsedHosts.append(nmapParsedHost(host.address, host.mac, host.vendor)) #create class instance as object in array parsedHosts and initialize first 3 elements

                if(host.os_fingerprinted):
                    host.osFingerprint = host.os_fingerprint                        #OS Fingerprint

                 #OS Match Parse
                OSmatches = host.os_match_probabilities()
                for OSmatch in OSmatches:
                    parsedHosts[x].addOSmatch(OSmatch.name)                         #OS Matches name 
                #Services Parse
                if host.services:
                    for s in host.services:
                        parsedHosts[x].addServiceBanner(s.banner)                   #Service banner (product + version)
                        parsedHosts[x].addServiceName(s.service)                    #Service name
                        parsedHosts[x].addServiceFingerprint(s.servicefp)           #Service fingerprint
                        parsedHosts[x].addServicePort(s.port)                       #Service port
                        parsedHosts[x].addServiceState(s.state)                     #Service state(open/close)
                x += 1
    return parsedHosts 

def display_results(rList):
    select = 1
    x = 1 

    while select != 0:
        for r in rList:
            print(f"\n\033[1;32;40m{r[SEARCHKEY]} | QUERY: {r[SEARCHQUERY]}")
            print("------------------------------------------------------")
            print(f"\033[1;32;40m{x})\033[1;31;40mFILE: \033[1;32;40m {r[FILE]} \033[1;31;40m")
            print(f"  DESCRIPTION: \033[1;32;40m {r[DESCRIPTION]} \033[1;31;40m")
            print(f"  DATE: \033[1;32;40m {r[DATE]} \033[1;31;40m")
            print(f"  AUTHOR: \033[1;32;40m {r[AUTHOR]} \033[1;31;40m")
            print(f"  TYPE: \033[1;32;40m {r[TYPE]} \033[1;31;40m")
            print(f"  PLATFORM: \033[1;32;40m {r[PLATFORM]} \033[1;31;40m")
            print(f"  PORT: \033[1;32;40m {r[PORT]}")
            x = x + 1

        print("(0 to Exit)------------------->", end=' ')
        select = int(input())

        if select == 0:
            return 0
        elif select < x and select > -1:   #TODO: Need to fix error handling for other keyboard inputs besides integers.. like arrows and shit
            if (os.path.isfile(SSPATH + rList[select - 1][FILE])) == True:
                with open(SSPATH + rList[select - 1][FILE], 'r') as exploitFILE:
                    textFile = exploitFILE.read()
                    pydoc.pager(textFile)
                    exploitFILE.close()
        else:
            print("\nNo such index!\n")

        x = 1
           
def create_nmap_search_list(parsedHosts):   #create dictionary search list from nmapParsedHost object
    searchDict = {}
    bannerSearchList = []
    OSsearchList = []
    for host in parsedHosts:
        for x in range(len(host.OSmatches)):
            OSsearchList.append(host.OSmatches[x].replace(" - ", " "))
            OSsearchList.append(host.OSmatches[x].replace("-", "<"))
            OSsearchList.append(host.OSmatches[x])
            searchDict.update({"OS MATCH: ip[" + host.hostAddress + "] " + " mac[" + host.hostMAC + "]" : OSsearchList})
            OSsearchList = []
        for x in range(len(host.serviceBanners)):
            if host.serviceBanners[x]:
                bannerSearch = host.serviceBanners[x].split(" ")
                bannerSearchList.append(bannerSearch[1] + " < " + bannerSearch[3])
                bannerSearchList.append(bannerSearch[1] + " " + bannerSearch[3])
                searchDict.update({"SERVICE MATCH: " + host.hostAddress + ":" + str(host.servicePorts[x]) : bannerSearchList})
                bannerSearchList = []
    return searchDict

def create_results_files(currentXMLpath, results, parsedHosts, searchDict):   #create output files for search results in host directory
    path = os.path.split(currentXMLpath)
    pathApart = currentXMLpath.split("/")
    os.makedirs(os.path.dirname(path[0] + "/ctfrecon/exploitDB-results"), exist_ok=True)
    with open(path[0] + "/ctfrecon/exploitDB-results", 'w') as resultsFILE:
        for host in parsedHosts:
            if host.hostAddress == pathApart[len(pathApart) - 2]:
                resultsFILE.write("Host: " + host.hostAddress + "\n")
                resultsFILE.write("MAC Address: " + host.hostMAC + "\n")
                resultsFILE.write("Vendor: " + host.hostVendor + "\n")
                resultsFILE.write("OS Matches: ")
                for OSmatch in host.OSmatches:
                    resultsFILE.write(OSmatch + "  ")

                for r in results:
                    if r[SEARCHKEY].find(pathApart[len(pathApart) -2]) != -1:
                        resultsFILE.write("\n\n" + r[SEARCHKEY] + " | QUERY: "  + r[SEARCHQUERY] + "\n")
                        resultsFILE.write("-----------------------------------------------------------\n")
                        resultsFILE.write("FILE: " + r[FILE] + "\n")
                        resultsFILE.write("DESCRIPTION: " + r[DESCRIPTION] + "\n")
                        resultsFILE.write("DATE: " + r[DATE] + "\n")
                        resultsFILE.write("AUTHOR: " + r[AUTHOR] + "\n")
                        resultsFILE.write("TYPE: " + r[TYPE] + "\n")
                        resultsFILE.write("PLATFORM: " + r[PLATFORM] + "\n")
                        resultsFILE.write("PORT: " + r[PORT] + "\n")
        resultsFILE.close()

        with open(path[0] + "/ctfrecon/.exploitDB_results_index.csv", 'w') as resultsIndexFILE:
            for r in results:
                if r[SEARCHKEY].find(pathApart[len(pathApart) - 2]) != -1:
                    rIndex = ",".join(r)
                    resultsIndexFILE.write(rIndex + "\n")
        resultsIndexFILE.close()

        with open(path[0] + "/ctfrecon/displayresults.py", 'w') as resultsDisplayFILE:
            resultsDisplayFILE.write("#!/usr/bin/python3\n\n")
            resultsDisplayFILE.write("import ctfrecon\n\n")
            resultsDisplayFILE.write("if __name__ == \"__main__\":\n")
            resultsDisplayFILE.write("    results = []\n")
            resultsDisplayFILE.write("    lines = ctfrecon.open_CSV('.exploitDB_results_index.csv')\n")
            resultsDisplayFILE.write("    for line in lines:\n")
            resultsDisplayFILE.write(r"        lineStrip = line.strip('\n')")
            resultsDisplayFILE.write("\n        results.append(lineStrip.split(','))\n")
            resultsDisplayFILE.write("    ctfrecon.display_results(results)")
        resultsDisplayFILE.close()

        status = subprocess.call("cp ctfrecon.py " + path[0] + "/ctfrecon/ctfrecon.py", shell=True)
        if status != 0:
            if status < 0:
                print("Killed by signal", status)
            else:
                print("Command failed with return code - ", status)

def check_len(someString):
    if len(someString) < 4:
        print("Search string too short!")
        exit(0)

def remove_duplicates(results1, results2):
    #remove duplicate results
    for x in range(len(results1)-1):
        for y in range(len(results2)-1):
            if results1[x] == results2[y]:
                del results2[y]
    for x in range(len(results2)-1):
        results1.append(results2[x])
    return results1

if __name__ == "__main__":

    commandArgs = sys.argv[1:]

    try:
        args, argvalue = getopt.getopt(commandArgs, unixOptions, gnuOptions)
    except getopt.error as err:
        print(str(err))
        sys.exit(2)

    if len(sys.argv) < 2:
        print("Usage: Deep Search:" + sys.argv[0] + " -d SEARCHQUERY")
        print("      Index Search:" + sys.argv[0] + " -i SEARCHQUERY")
        print("   Nmap XML Search:" + sys.argv[0] + " -x XML_FILE")
        exit(0)

    for currentArg, currentValue in args:
        if currentArg in ("-x", "--nmapXML"):
            results = []
            indexResults = []
            xmlPath = [currentValue]
            parsedHosts = parse_nmap(xmlPath)
            searchDict = create_nmap_search_list(parsedHosts)
            results = search_exploits(searchDict, open_CSV(SSPATH + 'files_exploits.csv'))
            indexResults = search_exploits_index(searchDict, open_CSV(SSPATH + 'files_exploits.csv'))
            finalResults = remove_duplicates(results, indexResults)
            create_results_files(currentValue, finalResults, parsedHosts, searchDict)
            break
        elif currentArg in ("-d", "--deep"):  #deep also runs index search
            check_len(currentValue)
            results = search_exploits(currentValue, open_CSV(SSPATH + 'files_exploits.csv'))
            indexResults = search_exploits_index(currentValue, open_CSV(SSPATH + 'files_exploits.csv'))
            finalResults = remove_duplicates(results, indexResults)
            break
        elif currentArg in ("-i", "--index"):
            check_len(currentValue)
            finalResults = search_exploits_index(currentValue, open_CSV(SSPATH + 'files_exploits.csv'))
            break

    if len(finalResults) > 0:
        display_results(finalResults)
    else:
        print("No results found for: " + currentValue)
