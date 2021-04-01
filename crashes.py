#!/usr/bin/env python3

import json
import hashlib
import os
import pprint
import re
import sys
import html
import getopt
import fx_crash_sig

from string import Template
from fx_crash_sig.crash_processor import CrashProcessor
from collections import Counter
from urllib.request import urlopen
from datetime import datetime, timedelta

# process types
# https://searchfox.org/mozilla-central/source/toolkit/components/crashes/CrashManager.jsm#162

###########################################################
# Usage
###########################################################
# -u (url)   : json datafile url
# -n (name)  : local json data filename excluding extension
# -d (name)  : html output filename excluding extension

###########################################################
# Global consts
###########################################################

# The default symbolication server to use.
SymbolServerUrl = "https://symbolication.stage.mozaws.net/symbolicate/v5"
# Max stack depth for symbolication
MaxStackDepth = 50
# Text vs. html output switch
DoHTML = True # Note, the non-html path is not maintained
# Maximum number of raw crashes to process. This matches
# the limit value of re:dash queries. Reduce for testing
# purposes.
CrashProcessMax = 3000
# Signature list length of the resulting top crashes report
MostCommonLength = 50
# When generating a report, signatures with crash counts
# lower than this value will not be included in the report.
MinCrashCount = 1
# Maximum number of crash reports to include for each signature
# in the final report. Limits the size of the resulting html.
MaxReportCount = 30
# Set to True to target a local json file for testing
LoadLocally = False
LocalJsonFile = "GPU_Raw_Crash_Data_2021_03_19.json"
# Default json file url if not specified via the command line.
jsonUrl = "https://sql.telemetry.mozilla.org/api/queries/78997/results.json?api_key=0XTUThlCYJLBQaKsc8cR4296Y6fasm8vezkZSNPg"
# Default report output filename if not specified via
# the command line.
outputFilename = "output" #.html
# Default filename for the crash stack cache file if
# not specified via the command line.
dbFilename = "crashreports" #.json

proc = CrashProcessor(MaxStackDepth, SymbolServerUrl)
# proc = CrashProcessor()
pp = pprint.PrettyPrinter(indent=2)

def symbolicate(ping):
  try:
    return proc.symbolicate(ping)
  except:
    return None

def generateSignature(payload):
  if payload is None:
    return ""
  try:
    return proc.get_signature_from_symbolicated(payload).signature
  except:
    return ""

def progress(count, total, status=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)

    sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', status))
    sys.stdout.flush()

def generateSourceLink(frame):
    # examples:
    # https://hg.mozilla.org/mozilla-central/file/2da6d806f45732e169fd8e7ea9a9761fa7fed93d/netwerk/protocol/http/OpaqueResponseUtils.cpp#l208
    # https://crash-stats.mozilla.org/sources/highlight/?url=https://gecko-generated-sources.s3.amazonaws.com/7d3f7c890af...e97be06f948921153/ipc/ipdl/PCompositorManagerParent.cpp&line=200#L-200
    # 'file': 's3:gecko-generated-sources:8276fd848664bea270...8e363bdbc972cdb7eb661c4043de93ce27810b54/ipc/ipdl/PWebGLParent.cpp:',
    # 'file': 'hg:hg.mozilla.org/mozilla-central:dom/canvas/WebGLParent.cpp:52d2c9e672d0a0c50af4d6c93cc0239b9e751d18',
    # 'line': 59,
    srcLineNumer = str()
    srcfileData = str()
    srcUrl = str()
    try:
      srcLineNumber = frame['line']
      srcfileData = frame['file']
      tokenList = srcfileData.split(':')
      if (len(tokenList) != 4):
        print("bad token list " + tokenList)
        return str()
    except:
      return str()

    if tokenList[0].find('s3') == 0:
      srcUrl = 'https://crash-stats.mozilla.org/sources/highlight/?url=https://gecko-generated-sources.s3.amazonaws.com/'
      srcUrl += tokenList[2]
      srcUrl += '&line='
      srcUrl += str(srcLineNumber)
      srcUrl += '#L-'
      srcUrl += str(srcLineNumber)
    elif tokenList[0].find('hg') == 0:
      srcUrl = 'https://'
      srcUrl += tokenList[1]
      srcUrl += '/file/'
      srcUrl += tokenList[3]
      srcUrl += '/'
      srcUrl += tokenList[2]
      srcUrl += '#l' + str(srcLineNumber)
    else:
      #print("Unknown src annoutation source") this happens a lot
      return str()

    return srcUrl

def processStack(frames):
  # Normalized function names we can consider the same in calculating
  # unique reports. We replace the regex match with the key using sub.
  coelesceFrameDict = {
    'RtlUserThreadStart': '[_]+RtlUserThreadStart'
    }

  # Functions we can replace with the normalized version, filters
  # out odd platform parameter differences.
  coelesceFunctionList = [
    'thread_start<'
    ]

  # functions we igore in calculating matching hashes.
  ignoreFunctionList = [
    '<unknown in igd10iumd64.dll>', '<unknown in igd11dxva64.dll>', '<unknown in igdumdim64.dll>',
    'RtlpLogHeapFailure', 'RtlpAnalyzeHeapFailure', 'RtlpFreeHeap',
    'RtlUserThreadStart'
    ]

  markupStack = ''
  hashData = ''

  for frame in frames:
    frameIndex = '?'
    try:
      frameIndex = frame['frame'] # zero based frame index
    except KeyError:
      continue
    except TypeError:
      #print("TypeError while indexing frame.");
      continue

    if not DoHTML:
      markupStack += '      [' + str(frameIndex) + '] '
    else:
      markupStack += "<div class='stackline'>" + str(frameIndex) + '&nbsp;&nbsp;&nbsp;'

    functionCall = ''
    normalizedFunction = ''
    skipFrame = False
    try:
      functionCall = frame['function']
      normalizedFunction = frame['normalized']
    except KeyError:
      #print("KeyError while indexing function.");
      markupStack += "(missing function)</div>"
      hashData += "(missing function)"
      continue
    except TypeError:
      print("TypeError while indexing function.");
      markupStack += "(missing function)</div>"
      hashData += "(missing function)"
      continue

    for k, v in coelesceFrameDict.items():
      functionCall = re.sub(v, k, functionCall, 1)
      break

    for v in coelesceFunctionList:
      if re.search(v, functionCall) != None:
        functionCall = normalizedFunction
        break

    for v in ignoreFunctionList:
      if re.search(v, functionCall) != None:
        skipFrame = True
        break

    srcUrl = generateSourceLink(frame)

    if (len(srcUrl) > 0):
      markupStack += escape(functionCall) + ' (<a href="' + srcUrl + '">' + 'src' + '</a>)</div>'
    else:
      markupStack += escape(functionCall) + '</div>'

    if skipFrame is False:
      hashData += functionCall


  # append meta data to our hashData so it applies to uniqueness
  hashData += operatingSystem
  hashData += operatingSystemVer
  hashData += compositor
  hashData += arch
  hashData += firefoxVer

  hash = hashlib.md5(hashData.encode('utf-8')).hexdigest()
  return hash, markupStack

# Cache a report to a local file under subfolder 'crashes'
def cacheCrashes(reports):
  os.makedirs("crashes", exist_ok=True)
  for sig in reports:
    for report in reports[sig]['reportList']:
      data = json.dumps(report)
      crashId = report['crashid']
      file = "crashes/" + crashId + ".txt"
      if not os.path.isfile(file):
        with open(file, "w") as cacheEntry:
           cacheEntry.write(data)

def findCrash(crashId):
  file = "crashes/" + crashId + ".txt"
  return os.path.isfile(file)

# Cache the reports database to a local json file. Speeds
# up symbolication runs across days by avoid re-symbolicating
# reports.
def cacheReports(reports):
  file = ("%s.json" % dbFilename)
  with open(file, "w") as database:
      database.write(json.dumps(reports))

# Load the local report database
def loadReports():
  file = ("%s.json" % dbFilename)
  data = dict()
  try:
    with open(file) as database:
      data = json.load(database)
  except FileNotFoundError:
    return dict()
  sigCount = len(data)
  reportCount = 0
  for sig in data:
    reportCount += len(data[sig]['reportList'])
  print("Existing database stats: %d signatures, %d reports" % (sigCount, reportCount))
  return data

def escape(text):
  return html.escape(text)

def checkCrashAge(dateStr):
  try:
    date = datetime.fromisoformat(dateStr)
  except:
    return False
  oldestDate = datetime.today() - timedelta(days=7)
  return (date >= oldestDate)

def purgeOldReports(reports):
  # Purge signatures that are outdated
  delSigList = list()
  for sig in reports:
    newRepList = list()
    for report in reports[sig]['reportList']:
      # "crash_date":"2021-03-22"
      dateStr = report['crashdate']
      if checkCrashAge(dateStr):
        newRepList.append(report)
    reports[sig]['reportList'] = newRepList
    if len(newRepList) == 0:
      # add this signature to our purge list
      delSigList.append(sig)
  # purge old signatures that no longer have reports
  # associated with them.
  for sig in delSigList:
    del reports[sig]
  print("Removed %d older signatures from our database." % len(delSigList))

###########################################################
# Process crashes and stacks
###########################################################

# u = redash json data source (url), n = output html path and filename, d = database path and filename
# python crashes.py -n output -d crashreports
options, remainder = getopt.getopt(sys.argv[1:], 'u:n:d:')
for o, a in options:
  if o == '-u':
    jsonUrl = a
    print("data source url: %s" %  jsonUrl)
  elif o == '-n':
    outputFilename = a
    print("output filename: %s.html" %  outputFilename)
  elif o == '-d':
    dbFilename = a
    print("local cache file: %s.json" %  dbFilename)
    
sigCounter = Counter()

props = list()
reports = dict()

totalCrashesProcessed = 0

# load up our database of processed crash ids
reports = loadReports()

if LoadLocally:
  with open(LocalJsonFile) as f:
    dataset = json.load(f)
else:
  print("loading json...")
  dataset = json.loads(urlopen(jsonUrl).read().decode("utf-8"))
  print("done.")

crashesToProcess = len(dataset["query_result"]["data"]["rows"])
if  crashesToProcess > CrashProcessMax:
  crashesToProcess = CrashProcessMax

for recrow in dataset["query_result"]["data"]["rows"]:

  if totalCrashesProcessed == CrashProcessMax:
    break

  # pull some redash props out of the recrow. You can add these
  # by modifying the sql query.
  operatingSystem = recrow['normalized_os']
  operatingSystemVer = recrow['normalized_os_version']
  firefoxVer = recrow['display_version']
  buildId = recrow['build_id']
  compositor = recrow['compositor']
  arch = recrow['arch']
  oom_size = recrow['oom_size']
  devVendor = recrow['vendor']
  devGen = recrow['gen']
  devChipset = recrow['chipset']
  devDevice = recrow['device']
  clientId = recrow['client_id']

  # Load the json crash payload from recrow
  props = json.loads(recrow["payload"])

  # touch up for the crash symbolication package
  props['stackTraces'] = props['stack_traces']

  crashId = props['crash_id']
  crashDate = props['crash_date']

  # Ignore crashes older than 7 days
  if not checkCrashAge(crashDate):
    continue

  # check if the crash id is processed, if so continue
  found = False
  signature = ""
  for sig in reports:
    for report in reports[sig]['reportList']:
      if report['crashid'] == crashId:
        found = True
        signature = sig
        # if you add a new value to the sql queries, you can update
        # the local json cache we have in memory here. Saves having
        # to delete the file and symbolicate everything again.
        # report['clientid'] = clientId
        break

  if found:
    sigCounter[signature] = len(reports[signature]['reportList'])
    totalCrashesProcessed += 1
    progress(totalCrashesProcessed, crashesToProcess)
    continue
  
  #print("processing: %s" % crashId)

  # symbolicate and return payload result
  payload = symbolicate(props)
  signature = generateSignature(payload)

  if len(signature) == 0:
    print("zero len sig")
    continue

  crash_info = props['stack_traces']['crash_info']

  if signature == 'EMPTY: no crashing thread identified':
    continue

  if signature == 'EMPTY: no frame data available':
    continue

  if signature == "<T>":
    print("sig <T>")
    continue;

  reason = str(props['metadata']['moz_crash_reason'])
  if reason != 'None':
    signature += " - " + str(props['metadata']['moz_crash_reason'])

  # pull stack information for the crashing thread
  crashingThreadIndex = payload['crashing_thread']
  threads = payload['threads']
  try:
    frames = threads[crashingThreadIndex]['frames']
  except IndexError:
    print("IndexError while indexing crashing thread");
    continue
  except TypeError:
    print("TypeError while indexing crashing thread");
    continue

  # build up a pretty stack and generate a hash of it
  hash, stack = processStack(frames)

  if signature not in reports.keys():
    reports[signature] = {'hashList':list(), 'reportList':list()}

  # save the meta data encorporated into our hash we use for uniqueness. This is displayed
  # in the signature meta data header.
  if (hash not in reports[signature]['hashList']):
    reports[signature]['hashList'].append(hash)
    reports[signature]['opoerating_system'] = operatingSystem
    reports[signature]['compositor'] = compositor
    reports[signature]['arch'] = arch
    reports[signature]['os_version'] = operatingSystemVer
    reports[signature]['firefoxVer'] = firefoxVer

  # create our report with per crash meta data
  report = {
    'clientid': clientId,
    'crashid': crashId,
    'crashdate': crashDate,
    'stack': stack,
    'oom_size': oom_size,
    'type': crash_info['type'],
    'devvendor': devVendor,
    'devgen': devGen,
    'devchipset': devChipset,
    'devdevice': devDevice
  }

  # save this crash in our report list
  reports[signature]['reportList'].append(report)

  sigCounter[signature] = len(reports[signature]['reportList'])
  totalCrashesProcessed += 1

  progress(totalCrashesProcessed, crashesToProcess)

print('\n')

###########################################################
# Post processing steps
###########################################################

# Purge signatures that are outdated
purgeOldReports(reports)

# calculate unique client id counts for each signature
clientCounts = dict()
needsUpdate = False
for sig in reports:
  clientCounts[sig] = list()
  for report in reports[sig]['reportList']:
    try:
      clientId = report['clientid']
    except:
      # this report never had its client id added when we updated the
      # report list to include client ids. set the date back far enough
      # such that purging of old reports will strip this record out.
      #report['crashdate'] = "2020-01-01"
      #needsUpdate = True
      continue
    if clientId not in clientCounts[sig]:
      clientCounts[sig].append(clientId)
  reports[sig]['clientcount'] = len(clientCounts[sig])

if needsUpdate:
  purgeOldReports(reports)

###########################################################
### HTML generation
###########################################################

signatureIndex = 0
collection = sigCounter.most_common(MostCommonLength)

if DoHTML is True:
  templateFile = open("template.html", "r")
  template = templateFile.read()
  templateFile.close()

  resultPage = ''

  # <!-- start of template -->
  # <!-- end of template -->
  sIndex = template.index('<!-- start of template -->')
  eIndex = template.index('<!-- end of template -->')
  header = template[0:sIndex]  
  footer = template[eIndex:]  
  template = template[sIndex:eIndex]

  # <!-- start of signature template -->
  # <!-- end of signature template -->
  sIndex = template.index('<!-- start of signature template -->')
  eIndex = template.index('<!-- end of signature template -->')
  sigTemplate = template[sIndex:eIndex]

  # <!-- start of signature meta template -->
  # <!-- end of signature meta template -->
  sIndex = template.index('<!-- start of signature meta template -->')
  eIndex = template.index('<!-- end of signature meta template -->')
  sigMetaTemplate = template[sIndex:eIndex]

  # <!-- start of report template -->
  # <!-- end of report template -->
  sIndex = template.index('<!-- start of report template -->')
  eIndex = template.index('<!-- end of report template -->')
  reportTemplate = template[sIndex:eIndex]

  resultFile = open(("%s.html" % outputFilename), "w")
  resultFile.write(header)

  for sig, crashcount in collection:
    try:
      sigRecord = reports[sig]
    except KeyError:
      resultFile.write("no stack data\n")
      continue

    crashcount = len(sigRecord['reportList'])
    percent = (crashcount / totalCrashesProcessed)*100.0

    if crashcount < MinCrashCount: # Skip small crash count reports
      continue

    #print('%d reports, colcount = %d clientcount = %d' % (len(sigRecord['reportList']), crashcount, sigRecord['clientcount']))

    signatureIndex += 1
    resultFile.write(Template(sigTemplate)
                     .substitute(rank=signatureIndex, percent=("%.00f%%" % percent),
                                 expandosig=('sig'+str(signatureIndex)), signature=(html.escape(sig)),
                                 clientcount=sigRecord['clientcount'], count=crashcount))

    resultFile.write(Template(sigMetaTemplate)
                      .substitute(expandosig=('sig'+str(signatureIndex)), os=sigRecord['opoerating_system'],
                                  fxver=sigRecord['firefoxVer'], osver=sigRecord['os_version'],
                                  arch=sigRecord['arch'], compositor=sigRecord['compositor']))

    idx = 0
    for report in reports[sig]['reportList']:
      idx = idx + 1
      if idx > MaxReportCount:
        break
      oombytes = report['oom_size'] if not None else '0'
      resultFile.write(Template(reportTemplate)
                       .substitute(expandostack=('st'+str(signatureIndex)+'-'+str(idx)), rindex=idx, type=report['type'],
                                  oomsize=oombytes,
                                  devvendor=report['devvendor'], devgen=report['devgen'],
                                  devchipset=report['devchipset'],
                                  stack=(report['stack'])))
    
    # Need to find a fix for this. Originally each template block was
    # isolated, but to get hiding of the reports section working, I
    # needed a div that spanned two blocked.
    resultFile.write("</div>") # <!-- NOTE this orphaned div for the expando stuff! -->

  # Add processed date to the footer
  dateTime = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
  resultFile.write(Template(footer).substitute(processeddate=dateTime))
  resultFile.close()

# Caching of reports
cacheReports(reports)



if DoHTML is False:
  # Not maintained
  reportCount = 0
  crashCount = 0

  resultFile = open("output.txt", "w")
  for sig, count in collection:

    resultFile.write("=====================================================================================================================\n")
    resultFile.write("%01d:  \'%s\'  crashes:%d\n" % (signatureIndex, sig, count))
    resultFile.write("=====================================================================================================================\n")

    signatureIndex += 1

    # pp.pprint(reports[sig]) contains hashList and reportList

    try:
      sigRecord = reports[sig]
    except KeyError:
      resultFile.write("no stack data\n")
      continue

    idx = 0
    for report in reports[sig]['reportList']:
      idx = idx + 1
      output = ''
      # signature and signature meta data
      output += 'report: #%d' % (idx)
      output += '  %s' % (report['type'])
      output += '  %s %s (%s)' % (sigRecord['opoerating_system'], sigRecord['os_version'], sigRecord['arch'])

      oombytes = report['oom_size'] if not None else '0'
      output += '  %s  oom_size:%s\n' % (sigRecord['compositor'], str(oombytes))

      output += report['stack']
      resultFile.write(output + '\n')

    crashCount += count
    reportCount += len(reports[sig]['reportList'])

  print('Total Crashes: %d Total Stacks: %d Total Reports: %d' % (crashCount, len(reports), reportCount))
  resultFile.close()


 
