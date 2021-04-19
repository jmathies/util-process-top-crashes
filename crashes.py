#!/usr/bin/env python3

import json
import hashlib
import os
import pprint
import re
import sys
import html
import getopt
import threading
import itertools
import time
import requests
import math

from string import Template
from collections import Counter
from urllib.request import urlopen
from urllib import request
from datetime import datetime, timedelta

import fx_crash_sig
from fx_crash_sig.crash_processor import CrashProcessor

# process types
# https://searchfox.org/mozilla-central/source/toolkit/components/crashes/CrashManager.jsm#162

###########################################################
# Usage
###########################################################
# -u (url)      : redash rest endpoint url
# -k (str)      : redash user api key
# -q (query id) : redash api query id
# -n (name)     : local json cache filename to use (excluding extension)
# -d (name)     : local html output filename to use (excluding extension)
# -c (count)    : number of reports to process, overrides the default
# -p (k=v)      : k=v redash query parameters to pass to the query request.
# python crashes.py -n nightly -d nightly -u https://sql.telemetry.mozilla.org -k (userapikey) -q 79354 -p process_type=gpu -p version=89 -p channel=nightly

## TODO
## bugzilla search
## rudimentary annotation support through a static json file
## battery-quarter for ooms

###########################################################
# Global consts
###########################################################

# The default symbolication server to use.
SymbolServerUrl = "https://symbolication.stage.mozaws.net/symbolicate/v5"
# Max stack depth for symbolication
MaxStackDepth = 50
# Maximum number of raw crashes to process. This matches
# the limit value of re:dash queries. Reduce for testing
# purposes.
CrashProcessMax = 5000
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
# Report analysis type - 0 = graphics, 1 = media. Controsl what
# we use in identifying unique signatures.
ReportType = 0 # currently not used
# Default json file url if not specified via the command line.
jsonUrl = "https://sql.telemetry.mozilla.org/api/queries/78997/results.json?api_key=0XTUThlCYJLBQaKsc8cR4296Y6fasm8vezkZSNPg"
# Default report output filename if not specified via
# the command line.
outputFilename = "output" #.html
# Default filename for the crash stack cache file if
# not specified via the command line.
dbFilename = "crashreports" #.json

proc = CrashProcessor(MaxStackDepth, SymbolServerUrl)
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

class Spinner:
  def __init__(self, message, delay=0.1):
    self.spinner = itertools.cycle(['-', '/', '|', '\\'])
    self.delay = delay
    self.busy = False
    self.spinner_visible = False
    sys.stdout.write(message)

  def write_next(self):
    with self._screen_lock:
      if not self.spinner_visible:
        sys.stdout.write(next(self.spinner))
        self.spinner_visible = True
        sys.stdout.flush()

  def remove_spinner(self, cleanup=False):
    with self._screen_lock:
      if self.spinner_visible:
        sys.stdout.write('\b')
        self.spinner_visible = False
        if cleanup:
          sys.stdout.write(' ')       # overwrite spinner with blank
          sys.stdout.write('\r')      # move to next line
        sys.stdout.flush()

  def spinner_task(self):
    while self.busy:
      self.write_next()
      time.sleep(self.delay)
      self.remove_spinner()

  def __enter__(self):
    if sys.stdout.isatty():
      self._screen_lock = threading.Lock()
      self.busy = True
      self.thread = threading.Thread(target=self.spinner_task)
      self.thread.start()

  def __exit__(self, exception, value, tb):
    if sys.stdout.isatty():
      self.busy = False
      self.remove_spinner(cleanup=True)
    else:
      sys.stdout.write('\r')

def poll_job(s, redash_url, job):
  while job['status'] not in (3,4):
      response = s.get('{}/api/jobs/{}'.format(redash_url, job['id']))
      job = response.json()['job']
      time.sleep(1)

  if job['status'] == 3:
      return job['query_result_id']
    
  return None

def getchRedashQueryResult(redash_url, query_id, api_key, params):
  s = requests.Session()
  s.headers.update({'Authorization': 'Key {}'.format(api_key)})

  payload = dict(max_age=86400, parameters=params)

  url = "%s/api/queries/%s/results" % (redash_url, query_id)
  response = s.post(url, data=json.dumps(payload))

  if response.status_code != 200:
    print("\nquery error '%s'" % response)
    pp.pprint(payload)
    raise Exception('Redash query failed.')
  
  #{ 'job': { 'error': '',
  #           'id': '21429857-5fd0-443d-ba4b-fb9cc6d49add',
  #           'query_result_id': None,
  #           'result': None,
  #           'status': 1,
  #           'updated_at': 0}}
  # ...or, we just get back the result

  try:
    result = response.json()['job']
  except KeyError:
    return response.json()

  result_id = poll_job(s, redash_url, response.json()['job'])

  response = s.get('{}/api/queries/{}/results/{}.json'.format(redash_url, query_id, result_id))

  if response.status_code != 200:
      raise Exception('Failed getting results. (Check your redash query for errors.) statuscode=%d' % response.status_code)

  return response.json()

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

  dataStack = list() # [idx] = { 'frame': '(frame)', 'srcUrl': '(url)' }
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

    dataStack.insert(frameIndex, { 'index': frameIndex, 'frame': '', 'srcUrl': '', 'module': '' })

    functionCall = ''
    normalizedFunction = ''
    module = ''
    skipFrame = False
    try:
      functionCall = frame['function']
      normalizedFunction = frame['normalized']
    except KeyError:
      #print("KeyError while indexing function.");
      dataStack[frameIndex]['frame'] = "(missing function)"
      hashData += "(missing function)"
      continue
    except TypeError:
      print("TypeError while indexing function.");
      dataStack[frameIndex]['frame'] = "(missing function)"
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

    try:
      module = frame['module']
    except:
      pass

    srcUrl = generateSourceLink(frame)

    dataStack[frameIndex]['srcUrl'] = srcUrl 
    dataStack[frameIndex]['frame'] = functionCall
    dataStack[frameIndex]['module'] = module

    if skipFrame is False:
      hashData += functionCall

  #if ReportType == 0:
  #elif ReportType == 1:
  #else:
  #  raise Exception('Undefined ReportType!')

  # Append any crash meta data to our hashData so it applies to uniqueness.
  # Any variance in this data will cause this signature to be broken out as
  # a separate signature in the final top crash list.
  hashData += operatingSystem
  hashData += operatingSystemVer
  hashData += arch
  # The redash queries we are currently using target specific versions, so this
  # doesn't have much of an impact except on beta, where we want to see the effect
  # of beta fixes that get uplifted.
  hashData += firefoxVer

  hash = hashlib.md5(hashData.encode('utf-8')).hexdigest()
  return hash, dataStack

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

def getDatasetStats(reports):
  sigCount = len(reports)
  reportCount = 0
  for sig in reports:
    reportCount += len(reports[sig]['reportList'])
  return sigCount, reportCount

# Cache the reports database to a local json file. Speeds
# up symbolication runs across days by avoid re-symbolicating
# reports.
def cacheReports(reports):
  file = ("%s.json" % dbFilename)
  with open(file, "w") as database:
      database.write(json.dumps(reports))
  sigCount, reportCount = getDatasetStats(reports)
  print("Cache database stats: %d signatures, %d reports." % (sigCount, reportCount))

# Load the local report database
def loadReports():
  file = ("%s.json" % dbFilename)
  reports = dict()
  try:
    with open(file) as database:
      reports = json.load(database)
  except FileNotFoundError:
    return dict()
  sigCount, reportCount = getDatasetStats(reports)
  print("Existing database stats: %d signatures, %d reports." % (sigCount, reportCount))
  return reports

def loadAnnotations(filename):
  file = "%s_annotations.json" % filename
  try:
    with open(file) as database:
      annotations = json.load(database)
  except FileNotFoundError:
    return dict()
  return annotations

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

def extractTemplate(token, srcTemplate):
  # This returns the inner template from srcTemplate, minus any
  # identifying tag data.

  # token would be something like 'signature' used
  # in identifying tags like:
  # <!-- start of signature template -->
  # <!-- end of signature template -->
  start = '<!-- start of ' + token + ' template -->'
  end = '<!-- end of ' + token + ' template -->'
  sIndex = srcTemplate.index(start)
  eIndex = srcTemplate.index(end)
  if sIndex == -1 or eIndex == -1:
    raise Exception("Bad HTML template tokens!") 
  template = srcTemplate[sIndex + len(start) : eIndex + len(end)]
  return template

def extractAndTokenizeTemplate(token, srcTemplate, insertToken):
  # This returns the inner template from srcTemplate, minus any
  # identifying tag data, and we also return srcTemplate with
  # $insertToken replacing the block we clipped out.

  start = '<!-- start of ' + token + ' template -->'
  end = '<!-- end of ' + token + ' template -->'
  sIndex = srcTemplate.index(start)
  eIndex = srcTemplate.index(end)
  if sIndex == -1 or eIndex == -1:
    raise Exception("Bad HTML template tokens!") 
  header = srcTemplate[0:sIndex]
  footer = srcTemplate[eIndex + len(end):]
  template = srcTemplate[sIndex + len(start) : eIndex]
  return template, (header + '$' + insertToken + footer)

def dumpTemplates():
  print('mainPage -----')
  print(mainPage)
  print('outerSigTemplate-----')
  print(outerSigTemplate)
  print('outerSigMetaTemplate-----')
  print(outerSigMetaTemplate)
  print('outerReportTemplate-----')
  print(outerReportTemplate)
  print('outerStackTemplate-----')
  print(outerStackTemplate)
  print('innerStackTemplate-----')
  print(innerStackTemplate)
  exit()

# return true if we should skip processing this signature
def processSignature(signature):
  if len(signature) == 0:
    return True
  elif signature == 'EMPTY: no crashing thread identified':
    return True
  elif signature == 'EMPTY: no frame data available':
    return True
  elif signature == "<T>":
    print("sig <T>")
    return True

  return False

def generateTopReports(reports):
  # For certain types of reasons like RustMozCrash, organize
  # the most common for a report list. Otherwise just dump the
  # first MaxReportCount.
  reasonCounter = Counter()
  for report in reports:
    crashReason = report['crashreason']
    reasonCounter[crashReason] += 1
  reportCol = reasonCounter.most_common(MaxReportCount)
  if len(reportCol) < MaxReportCount:
    return reports
  colCount = len(reportCol)
  maxReasonCount = int(math.ceil(MaxReportCount / colCount))
  reportList = list()
  count = 0
  for reason, count in reportCol:
    for report in reports:
      if report['crashreason'] == reason:
         reportList.append(report)
         count += 1
         if count > maxReasonCount:
           break # next reason
  return reportList

###########################################################
# Process crashes and stacks
###########################################################

queryId = ''
userKey = ''
parameters = dict()

options, remainder = getopt.getopt(sys.argv[1:], 'u:n:d:c:k:q:p:t:')
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
  elif o == '-c':
    CrashProcessMax = int(a)
  elif o == '-q':
    queryId = a
    print("query id: %s" %  queryId)
  elif o == '-k':
    userKey = a
    print("user key: %s" %  userKey)
  elif o == '-t':
    repType = '?'
    if a == 'media':
      ReportType = 1
      repType = 'Media'
    else:
      ReportType = 0
      repType = 'Graphics'
    print("analysis type: %s" %  repType)
  elif o == '-p':
    param = a.split('=')
    parameters[param[0]] = param[1]

if len(userKey) == 0:
  print("missing user api key.")
  exit()
elif len(queryId) == 0:
  print("missing query id.")
  exit()

parameters['crashcount'] = str(CrashProcessMax)
channel = parameters['channel']
fxVersion = parameters['version']
processType = parameters['process_type']

print("processing %d reports" % CrashProcessMax)

props = list()
reports = dict()

totalCrashesProcessed = 0

# load up our database of processed crash ids
reports = loadReports()

if LoadLocally:
  with open(LocalJsonFile) as f:
    dataset = json.load(f)
else:
  with Spinner("loading from redash..."):
    dataset = getchRedashQueryResult(jsonUrl, queryId, userKey, parameters)
  print()
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
  drvVer = recrow['driver_version']
  drvDate = recrow['driver_date']
  clientId = recrow['client_id']
  devDesc = recrow['device_description']

  # Load the json crash payload from recrow
  props = json.loads(recrow["payload"])

  # touch up for the crash symbolication package
  props['stackTraces'] = props['stack_traces']

  crashId = props['crash_id']
  crashDate = props['crash_date']
  minidumpHash = props['minidump_sha256_hash']
  crashReason = props['metadata']['moz_crash_reason']
  crashInfo = props['stack_traces']['crash_info']

  startupCrash = 0
  try:
    startupCrash = int(props['metadata']['startup_crash'])
  except:
    pass

  if crashReason != None:
    crashReason = crashReason.strip('\n')

  # Ignore crashes older than 7 days
  if not checkCrashAge(crashDate):
    totalCrashesProcessed += 1
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
        # report['minidumphash'] = minidumpHash
        # report['driverversion'] = drvVer
        # report['driverdate'] = drvDate
        # report['devdescription'] = devDesc
        # report['crashreason'] = crashReason
        report['compositor'] = compositor
        report['startup'] = startupCrash
        break

  # purge old signatures of the crash reason - remove me
  if crashReason != None:
    index = signature.find(crashReason)
    if index != -1:
      found = False
  if found:
    totalCrashesProcessed += 1
    progress(totalCrashesProcessed, crashesToProcess)
    continue
  
  # symbolicate and return payload result
  payload = symbolicate(props)
  signature = generateSignature(payload)

  if processSignature(signature):
    totalCrashesProcessed += 1
    continue

  if crashReason != None:
    oldSignature = signature + " - " + crashReason
    if oldSignature in reports.keys():
      report = reports[oldSignature]
      del reports[oldSignature]
      reports[signature] = report
      print()
      print("replaced: '" + oldSignature + "' with '" + signature + "'")


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
    reports[signature]['arch'] = arch
    reports[signature]['os_version'] = operatingSystemVer
    reports[signature]['firefoxVer'] = firefoxVer

  # create our report with per crash meta data
  report = {
    'clientid': clientId,
    'crashid': crashId,
    'crashdate': crashDate,
    'compositor': compositor,
    'stack': stack,
    'oom_size': oom_size,
    'type': crashInfo['type'],
    'devvendor': devVendor,
    'devgen': devGen,
    'devchipset': devChipset,
    'devdevice': devDevice,
    'devdescription': devDesc,
    'driverversion' : drvVer,
    'driverdate': drvDate,
    'minidumphash': minidumpHash,
    'crashreason': crashReason,
    'startup': startupCrash
  }

  # save this crash in our report list
  reports[signature]['reportList'].append(report)

  totalCrashesProcessed += 1

  progress(totalCrashesProcessed, crashesToProcess)

print('\n')

if totalCrashesProcessed == 0:
  print('No reports processed.')
  exit()

###########################################################
# Post processing steps
###########################################################

# Purge signatures that are outdated
purgeOldReports(reports)

# calculate unique client id counts for each signature
clientCounts = dict()
needsUpdate = False
for sig in reports:
  # maintenence, we moved compositor into individual reports - remove me
  try:
    del reports[sig]['compositor']
  except KeyError:
    pass
  clientCounts[sig] = list()
  for report in reports[sig]['reportList']:
    try:
      test = report['devdescription']
      test = report['compositor']
      test = report['startup']
    except:
      # purge records when we update the local db
      report['crashdate'] = "2020-01-01"
      needsUpdate = True
      continue
    clientId = report['clientid']
    if clientId not in clientCounts[sig]:
      clientCounts[sig].append(clientId)
  reports[sig]['clientcount'] = len(clientCounts[sig])

if needsUpdate:
  purgeOldReports(reports)

# generate a top crash list
sigCounter = Counter()
for sig in reports:
  sigCounter[sig] = len(reports[sig]['reportList'])


###########################################################
### HTML generation
###########################################################

templateFile = open("template.html", "r")
template = templateFile.read()
templateFile.close()

# <!-- start of crash template -->
# <!-- end of crash template -->
innerTemplate, mainPage = extractAndTokenizeTemplate('crash', template, 'main')

# <!-- start of signature template -->
# <!-- end of signature template -->
innerSigTemplate, outerSigTemplate = extractAndTokenizeTemplate('signature', innerTemplate, 'signature')

# Main inner block
# <!-- start of signature meta template -->
# <!-- end of signature meta template -->
innerSigMetaTemplate, outerSigMetaTemplate = extractAndTokenizeTemplate('signature meta', innerSigTemplate, 'reports')

# Report meta plus stack info
# <!-- start of report template -->
# <!-- end of report template -->
innerReportTemplate, outerReportTemplate = extractAndTokenizeTemplate('report', innerSigMetaTemplate, 'report')

# <!-- start of stackline template -->
# <!-- end of stackline template -->
innerStackTemplate, outerStackTemplate = extractAndTokenizeTemplate('stackline', innerReportTemplate, 'stackline')

outerStackTemplate = outerStackTemplate.strip()
innerStackTemplate = innerStackTemplate.strip()
outerReportTemplate = outerReportTemplate.strip()
outerSigMetaTemplate = outerSigMetaTemplate.strip()
outerSigTemplate = outerSigTemplate.strip()

#annDB = loadAnnotations(dbFilename)

#resultFile = open(("%s.html" % outputFilename), "w", encoding="utf-8")
resultFile = open(("%s.html" % outputFilename), "w", errors="replace")

signatureHtml = str()
sigMetaHtml = str()
signatureIndex = 0

sigCount, reportCount = getDatasetStats(reports)
collection = sigCounter.most_common(MostCommonLength)

for sig, crashcount in collection:
  try:
    sigRecord = reports[sig]
  except KeyError:
    continue

  crashcount = len(sigRecord['reportList'])
  percent = (crashcount / totalCrashesProcessed)*100.0

  if crashcount < MinCrashCount: # Skip small crash count reports
    continue

  signatureIndex += 1

  crashStatsHashQuery = 'https://crash-stats.mozilla.org/search/?'
  crashStatsQuery = 'https://crash-stats.mozilla.org/search/?signature=~%s&product=Firefox&_facets=signature&process_type=%s' % (sig, processType)

  # sort based on common reasons
  reportsToReport = generateTopReports(reports[sig]['reportList'])

  reportHtml = str()
  idx = 0
  hashTotal= 0
  for report in reportsToReport:
    idx = idx + 1
    if idx > MaxReportCount:
      break
    oombytes = report['oom_size'] if not None else '0'

    crashReason = report['crashreason']
    if (crashReason == None):
      crashReason = ''

    crashType = report['type']
    crashType = crashType.lstrip('EXCEPTION_')

    appendAmp = False
    try:
      crashStatsHashQuery += 'minidump_sha256_hash=~' + report['minidumphash']
      hashTotal += 1
      appendAmp = True
    except:
      pass

    # Redash meta data dump for a particular crash id
    infoLink = 'https://sql.telemetry.mozilla.org/queries/79462?p_channel=%s&p_process_type=%s&p_version=%s&p_crash_id=%s' % (channel, processType, fxVersion, report['crashid'])

    startupStyle = 'noicon'
    if report['startup'] != 0:
      startupStyle = 'icon'

    stackHtml = str()
    for frameData in report['stack']:
      # [idx] = { 'index': n, 'frame': '(frame)', 'srcUrl': '(url)', 'module': '(module)' }
      frameIndex = frameData['index']
      frame = frameData['frame']
      srcUrl = frameData['srcUrl']
      moduleName = frameData['module']

      linkStyle = 'inline-block'
      srcLink = srcUrl
      if len(srcUrl) == 0:
        linkStyle = 'none'
        srcLink = ''

      stackHtml += Template(innerStackTemplate).substitute(frameindex=frameIndex,
                                                            frame=escape(frame),
                                                            srcurl=srcLink,
                                                            module=moduleName,
                                                            style=linkStyle)

    reportHtml += Template(outerStackTemplate).substitute(expandostack=('st'+str(signatureIndex)+'-'+str(idx)),
                                                          rindex=idx,
                                                          type=crashType,
                                                          oomsize=oombytes,
                                                          devvendor=report['devvendor'],
                                                          devgen=report['devgen'],
                                                          devchipset=report['devchipset'],
                                                          description=report['devdescription'],
                                                          drvver=report['driverversion'],
                                                          drvdate=report['driverdate'],
                                                          compositor=report['compositor'],
                                                          reason=crashReason,
                                                          infolink=infoLink,
                                                          startupiconclass=startupStyle,
                                                          stackline=stackHtml)
    if appendAmp:
      crashStatsHashQuery += '&'

  sigHtml = Template(outerReportTemplate).substitute(expandosig=('sig'+str(signatureIndex)),
                                                     os=sigRecord['opoerating_system'],
                                                     fxver=sigRecord['firefoxVer'],
                                                     osver=sigRecord['os_version'],
                                                     arch=sigRecord['arch'],
                                                     report=reportHtml)

  crashStatsHashQuery = crashStatsHashQuery.rstrip('&')

  searchIconClass = 'icon'
  if hashTotal == 0:
    crashStatsHashQuery = ''
    searchIconClass = 'lticon'

  sigMetaHtml += Template(outerSigMetaTemplate).substitute(rank=signatureIndex,
                                                           percent=("%.00f%%" % percent),
                                                           expandosig=('sig'+str(signatureIndex)),
                                                           signature=(html.escape(sig)),
                                                           iconclass=searchIconClass,
                                                           cslink=crashStatsHashQuery,
                                                           cssearchlink=crashStatsQuery,
                                                           clientcount=sigRecord['clientcount'],
                                                           count=crashcount,
                                                           reports=sigHtml)

signatureHtml += Template(outerSigTemplate).substitute(channel=channel,
                                                       version=fxVersion,
                                                       process=processType,
                                                       sigcount=sigCount,
                                                       repcount=reportCount,
                                                       signature=sigMetaHtml)

# Add processed date to the footer
dateTime = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
resultFile.write(Template(mainPage).substitute(main=signatureHtml,
                                               processeddate=dateTime))
resultFile.close()

# Caching of reports
cacheReports(reports)