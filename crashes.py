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
import string
import pygal

from string import Template
from collections import Counter
from urllib.request import urlopen
from urllib import request
from datetime import datetime, timedelta, date

# python -m pip install SomePackage
# python.exe -m pip install --upgrade SomePackage
# python.exe -m pip install --upgrade fx_crash_sig
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
# -c (value)    : redash cache value in minutes (0 is the default)
# -n (name)     : local json cache filename to use (excluding extension)
# -d (name)     : local html output filename to use (excluding extension)
# -c (count)    : number of reports to process, overrides the default
# -p (k=v)      : k=v redash query parameters to pass to the query request.
# -z            : debugging: load and dump the first few records of the local databases. requires -d.
# -s (sig)      : search for a token in reports
# python crashes.py -n nightly -d nightly -u https://sql.telemetry.mozilla.org -k (userapikey) -q 79354 -p process_type=gpu -p version=89 -p channel=nightly

## TODO
## stats statistics when loaded or written
## report struct may not need to os, osver, and arch info anymore since we added stats
## signatures that went away feature
## annotation signature keywords
## click handler should ignore clicks if there's selection in the page
## popup panel layout (Fixed By and Notes) is confusing, and wide when it doesn't need to be.
## Remove reliance on version numbers? Need to get signature headers hooked up, and choose the latest releases for main reports
## build id (nightly / beta)
## linux distro information someplace
## clean up the startup crash icons
## better annotations support
## add dates to annotations

## improve signature header information layout, particular fx version numbers. We can easily expand this down and host info similar to crash stats summary pages.
##  - filter graphing and the list based on clicks on the header data (version, os, arch)

# python crashes.py -n beta -d beta -u https://sql.telemetry.mozilla.org -k nc2gV50AtsZHUpfmPwtR0F9ysiD8SateThgXUEba -q 79354 -p process_type=gpu -p version=90 -p channel=beta -s "draw_quad_spans<T>"

###########################################################
# Globals
###########################################################

# The default symbolication server to use.
SymbolServerUrl = "https://symbolication.services.mozilla.com/symbolicate/v5"
# Max stack depth for symbolication
MaxStackDepth = 50
# Maximum number of raw crashes to process. This matches
# the limit value of re:dash queries. Reduce for testing
# purposes.
CrashProcessMax = 7500
# Signature list length of the resulting top crashes report
MostCommonLength = 50
# When generating a report, signatures with crash counts
# lower than this value will not be included in the report.
MinCrashCount = 1
# When generating a report, signatures with client counts
# lower than this value will not be included in the report.
ReportLowerClientLimit = 2 # filter out single client crashes
# Maximum number of crash reports to include for each signature
# in the final report. Limits the size of the resulting html.
MaxReportCount = 100
# Default redash max_age value in minutes
MaxAge = 43200
# Set to True to target a local json file for testing
LoadLocally = False
LocalJsonFile = "GPU_Raw_Crash_Data_2021_03_19.json"
# Default json file url if not specified via the command line.
jsonUrl = "https://sql.telemetry.mozilla.org/api/queries/78997/results.json?api_key=0XTUThlCYJLBQaKsc8cR4296Y6fasm8vezkZSNPg"

proc = CrashProcessor(MaxStackDepth, SymbolServerUrl)
pp = pprint.PrettyPrinter(indent=1, width=260)

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

###########################################################
# Progress indicator
###########################################################

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

###########################################################
# Redash queries
###########################################################

def getRedashQueryResult(redash_url, query_id, api_key, cacheValue, params):
  s = requests.Session()
  s.headers.update({'Authorization': 'Key {}'.format(api_key)})

  # max_age is a redash value that controls cached results. If there is a cached query result
  # newer than this time (in seconds) it will be returned instead of a fresh query.
  # 86400 = 24 hours, 43200 = 12 hours, 0 = refresh query 
  #
  # Note sometimes the redash caching feature gets 'stuck' on an old cache. Side effect is
  # that all reports will eventually be older than 7 days and as such will be filtered out
  # by this script's age checks in processRedashDataset. Crash lists will shrink to zero
  # as a result.
  payload = dict(max_age=cacheValue, parameters=params)

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

###########################################################
# HTML and Text Formatting Utilities
###########################################################

def escapeBugLinks(text):
  # convert bug references to links
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1323439
  pattern = "bug ([0-9]*)"
  replacement = "<a href='https://bugzilla.mozilla.org/show_bug.cgi?id=\\1'>Bug \\1</a>"
  result = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
  return result

def createBugLink(id):
  # convert bug references to links
  return "<a href='https://bugzilla.mozilla.org/show_bug.cgi?id=" + str(id) + "'>bug " + str(id) + "</a>"

safe = string.ascii_letters + string.digits + '_-.'

def stripWhitespace(text):
  text = text.strip(' \t\n')
  return text

def stringToHtmlId(s):
    s = ''.join([letter for letter in s if letter in safe])
    return s

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

def escape(text):
  return html.escape(text)

###########################################################
# Crash Report Utilities
###########################################################

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

  dataStack = list() # [idx] = { 'frame': '(frame)', 'srcUrl': '(url)' }

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
    module = 'unknown'
    offset = 'unknown'

    try:
      offset = frame['module_offset']
    except:
      pass
    try:
      module = frame['module']
    except:
      pass


    try:
      functionCall = frame['function']
    except KeyError:
      dataStack[frameIndex]['frame'] = offset
      dataStack[frameIndex]['module'] = module
      continue
    except TypeError:
      print("TypeError while indexing function.");
      dataStack[frameIndex]['frame'] = "(missing function)"
      continue

    for k, v in coelesceFrameDict.items():
      functionCall = re.sub(v, k, functionCall, 1)
      break

    for v in coelesceFunctionList:
      if re.search(v, functionCall) != None:
        normalizedFunction = functionCall
        try:
          normalizedFunction = frame['normalized']
        except KeyError:
          pass
        except TypeError:
          pass
        functionCall = normalizedFunction
        break

    srcUrl = generateSourceLink(frame)

    dataStack[frameIndex]['srcUrl'] = srcUrl
    dataStack[frameIndex]['frame'] = functionCall
    dataStack[frameIndex]['module'] = module

  return dataStack

def generateSignatureHash(signature, os, osVer, arch, fxVer):
  hashData = signature

  # Append any crash meta data to our hashData so it applies to uniqueness.
  # Any variance in this data will cause this signature to be broken out as
  # a separate signature in the final top crash list.
  #hashData += os
  #hashData += osVer
  #hashData += arch

  # The redash queries we are currently using target specific versions, so this
  # doesn't have much of an impact except on beta, where we want to see the effect
  # of beta fixes that get uplifted.
  #hashData += fxVer

  return hashlib.md5(hashData.encode('utf-8')).hexdigest()

###########################################################
# Reports data structure utilities
###########################################################

def getDatasetStats(reports):
  sigCount = len(reports)
  reportCount = 0
  for hash in reports:
    reportCount += len(reports[hash]['reportList'])
  return sigCount, reportCount

def processRedashDataset(dbFilename, jsonUrl, queryId, userKey, cacheValue, parameters):
  props = list()
  reports = dict()

  totals = {
    'processed': 0,
    'skippedBadSig': 0,
    'alreadyProcessed': 0,
    'outdated': 0
  }
  
  # load up our database of processed crash ids
  # returns an empty dict() if no data is loaded.
  reports, stats = loadReports(dbFilename)

  if LoadLocally:
    with open(LocalJsonFile) as f:
      dataset = json.load(f)
  else:
    with Spinner("loading from redash..."):
      dataset = getRedashQueryResult(jsonUrl, queryId, userKey, cacheValue, parameters)
    print("   done.")

  crashesToProcess = len(dataset["query_result"]["data"]["rows"])
  if  crashesToProcess > CrashProcessMax:
    crashesToProcess = CrashProcessMax

  print('%04d total reports loaded.' % crashesToProcess)

  for recrow in dataset["query_result"]["data"]["rows"]:
    if totals['processed'] >= CrashProcessMax:
      break

    # pull some redash props out of the recrow. You can add these
    # by modifying the sql query.
    operatingSystem = recrow['normalized_os']
    operatingSystemVer = recrow['normalized_os_version']
    firefoxVer = recrow['display_version']
    buildId = recrow['build_id']
    compositor = recrow['compositor']
    arch = recrow['arch']
    oomSize = recrow['oom_size']
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

    startupCrash = int(recrow['startup_crash'])
    fissionEnabled = int(recrow['fission_enabled'])

    lockdownVal = int(recrow['lockdown_enabled'])
    lockdownEnabled = False
    if lockdownVal == 1:
      lockdownEnabled = True

    if crashReason != None:
      crashReason = crashReason.strip('\n')

    # Ignore crashes older than 7 days
    if not checkCrashAge(crashDate):
      totals['processed'] += 1
      totals['outdated'] += 1
      progress(totals['processed'], crashesToProcess)
      continue

    # check if the crash id is processed, if so continue
    ## note, this search has become quite slow. optimize me.
    found = False
    signature = ""
    for sighash in reports: # reports is a dictionary of signature hashes
      for report in reports[sighash]['reportList']: # reportList is a list of dictionaries 
        if report['crashid'] == crashId: # string compare, slow
          found = True
          # if you add a new value to the sql queries, you can update
          # the local json cache we have in memory here. Saves having
          # to delete the file and symbolicate everything again.
          #report['fission'] = fissionEnabled
          #report['lockdown'] = lockdownEnabled
          break

    if found:
      totals['processed'] += 1
      totals['alreadyProcessed'] += 1
      progress(totals['processed'], crashesToProcess)
      continue
  
    # symbolicate and return payload result
    payload = symbolicate(props)
    signature = generateSignature(payload)

    if skipProcessSignature(signature):
      totals['processed'] += 1
      totals['skippedBadSig'] += 1
      progress(totals['processed'], crashesToProcess)
      continue

    # pull stack information for the crashing thread
    try:
      crashingThreadIndex = payload['crashing_thread']
    except KeyError:
      #print("KeyError on crashing_thread for report");
      continue

    threads = payload['threads']
    
    try:
      frames = threads[crashingThreadIndex]['frames']
    except IndexError:
      print("IndexError while indexing crashing thread");
      continue
    except TypeError:
      print("TypeError while indexing crashing thread");
      continue

    # build up a pretty stack
    stack = processStack(frames)

    # generate a tracking hash 
    hash = generateSignatureHash(signature, operatingSystem, operatingSystemVer, arch, firefoxVer)

    if hash not in reports.keys():
      # Set up this signature's meta data we track in the signature header.
      reports[hash] = {
        'signature':          signature,
        'operatingsystem':    [operatingSystem],
        'osversion':          [operatingSystemVer],
        'firefoxver':         [firefoxVer],
        'arch':               [arch],
        'reportList':         list()
      }

    # Update meta data we track in the report header.
    if operatingSystem not in reports[hash]['operatingsystem']:
      reports[hash]['operatingsystem'].append(operatingSystem)
    if operatingSystemVer not in reports[hash]['osversion']:
      reports[hash]['osversion'].append(operatingSystemVer)
    if firefoxVer not in reports[hash]['firefoxver']:
      reports[hash]['firefoxver'].append(firefoxVer)
    if arch not in reports[hash]['arch']:
      reports[hash]['arch'].append(arch)

    # create our report with per crash meta data
    report = {
      'clientid':           clientId,
      'crashid':            crashId,
      'crashdate':          crashDate,
      'compositor':         compositor,
      'stack':              stack,
      'oomsize':            oomSize,
      'type':               crashInfo['type'],
      'devvendor':          devVendor,
      'devgen':             devGen,
      'devchipset':         devChipset,
      'devdevice':          devDevice,
      'devdescription':     devDesc,
      'driverversion' :     drvVer,
      'driverdate':         drvDate,
      'minidumphash':       minidumpHash,
      'crashreason':        crashReason,
      'startup':            startupCrash,
      'fission':            fissionEnabled,
      'lockdown':           lockdownEnabled,
      # Duplicated but useful if we decide to change the hashing algo
      # and need to reprocess reports.
      'operatingsystem':    operatingSystem,
      'osversion':          operatingSystemVer,
      'firefoxver':         firefoxVer,
      'arch':               arch
    }

    # save this crash in our report list
    reports[hash]['reportList'].append(report)
   
    if hash not in stats.keys():
      stats[hash] = {
        'signature': signature,
        'crashdata': {}
      }

    # check to see if stats has a date entry that matches crashDate
    if crashDate not in stats[hash]['crashdata']:
      stats[hash]['crashdata'][crashDate] = { 'crashids': [], 'clientids':[] }

    if operatingSystem not in stats[hash]['crashdata'][crashDate]:
      stats[hash]['crashdata'][crashDate][operatingSystem] = {}

    if operatingSystemVer not in stats[hash]['crashdata'][crashDate][operatingSystem]:
      stats[hash]['crashdata'][crashDate][operatingSystem][operatingSystemVer] = {}

    if arch not in stats[hash]['crashdata'][crashDate][operatingSystem][operatingSystemVer]:
      stats[hash]['crashdata'][crashDate][operatingSystem][operatingSystemVer][arch] = {}

    if firefoxVer not in stats[hash]['crashdata'][crashDate][operatingSystem][operatingSystemVer][arch]:
      stats[hash]['crashdata'][crashDate][operatingSystem][operatingSystemVer][arch][firefoxVer] = { 'clientcount': 0, 'crashcount': 0 }

    if crashId not in stats[hash]['crashdata'][crashDate]['crashids']:
      stats[hash]['crashdata'][crashDate]['crashids'].append(crashId)
      stats[hash]['crashdata'][crashDate][operatingSystem][operatingSystemVer][arch][firefoxVer]['crashcount'] += 1
      if clientId not in stats[hash]['crashdata'][crashDate]['clientids']:
        stats[hash]['crashdata'][crashDate][operatingSystem][operatingSystemVer][arch][firefoxVer]['clientcount'] += 1
        stats[hash]['crashdata'][crashDate]['clientids'].append(clientId)

    totals['processed'] += 1

    progress(totals['processed'], crashesToProcess)

  print('\n')
  print('%04d - reports processed' % totals['processed'])
  print('%04d - cached results' % totals['alreadyProcessed'])
  print('%04d - reports skipped, bad signature' % totals['skippedBadSig'])
  print('%04d - reports skipped, out dated' % totals['outdated'])

  if totals['processed'] == 0:
    exit()

  # Post processing steps

  # Purge signatures from our reports list that are outdated (based
  # on crash date and version). This keeps our crash lists current,
  # especially after a merge. Note this doesn't clear stats, just reports.
  queryFxVersion = parameters['version']
  purgeOldReports(reports, queryFxVersion)

  # purge old crash and client ids from the stats database.
  cleanupStats(reports, stats)

  # calculate unique client id counts for each signature. These are client counts
  # associated with the current redash query, and apply only to a seven day time
  # window. They are stored in the reports database and displayed in the top crash
  # reports. 
  clientCounts = dict()
  needsUpdate = False
  for hash in reports:
    clientCounts[hash] = list()
    for report in reports[hash]['reportList']:
      clientId = report['clientid']
      if clientId not in clientCounts[hash]:
        clientCounts[hash].append(clientId)
    reports[hash]['clientcount'] = len(clientCounts[hash])

  return reports, stats, totals['processed']

def checkCrashAge(dateStr):
  try:
    date = datetime.fromisoformat(dateStr)
  except:
    return False
  oldestDate = datetime.today() - timedelta(days=7)
  return (date >= oldestDate)

def getMainVer(version):
  return version.split('.')[0]

def purgeOldReports(reports, fxVersion):
  # Purge obsolete reports.
  # 89.0b7 89.0 90.0.1
  totalReportsDropped = 0
  for hash in reports:
    keepRepList = list()
    origRepLen = len(reports[hash]['reportList'])
    for report in reports[hash]['reportList']:
      reportVer = ''
      try:
        reportVer = getMainVer(report['firefoxver'])
      except:
        pass
      if fxVersion == reportVer:
        keepRepList.append(report)
    totalReportsDropped += (origRepLen - len(keepRepList))
    reports[hash]['reportList'] = keepRepList

  print("Removed %d older reports." % totalReportsDropped)

  # Purge signatures that have no reports
  delSigList = list()
  for hash in reports:
    newRepList = list()
    for report in reports[hash]['reportList']:
      # "crash_date":"2021-03-22"
      dateStr = report['crashdate']
      if checkCrashAge(dateStr):
        newRepList.append(report)
    reports[hash]['reportList'] = newRepList
    if len(newRepList) == 0:
      # add this signature to our purge list
      delSigList.append(hash)

  for hash in reports:
    if len(reports[hash]['reportList']) == 0:
      if hash not in delSigList:
        delSigList.append(hash)

  # purge old signatures that no longer have reports
  # associated with them.
  for hash in delSigList:
    del reports[hash]

  print("Removed %d older signatures from our reports database." % len(delSigList))

def cleanupStats(reports, stats):
  # remove old crash and client ids we no longer have reports for
  clientList = list()
  crashList = list()
  for hash in reports:
    for report in reports[hash]['reportList']:
      clientid = report['clientid']
      crashid = report['crashid']
      if clientid not in clientList:
        clientList.append(clientid)
      if crashid not in crashList:
        crashList.append(crashid)

  purgeClientIdList = list()
  purgeCrashIdList = list()

  for hash in stats:
    for date in stats[hash]['crashdata'].keys():
      for crashid in stats[hash]['crashdata'][date]['crashids']:
        if crashid not in crashList:
          if crashid not in purgeCrashIdList:
            purgeCrashIdList.append(crashid)
      for clientid in stats[hash]['crashdata'][date]['clientids']:
        if clientid not in clientList:
          if clientid not in purgeClientIdList:
            purgeClientIdList.append(clientid)

  for crashid in purgeCrashIdList:
    for hash in stats:
      for date in stats[hash]['crashdata'].keys():
          if crashid in stats[hash]['crashdata'][date]['crashids']:
            stats[hash]['crashdata'][date]['crashids'].remove(crashid)


  for clientid in purgeClientIdList:
    for hash in stats:
      for date in stats[hash]['crashdata'].keys():
          if clientid in stats[hash]['crashdata'][date]['clientids']:
            stats[hash]['crashdata'][date]['clientids'].remove(clientid)
  
  print("Removed %d old client ids and %d old crash ids tracked in stats." % (len(purgeClientIdList), len(purgeCrashIdList)))

  return True

# return true if we should skip processing this signature
def skipProcessSignature(signature):
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

def isFissionRelated(reports):
  isFission = True
  for report in reports:
    try:
      if report['fission'] == 0:
        isFission = False
    except:
      pass
  return isFission

def isLockdownRelated(reports):
  isLockdown = True
  for report in reports:
    try:
      if report['lockdown'] == 0:
        isLockdown = False
    except:
      pass
  return isLockdown

def generateTopReportsList(reports):
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

def dumpDatabase(reports, annoFilename):
  print("= Reports =======================================================================================")
  pp.pprint(reports)
  print("= Annotations ===================================================================================")
  reports = loadAnnotations(annoFilename)
  pp.pprint(reports)

def doMaintenance(dbFilename):
  exit()
  # load up our database of processed crash ids
  reports, stats = loadReports(dbFilename)

  for hash in reports:
    signature = reports[hash]['signature']
    clientcount = reports[hash]['clientcount']

    operatingSystem = reports[hash]['operatingsystem']
    del reports[hash]['operatingsystem']
    reports[hash]['operatingsystem'] = [operatingSystem]

    operatingSystemVer = reports[hash]['osversion']
    del reports[hash]['osversion']
    reports[hash]['osversion'] = [operatingSystemVer]

    firefoxVer = reports[hash]['firefoxver']
    del reports[hash]['firefoxver']
    reports[hash]['firefoxver'] = [firefoxVer]

    arch = reports[hash]['arch']
    del reports[hash]['arch']
    reports[hash]['arch'] = [arch]

  #dumpDatabase(reports)

  # Caching of reports
  #cacheReports(reports, stats, dbFilename)

###########################################################
# File utilities
###########################################################

# Load the local report database
def loadReports(dbFilename):
  reportsFile = ("%s-reports.json" % dbFilename)
  statsFile = ("%s-stats.json" % dbFilename)
  reports = dict()
  stats = dict()
  try:
    with open(reportsFile) as database:
      reports = json.load(database)
  except FileNotFoundError:
    pass
  try:
    with open(statsFile) as database:
      stats = json.load(database)
  except FileNotFoundError:
    pass
  sigCount, reportCount = getDatasetStats(reports)
  print("Existing database stats: %d signatures, %d reports." % (sigCount, reportCount))
  return reports, stats

# Cache the reports database to a local json file. Speeds
# up symbolication runs across days by avoid re-symbolicating
# reports.
def cacheReports(reports, stats, dbFilename):
  reportsFile = ("%s-reports.json" % dbFilename)
  statsFile = ("%s-stats.json" % dbFilename)
  with open(reportsFile, "w") as database:
      database.write(json.dumps(reports))
  with open(statsFile, "w") as database:
      database.write(json.dumps(stats))
  sigCount, reportCount = getDatasetStats(reports)
  print("Cache database stats: %d signatures, %d reports." % (sigCount, reportCount))

def loadAnnotations(filename):
  file = "%s.json" % filename
  try:
    with open(file) as database:
      annotations = json.load(database)
      print("Loading %s annotations file." % file)
  except FileNotFoundError:
    print("Could not find %s file." % file)
    return dict()
  except json.decoder.JSONDecodeError:
    print("Json error parsing %s" % file)
    return dict()
  return annotations

###########################################################
# HTML Template Utilities
###########################################################

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

###########################################################
### Report generation
###########################################################

def generateSignatureReport(signature):
  reports, stats = loadReports()
  reports = reports[sig]
  if len(reports) == 0:
    print("signature not found in database.")
    exit()

  #for report in reports:
  exit()
    
def generateSparklineJS(sigStats, operatingSystems, operatingSystemVers, firefoxVers, archs, className):
  # generate stats data for crash rate over time graphs
  #   data = [ {name: "Bitcoin", date: "2017-01-01", value: 967.6}, ]
  #"Windows": {
  #  "6.1": {
  #    "x86": {
  #      "91.0a1": {
  #        "clientcount": 1,
  #        "crashcount": 3
  #      }
  #    }
  #  }
  #}

  rawData = dict()
  for dateStr in sigStats['crashdata']:
    for os in operatingSystems:
      for osver in operatingSystemVers:
        for arch in archs:
          for fxver in firefoxVers:
            try:
              stats = sigStats['crashdata'][dateStr][os][osver][arch][fxver]
              rawData[dateStr] = { 'os': os, 'crashcount': stats['crashcount'] }
            except:
              pass # some dates may not apply to a particular combination

  # average data for each os to smooth out the graph
  # {name: "Windows", date: "2021-06-24", value: 84}

  # generate a list of dates
  avgData = dict()
  dates = list(rawData.keys())
  dates.sort()

  # generate an os list [not used]
  osList = list()
  for targetDate in dates:
    os = rawData[targetDate]['os']
    if os not in osList:
      osList.append(os)

  # generate plot data
  plotData = '['
  template = '{name: "$name", date: "$date", value: $value},'

  for targetDate in dates:
    pd = date.fromisoformat(targetDate)
    minDate = pd - timedelta(3)
    maxDate = pd + timedelta(4)
    crashCount = 0
    dataPoints = 0

    for tmpDateStr in dates:
      tmpDate = date.fromisoformat(tmpDateStr)
      if tmpDate >= minDate and tmpDate <= maxDate:
        crashCount += rawData[pd.isoformat()]['crashcount']
        dataPoints += 1

    if dataPoints == 0:
      avgData[targetDate] = 0
    else:
      avgData[targetDate] = crashCount / dataPoints

    #print("date:%s cc=%d dp=%d avg=%f" % (targetDate, crashCount, dataPoints, avgData[targetDate]))
    plotData += Template(template).substitute(name='All', date=targetDate, value=avgData[targetDate])

  plotData += ']'
  #print(plotData)
  template = 'sparkline(document.querySelector("$cname"), $data, sloptions);' ## sloptions defined in template.html
  return Template(template).substitute(data=plotData, cname='.' + className)

# from list of strings, return a comma separated pretty list
def getItemizedHeaderList(theList):
  result = ''
  sl = theList.sort()
  for s in theList:
    result += s + ', '
  return result.strip(' ,')

# currently not in use
def versionListIsExclusiveTo(version, vList):
  # 92.0b6
  # 92.0.1
  # 92.0
  # 94.0a1
  found = False
  for v in vList:
    majorVersionNumber = v.split('.')[0]
    if version == majorVersionNumber:
      found = True

  for v in vList:
    majorVersionNumber = v.split('.')[0]
    if version != majorVersionNumber:
      found = False
  return found

def getFxVersionsFromStatsRec(statsCrashData):
  result = list()
  for date in statsCrashData.values():
    for opsys in date.values():
      if (isinstance(opsys, dict)):
        for osver in opsys.values():
          for arch in osver.values():
            for ver in arch.keys():
              if ver not in result:
                result.append(ver)
  result.sort()
  return result

def getPlatformDataFromStatsRec(statsCrashData):
  osresult = list()
  verresult = list()
  archresult = list()
  for date in statsCrashData.values():
    # accumulate operating system type
    for opsys in date.keys():
      if opsys in ['Windows', 'Linux', 'Mac']: # filter out lists clientids and crashids
        if opsys not in osresult:
          osresult.append(opsys)
        osdict = date[opsys]
        # accumulate os version values
        for osver in osdict.keys():
          if osver not in verresult:
            verresult.append(osver)
          # accumulate arch values
          osverdict = osdict[osver]
          for arch in osverdict.keys():
            if arch not in archresult:
              archresult.append(arch)

  osresult.sort()
  verresult.sort()
  archresult.sort()
  return osresult, verresult, archresult

def getSimpVerList(verList):
  result = list()
  for ver in verList:
    simp = ver.split('.', 1)[0]
    if simp not in result:
      result.append(simp)
  return result

def testIfNewCrash(statsCrashData, version):
  verList = getFxVersionsFromStatsRec(statsCrashData)
  simpList = getSimpVerList(verList)
  if version in simpList and len(simpList) == 1:
    return True
  return False

def prettyBetaVersions(verList):
  verList.sort()
  betaDict = dict()

  for s in verList:
    mver = s.split('.')[0]
    if mver not in betaDict.keys():
      betaDict[mver] = list()

    try:
      bver = s.split('b',1)[1]
    except:
      bver = 'rc' # RC's '94.0'

    betaDict[mver].append(bver)

  result = ''
  for ver in betaDict.keys():
    betaDict[ver].sort()
    result += ver + ' ['
    for beta in betaDict[ver]:
      result += beta + ','
    result = result.strip(',')
    result += '] '
  return result

def getCommaDelimitedList(theList):
  result = ''
  theList.sort()
  for s in theList:
    result += s + ', '
  return result.strip(' ,')

def getPrettyPlatformLists(statsCrashData):
  opsys, ver, arch = getPlatformDataFromStatsRec(statsCrashData)
  return getCommaDelimitedList(opsys), getCommaDelimitedList(ver), getCommaDelimitedList(arch)

def getPrettyFirefoxVersionList(statsCrashData, channel):
  verList = getFxVersionsFromStatsRec(statsCrashData)
  result = ''
  if channel == 'nightly':
    verList.sort()
    for s in verList:
      result += s.split('.')[0] + ', '
  elif channel == 'beta':
    result = prettyBetaVersions(verList)
  else:
    verList.sort()
    for s in verList:
      result += s + ', '

  return result.strip(' ,')

def generateTopCrashReport(reports, stats, totalCrashesProcessed, processType,
                           channel, queryFxVersion, outputFilename, annoFilename):

  templateFile = open("template.html", "r")
  template = templateFile.read()
  templateFile.close()

  # <!-- start of crash template -->
  # <!-- end of crash template -->
  innerTemplate, mainPage = extractAndTokenizeTemplate('crash', template, 'main')
  annotationTemplate, mainPage = extractAndTokenizeTemplate('annotation', mainPage, 'annotations')
  annotationReport, annotationTemplate = extractAndTokenizeTemplate('annotation report', annotationTemplate, 'annreports')

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

  outerStackTemplate = stripWhitespace(outerStackTemplate)
  innerStackTemplate = stripWhitespace(innerStackTemplate)
  outerReportTemplate = stripWhitespace(outerReportTemplate)
  outerSigMetaTemplate = stripWhitespace(outerSigMetaTemplate)
  outerSigTemplate = stripWhitespace(outerSigTemplate)
  annotationTemplate = stripWhitespace(annotationTemplate)
  annotationReport = stripWhitespace(annotationReport)
  # mainPage = stripWhitespace(mainPage) # mucks with js
  annDb = loadAnnotations(annoFilename)

  #resultFile = open(("%s.html" % outputFilename), "w", encoding="utf-8")
  resultFile = open(("%s.html" % outputFilename), "w", errors="replace")

  signatureHtml = str()
  sigMetaHtml = str()
  annotationsHtml = str()
  signatureIndex = 0

  sigCount, reportCount = getDatasetStats(reports)

  # generate a top crash list
  sigCounter = Counter()
  for hash in reports:
    if reports[hash]['clientcount'] < ReportLowerClientLimit:
      continue
    sigCounter[hash] = len(reports[hash]['reportList'])

  collection = sigCounter.most_common(MostCommonLength)
  
  sparklineJS = ''

  for hash, crashcount in collection:
    try:
      sigRecord = reports[hash] # reports data vs. stats
    except KeyError:
      continue

    signature = sigRecord['signature']
    statsCrashData = stats[hash]['crashdata']

    prettyOperatingSystems, prettyOperatingSystemVers, prettyArchs = getPrettyPlatformLists(statsCrashData)
    prettyFirefoxVers = getPrettyFirefoxVersionList(statsCrashData, channel)

    operatingSystemsList, operatingSystemVersList, archsList = getPlatformDataFromStatsRec(statsCrashData)
    firefoxVersList = getFxVersionsFromStatsRec(statsCrashData)

    crashcount = len(sigRecord['reportList'])
    percent = (crashcount / reportCount)*100.0

    if crashcount < MinCrashCount: # Skip small crash count reports
      continue

    isNewCrash = False
    newIcon = 'noicon'
    if testIfNewCrash(statsCrashData, queryFxVersion):
      isNewCrash = True
      newIcon = 'icon'

    signatureIndex += 1

    crashStatsHashQuery = 'https://crash-stats.mozilla.org/search/?'
    crashStatsQuery = 'https://crash-stats.mozilla.org/search/?signature=~%s&product=Firefox&_facets=signature&process_type=%s' % (signature, processType)

    # sort reports in this signature based on common crash reasons, so the most common
    # is at the top of the list.
    reportsToReport = generateTopReportsList(reports[hash]['reportList'])

    #fissionIcon = 'noicon'
    #if isFissionRelated(reports[hash]['reportList']):
    #  fissionIcon = 'icon'
    #if crashcount < 10 and fissionIcon == 'icon':
    #  fissionIcon = 'grayicon'

    lockdownIcon = 'noicon'
    if isLockdownRelated(reports[hash]['reportList']):
      lockdownIcon = 'icon'

    reportHtml = str()
    idx = 0
    hashTotal= 0
    oomIcon = 'noicon'
    for report in reportsToReport:
      idx = idx + 1
      if idx > MaxReportCount:
        break
      oombytes = report['oomsize']


      if report['oomsize'] is not None:
        oomIcon = 'icon'
      else:
        oombytes = ''

      crashReason = report['crashreason']
      if (crashReason == None):
        crashReason = ''

      crashType = report['type']
      crashType = crashType.replace('EXCEPTION_', '')

      appendAmp = False
      if hashTotal < 30: # This is all crash stats can hande (414 Request-URI Too Large)
        try:
          crashStatsHashQuery += 'minidump_sha256_hash=~' + report['minidumphash']
          hashTotal += 1
          appendAmp = True
        except:
          pass

      # Redash meta data dump for a particular crash id
      infoLink = 'https://sql.telemetry.mozilla.org/queries/79462?p_channel=%s&p_process_type=%s&p_version=%s&p_crash_id=%s' % (channel, processType, queryFxVersion, report['crashid'])

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

      compositor = report['compositor']
      if compositor == 'webrender_software_d3d11':
        compositor = 'd3d11'
      elif compositor == 'webrender':
        compositor = 'webrender'
      elif compositor == 'webrender_software':
        compositor = 'swiggle'
      elif compositor == 'none':
        compositor = ''

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
                                                            compositor=compositor,
                                                            reason=crashReason,
                                                            infolink=infoLink,
                                                            startupiconclass=startupStyle,
                                                            stackline=stackHtml)
      if appendAmp:
        crashStatsHashQuery += '&'

    # class="svg-$expandosig"
    sparklineJS += generateSparklineJS(stats[hash], operatingSystemsList, operatingSystemVersList, firefoxVersList, archsList, 'svg-'+stringToHtmlId(hash)) + '\n'

    # svg element
    sigHtml = Template(outerReportTemplate).substitute(expandosig=stringToHtmlId(hash),
                                                       os=prettyOperatingSystems,
                                                       fxver=prettyFirefoxVers,
                                                       osver=prettyOperatingSystemVers,
                                                       arch=prettyArchs,
                                                       report=reportHtml)

    crashStatsHashQuery = crashStatsHashQuery.rstrip('&')

    searchIconClass = 'icon'
    if hashTotal == 0:
      crashStatsHashQuery = ''
      searchIconClass = 'lticon'

    # ann$expandosig - view signature meta parameter
    annIconClass = 'lticon'
    if signature in annDb:
      record = annDb[signature]
      # record['annotations'] { date: 'date', 'annotation': 'notes' }
      sigAnnotations = str()
      # record['fixedby'] (list of tables, { date: 'date', 'version': 87, 'bug': 1234567 }
      for fb in record['fixedby']:
        sigAnnotations += Template(annotationReport).substitute(annotations=escape(fb['annotation']),
                                                                fixedbybug=createBugLink(str(fb['bug'])),
                                                                fixedbyversion=fb['version'])
      for annotation in record['annotations']:
        annotation = escape(annotation['annotation'])
        annotation = escapeBugLinks(annotation)
        sigAnnotations += Template(annotationReport).substitute(annotations=annotation, fixedbybug='', fixedbyversion='')
      annotationsHtml += Template(annotationTemplate).substitute(expandosig=('sig'+str(signatureIndex)),
                                                                 annreports=sigAnnotations)
      annIconClass = 'icon'

    sigMetaHtml += Template(outerSigMetaTemplate).substitute(rank=signatureIndex,
                                                             percent=("%.00f%%" % percent),
                                                             # expandosig=('sig'+str(signatureIndex)),
                                                             expandosig=stringToHtmlId(hash),
                                                             annexpandosig=('sig'+str(signatureIndex)),
                                                             signature=(html.escape(signature)),
                                                             newicon=newIcon,
                                                             fissionicon='noicon',
                                                             lockicon=lockdownIcon,
                                                             oomicon=oomIcon,
                                                             iconclass=searchIconClass,
                                                             anniconclass=annIconClass,
                                                             cslink=crashStatsHashQuery,
                                                             cssearchlink=crashStatsQuery,
                                                             clientcount=sigRecord['clientcount'],
                                                             count=crashcount,
                                                             reports=sigHtml)

  signatureHtml += Template(outerSigTemplate).substitute(channel=channel,
                                                         # version=queryFxVersion,
                                                         process=processType,
                                                         sigcount=sigCount,
                                                         repcount=reportCount,
                                                         sparkline=sparklineJS,
                                                         signature=sigMetaHtml)

  # Add processed date to the footer
  dateTime = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
  resultFile.write(Template(mainPage).substitute(main=signatureHtml,
                                                 annotations=annotationsHtml,
                                                 processeddate=dateTime))
  resultFile.close()

###########################################################
# Process crashes and stacks
###########################################################

def main():
  global CrashProcessMax

  queryId = ''
  userKey = ''
  targetSignature = ''

  dbFilename = "crashreports" #.json
  annoFilename = "annotations"
  cacheValue = MaxAge
  parameters = dict()

  options, remainder = getopt.getopt(sys.argv[1:], 'c:u:n:d:c:k:q:p:s:zm')
  for o, a in options:
    if o == '-u':
      jsonUrl = a
      print("data source url: %s" %  jsonUrl)
    elif o == '-n':
      outputFilename = a
      print("output filename: %s.html" %  outputFilename)
    elif o == '-c':
      cacheValue = int(a)
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
    elif o == '-s':
      targetSignature = a
      print("target signature: %s" %  targetSignature)
    elif o == '-m':
      print("calling maintenance function.")
      doMaintenance(dbFilename)
      exit()
    elif o == '-p':
      param = a.split('=')
      parameters[param[0]] = param[1]
    elif o == '-z':
      reports, stats = loadReports(dbFilename)
      dumpDatabase(reports)
      exit()

  if len(userKey) == 0:
    print("missing user api key.")
    exit()
  elif len(queryId) == 0:
    print("missing query id.")
    exit()

  print("redash cache time: %d" %  cacheValue)

  parameters['crashcount'] = str(CrashProcessMax)

  if len(targetSignature) > 0:
    print("analyzing '%s'" % targetSignature)
    generateSignatureReport(targetSignature)
    exit()

  # Pull fresh data from redash and process it
  reports, stats, totalCrashesProcessed = processRedashDataset(dbFilename, jsonUrl, queryId, userKey, cacheValue, parameters)

  # Caching of reports
  cacheReports(reports, stats, dbFilename)

  processType = parameters['process_type']
  channel = parameters['channel']
  queryFxVersion = parameters['version']

  generateTopCrashReport(reports, stats, totalCrashesProcessed, processType, channel,
                         queryFxVersion, outputFilename, annoFilename)

  exit()

if __name__ == "__main__":
  main()
