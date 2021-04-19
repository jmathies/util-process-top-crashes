#!/usr/bin/env python3

import json
import os
import pprint
import getopt
import sys
import re
import html
import pprint

pp = pprint.PrettyPrinter(indent=2)

def saveAnnotations(ann, filename):
  file = "%s_annotations.json" % filename
  with open(file, "w") as database:
      database.write(json.dumps(ann))

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

def escapeBugLinks(text):
  # convert bug references to links
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1323439
  pattern = "bug ([0-9]*) "
  replacement = "<a href='https://bugzilla.mozilla.org/show_bug.cgi?id=\\1'>\\1</a> "
  result = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
  return result

fixedBy = False
newDatabase = False
dbFilename = "default"

options, remainder = getopt.getopt(sys.argv[1:], 's:a:f:p:d:c')
for o, a in options:
  if o == '-a':
    annotation = a
    print("annotation: '%s'" %  annotation)
  elif o == '-c':
    newDatabase = True
    print("Using a new database.")
  elif o == '-s':
    signature = a
  elif o == '-f':
    bugId = int(a)
    fixedBy = True
    print("marking as fixed by bug #%d" % bugId)
  elif o == '-v':
    appliesToFxVersion = a
    print("fixed in firefox version %d" % int(a))
  elif o == '-p':
    param = a.split('=')
    parameters[param[0]] = param[1]
  elif o == '-d':
    dbFilename = a
    print("local database file: %s_annotations.json" %  dbFilename)

#channel = parameters['channel']
#fxVersion = parameters['version']
#processType = parameters['process_type']

annDb = dict()
if not newDatabase:
  annDb = loadAnnotations(dbFilename)

signature = signature.strip("'\n \t")
annotation = annotation.strip("'\n \t")
print('signature: [%s]' % signature)

record = dict()
if signature in annDb:
  record = annDb[signature]
else:
  record['annotations'] = list() # string list
  record['fixedby'] = list() # [n] = { 'version': 87, 'bug': 1234567 }

# escape for html
annotation = escape(annotation)
# convert bug references to links
annotation = escapeBugLinks(annotation)

record['annotations'].append(annotation)

if fixedBy:
  record['fixedby'].append(bugId)

annDb[signature] = record

#pp.pprint(annDb)

saveAnnotations(annDb, dbFilename)