#!/usr/bin/env python3

import json
import os
import pprint
import getopt
import sys
import re
import html
import pprint

###########################################################
# Usage
###########################################################
# -s (signature)      : signature to annotate
# -a (annotation)     : simple text based note. bugzilla references
#                       will automatically get linked.
# -c                  : clear any existing data in the database
# -f (bug#)           : add a fixed by bug # annotation
# -v (version)        : fixed by annotation firefox version ex: '89.0'
#
# examples:
# python annotate.py -s "draw_quad_spans<T>" -a "filed Bug 1712938"

pp = pprint.PrettyPrinter(indent=2)

def saveAnnotations(ann, filename):
  file = "%s.json" % filename
  with open(file, "w") as database:
      database.write(json.dumps(ann))

def loadAnnotations(filename):
  file = "%s.json" % filename
  try:
    with open(file) as database:
      annotations = json.load(database)
  except FileNotFoundError:
    print("Could not find %s file." % file)
    return dict()
  except json.decoder.JSONDecodeError:
    print("Json error parsing %s" % file)
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
dbFilename = "annotations"
annotation = None

options, remainder = getopt.getopt(sys.argv[1:], 's:a:f:p:cv:')
for o, a in options:
  if o == '-a':
    annotation = a
  elif o == '-c':
    newDatabase = True
    print("Using a new database.")
  elif o == '-s':
    signature = a
  elif o == '-f':
    bugId = int(a)
    fixedBy = True
  elif o == '-v':
    appliesToFxVersion = a
  elif o == '-p':
    param = a.split('=')
    parameters[param[0]] = param[1]

#channel = parameters['channel']
#fxVersion = parameters['version']
#processType = parameters['process_type']

annDb = dict()
if not newDatabase:
  annDb = loadAnnotations(dbFilename)

signature = signature.strip("'\n \t")
print('signature: [%s]' % signature)

if annotation is None:
  annotation = ''

if fixedBy:
  if appliesToFxVersion is None or bugId is None or annotation is None:
    print("missing parameters for fixed by entry.")
    exit()
  print("Fixed by version '%s' in bug %d, annotation: '%s'" % (appliesToFxVersion, bugId, annotation))
elif annotation:
  print("annotation: '%s'" %  annotation)
else:
  exit()

annotation = annotation.strip("'\n \t")

record = dict()
if signature in annDb:
  record = annDb[signature]
else:
  record['annotations'] = list() # string list
  record['fixedby'] = list() # [n] = { 'version': '87.b0', 'bug': 1234567 }

if fixedBy:
  entry = { 'bug': bugId, 'version': appliesToFxVersion, 'annotation':annotation}
  record['fixedby'].append(entry)
elif len(annotation) > 0:
  annotation = annotation.strip("'\n \t")
  record['annotations'].append(annotation)


annDb[signature] = record

#pp.pprint(annDb)

saveAnnotations(annDb, dbFilename)