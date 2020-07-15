from pyDatalog import pyDatalog
from pyDatalog import Logic
import logging
from pyDatalog import pyEngine
pyEngine.Trace = True
import copy
import itertools
import gc

#logging.basicConfig(level=logging.DEBUG)

Logic()
#pyDatalog.create_terms('a','b','c','d','isTrue','equal','X','Y','Z')

#equal(X,Y) <= equal(Y,X)
#equal(X,Z) <= equal(X,Y) & equal(Y,Z)

#+ equal('a','b')
#+ equal('b','c')

#myAnswer = pyDatalog.ask('equal(X,Y)')
#print str(myAnswer.answers)

pyDatalog.create_terms('parent,child,grandparent,X,Y,Z,Alice,Bob,Charlie,David,Eve')

grandparent(X,Z) <= parent(X,Y) & parent(Y,Z)
+ parent('Alice','Bob')
+ parent('Bob','Charlie')
+ parent('Charlie','David')

myAnswer = pyDatalog.ask('grandparent(X,Y)')
print str(myAnswer.answers)

logic1 = Logic(True)

+ parent('David','Eve')

myAnswer = pyDatalog.ask('grandparent(X,Y)')
print str(myAnswer.answers)

Logic()

grandparent(X,Z) <= parent(X,Y) & parent(Y,Z)
+ parent('Alice','Bob')
+ parent('Bob','Charlie')
+ parent('Charlie','David')

myAnswer = pyDatalog.ask('grandparent(X,Y)')
print str(myAnswer.answers)

Logic(logic1)

myAnswer = pyDatalog.ask('grandparent(X,Y)')
print str(myAnswer.answers)
#Test

+ inSet(['A1'],'A')
+ inSet(['A2'],'A')
+ inSet(['A2,A3'],'A')
#Does adding to a set get rid of duplicates?
