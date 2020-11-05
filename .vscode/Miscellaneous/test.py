from pyDatalog import pyDatalog
from pyDatalog import Logic
import logging
from pyDatalog import pyEngine
pyEngine.Trace = True



@pyDatalog.predicate()
def p2(X,Y):
    yield (1,2)
    yield (2,3)
print(pyDatalog.ask('p(1,Y)')) # prints == set([(1, 2)])


@pyDatalog.predicate()
def providesIfRequired2(requiredN,providedN):
    if requiredN == 1:
        required = True
    else:
        required = False
    if providedN ==1:
        provided = True
    else:
        provided = False
    t = (not required or (required and provided))
    return iter([t])
print(pyDatalog.ask('providesIfRequired(1,1)'))
