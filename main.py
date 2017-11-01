from pyDatalog import pyDatalog
from pyDatalog import Logic
import logging
from pyDatalog import pyEngine
pyEngine.Trace = True
import copy
import itertools
import gc
import sys

#This is the risk metric
Logic()
pyDatalog.create_terms('connectsTo,residesOn,runs,TargetHost,SourceHost,DestHost,TargetService,SourceService,compromised,connectsToWithPrivileges,questionableWithinRisk,functionQuestionableWithinRisk')
pyDatalog.create_terms('cTo,cToWithPrivileges,ServiceA,ServiceB,HostA,HostB,localRootExploit,remoteRootExploit,attackerConnectsToWithPrivileges,attackerReachable')
pyDatalog.create_terms('allPaths,allAttackerPaths,P,P2,IntermediateService1,attackerCanReachOneStep,ok,attackerCanReachTwoSteps,oneStepToBadness,twoStepsToBadness')
pyDatalog.create_terms('requires,Task,Hostname','remoteUserExploit','vulnExists')
pyDatalog.create_terms('cutConnection','VulnType','isA','C','C2','cost','TotalC','TotalC2','E','E2','notConnectsTo','notResidesOn','notCompromised','notRemoteUserExploit','notRemoteRootExploit','notLocalRootExploit''a','b','c','suspicious','t1','t2','t3','t4','t5','TacticNumber','moveHostTo')
pyDatalog.create_terms('TestA','TestB','utility','FunctionA','resultingUtil','functionCompromised','functionUncompromised','FuncAUtil','allConnectionPaths','questionable','functionQuestionable','U','requiresConnection','networkConnectsTo','adHost','missingConnection')

class ProbabilityError(Exception):
    def __init__(self,message):
        self.message = "Probabilities do not add to 1.00"
# Dictionary of capability,probability pairs for the attacker's capabilities
# The probabilities should add to equal 1.00
class RiskPDF:
    def __init__(self, pdf):
        total = float(0)
        self.maxR = 0
        self.pdfDict = pdf
        #Determine the highest risk (i.e., what is the highest value of the attacker's capability)
        for k,v in self.pdfDict.iteritems():
            total += v
            if k > self.maxR:
                self.maxR = k
        #Check that probabilities add to 100
        if total != float(1):
            raise ProbabilityError

    def maxRisk(self):
        return self.maxR
    def probabilityOfRisk(self,r):
        return self.pdfDict[r]

riskDistribution = RiskPDF(dict([(0,0.10),(1,0.30),(2,0.30),(3,0.30)]))
maxRisk = riskDistribution.maxRisk()

sourceService = "attackerClient"
targetService = "controller1"
#targetService = "paymentServer"

def addAllPossibleConnections():
    #newConnections = createAddNetworkConnectionIter()
    #get list of services
    servicesAnswers = pyDatalog.ask("isA(ServiceA,'userAccount')").answers
    servicesList = []
    for answer in servicesAnswers:
        servicesList.append(answer[0])
    #print("Services: " + str(servicesList))
    #get permutations of two services
    allPossibleConnections = itertools.permutations(servicesList,2)
    #remove permutations that represent services that are already directly connected
    #possibleConnections = itertools.ifilter(lambda connectionPair: connectionDoesNotExist(connectionPair),allPossibleConnections)
    #possibleConnectionsTactics = itertools.imap(createAddConnectionTactic,possibleConnections)
    #print("Available new connections" + str(list(possibleConnectionsTactics)))
    for c in allPossibleConnections:
        pyDatalog.assert_fact("networkConnectsTo",c[0],c[1])

def setup():
    #pyDatalog.load(open("architectureInstance.py","r").read())
    pyDatalog.load(open("icsArchInstance.py","r").read())
    #addAllPossibleConnections()
    pyDatalog.load(open("architectureStyle.py","r").read())
    pyDatalog.load(open("vulnerabilityStyle.py","r").read())
#Save this for later
setup()
noVulnLogic = Logic(True)
Logic()
setup()




def sumAllUtilities():
    sum = 0
    utilitiesAnswer = pyDatalog.ask('utility(FunctionA,U)')
    #print(utilitiesAnswer)
    if utilitiesAnswer == None:
        return sum
    utilitiesSet = utilitiesAnswer.answers
    for uTuple in utilitiesSet:
        sum += uTuple[1]
    #print("Sum: " + str(sum))
    return sum

maxUtility = sumAllUtilities()

print("Maximum Utility with No Vulnerabilities: " + str(sumAllUtilities()))

def sumQuestionableUtilitiesWithinRisk(rMax):
    sum = 0

    #qa = pyDatalog.ask("questionableWithinRisk(ServiceA," + str(rMax) + ")")
    #print "Questionable Services:"
    #print qa.answers

    #mc = pyDatalog.ask("missingConnection(ServiceA,ServiceB)")
    #print "Missing Connections:"
    #print mc.answers

    #BUG This is the source of slowness
    #top = riskDistribution.maxRisk() + 1
    #for r in range(0,top):
    utilitiesAnswer = pyDatalog.ask("functionQuestionableWithinRisk(FunctionA,U," + str(rMax) + ")")
    if utilitiesAnswer != None:
        utilitiesSet = utilitiesAnswer.answers
        #print(str(utilitiesSet))
        for uTuple in utilitiesSet:
            #print("Questionable Function: " + uTuple[0])
            sum += uTuple[1]
    #print("Questionable Sum: " + str(sum) + " For Risk: " + str(rMax))
    return sum

def sumQuestionableUtilities():
    sum = 0
    #BUG This is the source of slowness
    utilitiesAnswer = pyDatalog.ask('functionQuestionable(FunctionA,U)')
    if utilitiesAnswer == None:
        return sum
    utilitiesSet = utilitiesAnswer.answers
    #print(str(utilitiesSet))
    for uTuple in utilitiesSet:
        sum += uTuple[1]
    #print("Questionable Sum: " + str(sum))
    return sum

def determineResidualUtility():
    return (maxUtility - sumQuestionableUtilities())

#Is it right to loop through all risks?
def determineResidualUtility2():
    sum = float(maxUtility) #Change this later to 1.00
    top = riskDistribution.maxRisk() + 1
    for r in range(0,top):
        sum -= sumQuestionableUtilitiesWithinRisk(r) * riskDistribution.probabilityOfRisk(r)
    return sum
#originalLogic = Logic(True)

#Is it right to loop through all risks?
def determineResidualUtility3():
    #sum = float(maxUtility) #Change this later to 1.00
    sum = float(0)
    #print("Max Utility: " + str(maxUtility))
    top = riskDistribution.maxRisk() + 1
    for r in range(0,top):
        #print sumQuestionableUtilitiesWithinRisk(r)
        sum += (maxUtility - sumQuestionableUtilitiesWithinRisk(r)) * riskDistribution.probabilityOfRisk(r)
        #sum -= (maxUtility - sumQuestionableUtilitiesWithinRisk(r)) * riskDistribution.probabilityOfRisk(r)
        #print ("+ (" + str(maxUtility) + " - "+ str(sumQuestionableUtilitiesWithinRisk(r)) + ") * " + str(riskDistribution.probabilityOfRisk(r)))
    #print("Residual utility: " + str(sum))
    return sum

#Define Tactics

#Should this cut the connection in both directions? I'm going with no
def cutNetworkConnection(ServiceA, ServiceB):
    pyDatalog.retract_fact("networkConnectsTo",ServiceA,ServiceB)

def moveService(ServiceA,HostA,HostB):
    pyDatalog.retract_fact(residesOn,ServiceA,HostA)
    pyDatalog.assert_fact(residesOn,HostB)

def mitigate(ServiceA):
    pyDatalog.retract_fact(compromised,ServiceA)


#Search:
#Find connections to cut:
#Does this need to be refreshed?
connections = pyDatalog.ask('networkConnectsTo(ServiceA,ServiceB)').answers
#print("Network Connections" + str(connections))

def connectionDoesNotExist(connectionPair):
    #print("Connection pair: " + str(connectionPair))
    if connectionPair in connections:
        return False
    else:
        return True

def createAddConnectionTactic(connectionPair):
    t = ["assert","networkConnectsTo",connectionPair[0],connectionPair[1]]
    return t

#TODO: Make generic tactic iters
#This only adds to iter if connection doesn't already exist and maybe if both source and target
#are internal to oranization
def createAddNetworkConnectionIter():
    #get list of services
    servicesAnswers = pyDatalog.ask("isA(ServiceA,'userAccount')").answers
    servicesList = []
    for answer in servicesAnswers:
        servicesList.append(answer[0])
    #print("Services: " + str(servicesList))
    #get permutations of two services
    allPossibleConnections = itertools.permutations(servicesList,2)
    #remove permutations that represent services that are already directly connected
    possibleConnections = itertools.ifilter(lambda connectionPair: connectionDoesNotExist(connectionPair),allPossibleConnections)
    possibleConnectionsTactics = itertools.imap(createAddConnectionTactic,possibleConnections)
    #print("Available new connections" + str(list(possibleConnectionsTactics)))
    return possibleConnectionsTactics

#createAddNetworkConnectionIter()

def createCutNetworkConnectionIter():
    connectionIter = []
    for connection in connections:
        c = ["retract","networkConnectsTo",connection[0],connection[1]]
        #print c
        connectionIter.append(c)
    return iter(connectionIter)


#tacticsIter = createCutNetworkConnectionIter()
#tacticsIter = createAddNetworkConnectionIter()
def tacticsIter():
    #return createCutNetworkConnectionIter()
    return createAddNetworkConnectionIter()
    #return itertools.chain(createAddNetworkConnectionIter(),createCutNetworkConnectionIter())

#This is the tactic format:
#['retract', 'connectsTo', 'paymentServer', 'host1']



def createAttackScenarioLogic(currentAttackScenario):
    #for currentAttackScenario in attackScenarios:
        #Clear all vulnerabilities and add only those for a specific attack
        Logic()
        #BUG? Removed line below
        #Logic(noVulnLogic)
        setup()
        #serviceTuple is a tuple of services on the attack path
        serviceTuple = currentAttackScenario[0]
        #we have to add the final (target) service to the end of the path
        serviceTuple = serviceTuple + (targetService,)
        #vulnerabilityTuple is a tuple of the vulnerabilities exploited along the attack path
        vulnerabilityTuple = currentAttackScenario[1]
        #print("Creating Attack Scenario...")
        for s,v  in zip(serviceTuple,vulnerabilityTuple):
            if v != "legitimate":
                #print("Adding Fact: " + v + "(" + s + ",0)")
                pyDatalog.assert_fact(v,s,0)

#BUG This needs to be fixed up to only get attack scenarios within risk
#and to include that risk number in list that's returned
#This version of get attack scenarios does not attempt to change the Logic
#other than adding in the vulnerabilities
def getAttackScenarios3():
        #First find all the attack Scenarios
        #Set up the architecture and logic
        #Logic()
        #Logic(noVulnLogic)
        #setup()
        #Apply all the possible vullnerabilities to the instance
        pyDatalog.load(open("applyAllVulnerabilities.py","r").read())
        #Find all potential attack scenarios to get from the source to the target
        maxR = riskDistribution.maxRisk()
        attackQuery = "allAttackerPaths('" + sourceService + "','" + targetService + "',P,E,TotalC)"
        attackScenariosAnswer = pyDatalog.ask(attackQuery)
        #print attackScenariosAnswer.answers
        #attackQuery = "allAttackerPaths('" + sourceService + "','" + targetService + "',P,E," + str(maxR) + ")"
        #print attackScenariosAnswer.answers
        #print attackQuery
        #attackScenariosAnswer = pyDatalog.ask(attackQuery)
        if attackScenariosAnswer == None:
            return []
        else:
            attackScenarios = attackScenariosAnswer.answers
            #print attackScenarios
            #print("Attack Scenarios: " + str(len(attackScenarios)))
            return attackScenarios

def getAttackScenarios2():
        #First find all the attack Scenarios
        #Set up the architecture and logic
        Logic()
        #Logic(noVulnLogic)
        setup()
        #Apply all the possible vullnerabilities to the instance
        pyDatalog.load(open("applyAllVulnerabilities.py","r").read())
        #Find all potential attack scenarios to get from the source to the target
        maxR = riskDistribution.maxRisk()
        attackQuery = "allAttackerPaths('" + sourceService + "','" + targetService + "',P,E,TotalC)"
        attackScenariosAnswer = pyDatalog.ask(attackQuery)
        #print attackScenariosAnswer.answers
        #attackQuery = "allAttackerPaths('" + sourceService + "','" + targetService + "',P,E," + str(maxR) + ")"
        #print attackScenariosAnswer.answers
        #print attackQuery
        #attackScenariosAnswer = pyDatalog.ask(attackQuery)
        if attackScenariosAnswer == None:
            return []
        else:
            attackScenarios = attackScenariosAnswer.answers
            #print attackScenarios
            #print("Attack Scenarios: " + str(len(attackScenarios)))
            return attackScenarios

#getAttackScenarios2()

def getAttackScenarios():
        #First find all the attack Scenarios
        #Set up the architecture and logic
        Logic()
        #Logic(noVulnLogic)
        setup()
        #Apply all the possible vullnerabilities to the instance
        pyDatalog.load(open("applyAllVulnerabilities.py","r").read())
        #Find all potential attack scenarios to get from the source to the target
        attackQuery = "allAttackerPaths('" + sourceService + "','" + targetService + "',P,E,TotalC)"
        attackScenariosAnswer = pyDatalog.ask(attackQuery)
        attackScenarios = attackScenariosAnswer.answers
        #print("Attack Scenarios: " + str(len(attackScenarios)))
        return attackScenarios


def bestOptions(utilities):
    print utilities
    bestUtility = 0
    #This is a set of sets of tactics
    bestTacticsSets = []
    for tacticOption in utilities:
        u = utilities[tacticOption]
        if u > bestUtility:
            bestUtility = u
            bestTacticsSets = [tacticOption]
        elif u == bestUtility:
            bestTacticsSets.append(tacticOption)
    print("Best Utility: " + str(bestUtility))
    print("Best Tactics Options: " + str(bestTacticsSets))

# Hypothetical probability density function for various costs/risks
# An attack with cost 2 is 1/2 as likely as an attack with cost 1
# (That's just my estimate here)

# 0 10% (no attacks)
# 1 30% (1) -> 1
# 2 30% (1,2,2) -> 1/1 + 1/2 + 1/2 -> (sum is 2) -> 1/2 + 1/4 + 1/4
# 3 30% (1,2,2,3) -> 1/1 * 1/2 + 1/2  1/3 -> (sum is 2.3333) ...

#1 weight is 10*0 + 30*1 + 30*1/2 + ...

#Hypothetical attack scenario costs (risks)
#1, 2, 2, 3

# First attack scenario weight is

def tryTacticOptions3(maxTactics):
    #generate the tactic sets
    #for each tactic set in the iterator
        #apply the tactic set
        #check the amortized utility of the system across possible risks
        #if this tactic set is better, save it
        #undo the tactic set


    #Initialize utilities dictionary for each of the tactic options
    utilities = {}
    for numTactics in range(1,maxTactics+1):
        tacticOptions = itertools.combinations(tacticsIter(),numTactics)
        for tacticSet in tacticOptions:
            #print str((sorted(list(tacticSet))))
            utilities[str(sorted(list(tacticSet)))] = float(0)
        utilities[None] = float(determineResidualUtility3())
    #print("Tactic options: " + str(len(list(itertools.permutations(tacticsIter(),maxTactics)))))

    #For progress tracking
    numOptions = len(utilities)
    setNumber = 0

    print("Tactic options: " + str(numOptions))
    #TODO Ensure logic is correct here...should be all possible vulnerabilities, I think
    #BUG Also try zero tactics! Maybe current config is the best
    for numTactics in range(1,maxTactics+1):
        print("Trying " + str(numTactics) + " tactics...")
    #for attackScenario in attackScenarios:
        #Set up attack scenario logic
        #createAttackScenarioLogic(attackScenario)
        #scenarioRisk = attackScenario[2]
        #Create tactics iterator
        #print("Tactic options: " + str(len(list(itertools.permutations(tacticsIter(),maxTactics)))))
        tacticOptions = itertools.combinations(tacticsIter(),numTactics)
        #if numTactics == 0:
        #    tacticOptions = iter([[]])
        for tacticSet in tacticOptions:
            #Print status
            setNumber += 1
            percentComplete = 100 * setNumber / numOptions
            print(str(percentComplete) + "%...\r"),
            sys.stdout.flush()
            #print "***************************************"
            #print "Tactic Set:"
            #print tacticSet
            #Apply the set of tactics in that option
            for tactic in tacticSet:
                #print tactic
                args = tactic[1:]
                if tactic[0] == "retract":
                    pyDatalog.retract_fact(*args)
                    #print "Retracted fact"
                    #print "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
                else:
                    pyDatalog.assert_fact(*args)
                    #print "Asserted fact"
            #Check for attacks
            attackScenarios = getAttackScenarios3()
            #Find the cost of all the attacks
            #costList includes all attacks, including maybe those above the risk threshold
            costList = []
            for attackScenario in attackScenarios:
                #print attackScenario
                costList.append(attackScenario[2])
            sortedCosts = sorted(costList)
            #Determine relatively likelihood of each attack
            #I.e., the assumption is that easier attacks are more likely
            attackLikelihoods = []
            top = riskDistribution.maxRisk() + 1
            #For all attack costs in the riskPDF
            for r in range(0,top):
                costsUnderThisRisk = []
                inverseWeightedCosts = []
                inverseCostSum = float(0)
                for c in sortedCosts:
                    if c <= r:
                        costsUnderThisRisk.append(c)
                        inverseCostSum += (1/float(c))
                for c in costsUnderThisRisk:
                    inverseWeightedCosts.append([c,1/(c * inverseCostSum)])
                attackLikelihoods.append([r,riskDistribution.probabilityOfRisk(r), inverseWeightedCosts])
            #print attackLikelihoods
            # Determine the likelihood of an attack given a particular cost/risk value
            #This dictionary looks up the overall likelihood of an attack given a cost
            #It's based on the cost of the attack and the riskPDF
            attackLikelihoodDict = {}
            for r in range(0,top):
                attackLikelihoodDict[r] = float(0)
            for riskLevel in attackLikelihoods:
                r = riskLevel[0]
                probabilityOfRisk = riskLevel[1]
                scenarios = riskLevel[2]
                lastR = -1
                for scenario in scenarios:
                    #Don't repeat dictionary inclusion for a given attack risk/cost
                    scenarioRisk = scenario[0]
                    if scenarioRisk != lastR:
                        attackLikelihoodDict[scenarioRisk] += (scenario[1] * probabilityOfRisk)
                    lastR = scenarioRisk
            #print attackLikelihoodDict
            #print("Attack Scenarios: " + str(len(attackScenarios)))
            #Determine utility and add to part in dictionary
            #Includes cost of tactic: A cost of 1 per tactic
            #Weighted Value
            utilities[str(sorted(list(tacticSet)))] += determineResidualUtility3() - numTactics
            #utilities[str(sorted(list(tacticSet)))] += (determineResidualUtility2() - numTactics) * attackLikelihoodDict[scenarioRisk]
            #Reverse tactic application
            for tactic in tacticSet:
                #print tactic
                args = tactic[1:]
                if tactic[0] == "assert":
                    pyDatalog.retract_fact(*args)
                else:
                    pyDatalog.assert_fact(*args)
    #print utilities
    bestOptions(utilities)

#BUG I should also try zero tactic options!
#NOTE: Tactics should be applied only if they are not redundant
#For example, don't apply the same tactic twice, and don't apply
#a tactic like cutting a network connection when the connection
#doesn't exist. Otherwise, this will mess up the reversal of the
#tactics
def tryTacticOptions2(maxTactics):
    attackScenarios = getAttackScenarios2()
    costList = []
    for attackScenario in attackScenarios:
        print attackScenario
        costList.append(attackScenario[2])
    #print "Cost List:"
    #print costList
    sortedCosts = sorted(costList)
    #print "Sorted Cost List:"
    #print sortedCosts
    attackLikelihoods = []
    top = riskDistribution.maxRisk() + 1
    for r in range(0,top):
        costsUnderThisRisk = []
        inverseWeightedCosts = []
        inverseCostSum = float(0)
        for c in sortedCosts:
            if c <= r:
                costsUnderThisRisk.append(c)
                inverseCostSum += (1/float(c))
        for c in costsUnderThisRisk:
            inverseWeightedCosts.append([c,1/(c * inverseCostSum)])
        attackLikelihoods.append([r,riskDistribution.probabilityOfRisk(r), inverseWeightedCosts])
    #print attackLikelihoods
    # Determine the likelihood of an attack with a particular cost
    attackLikelihoodDict = {}
    for r in range(0,top):
        attackLikelihoodDict[r] = float(0)
    for riskLevel in attackLikelihoods:
        r = riskLevel[0]
        probabilityOfRisk = riskLevel[1]
        scenarios = riskLevel[2]
        lastR = -1
        for scenario in scenarios:
            #Don't repeat addition for a given attack risk/cost
            scenarioRisk = scenario[0]
            if scenarioRisk != lastR:
                attackLikelihoodDict[scenarioRisk] += (scenario[1] * probabilityOfRisk)
            lastR = scenarioRisk
    print attackLikelihoodDict
    print("Attack Scenarios: " + str(len(attackScenarios)))
    #Initialize utilities dictionary for each of the tactic options
    utilities = {}
    for numTactics in range(1,maxTactics+1):
        tacticOptions = itertools.combinations(tacticsIter(),numTactics)
        for tacticSet in tacticOptions:
            #print str((sorted(list(tacticSet))))
            utilities[str(sorted(list(tacticSet)))] = float(0)
    #print("Tactic options: " + str(len(list(itertools.permutations(tacticsIter(),maxTactics)))))
    print("Tactic options: " + str(len(utilities)))

    for numTactics in range(1,maxTactics+1):
        print("Trying " + str(numTactics) + " tactics...")
        for attackScenario in attackScenarios:
            #Set up attack scenario logic
            createAttackScenarioLogic(attackScenario)
            scenarioRisk = attackScenario[2]
            #Create tactics iterator
            #print("Tactic options: " + str(len(list(itertools.permutations(tacticsIter(),maxTactics)))))
            tacticOptions = itertools.combinations(tacticsIter(),numTactics)
            for tacticSet in tacticOptions:
                #Apply the set of tactics in that option
                for tactic in tacticSet:
                    #print tactic
                    args = tactic[1:]
                    if tactic[0] == "retract":
                        pyDatalog.retract_fact(*args)
                    else:
                        pyDatalog.assert_fact(*args)
                #Determine utility and add to part in dictionary
                #Includes cost of tactic: A cost of 1 per tactic
                #Weighted Value
                utilities[str(sorted(list(tacticSet)))] += (determineResidualUtility2() - numTactics) * attackLikelihoodDict[scenarioRisk]
                #Reverse tactic application
                for tactic in tacticSet:
                    #print tactic
                    args = tactic[1:]
                    if tactic[0] == "assert":
                        pyDatalog.retract_fact(*args)
                    else:
                        pyDatalog.assert_fact(*args)
    #print utilities
    bestOptions(utilities)



#NOTE: Tactics should be applied only if they are not redundant
#For example, don't apply the same tactic twice, and don't apply
#a tactic like cutting a network connection when the connection
#doesn't exist. Otherwise, this will mess up the reversal of the
#tactics
def tryTacticOptions(maxTactics):
    attackScenarios = getAttackScenarios()
    print("Attack Scenarios: " + str(len(attackScenarios)))
    #Initialize utilities dictionary for each of the tactic options
    utilities = {}
    for numTactics in range(1,maxTactics+1):
        tacticOptions = itertools.combinations(tacticsIter(),numTactics)
        for tacticSet in tacticOptions:
            #print str((sorted(list(tacticSet))))
            utilities[str(sorted(list(tacticSet)))] = 0
    #print("Tactic options: " + str(len(list(itertools.permutations(tacticsIter(),maxTactics)))))
    print("Tactic options: " + str(len(utilities)))

    for numTactics in range(1,maxTactics+1):
        print("Trying " + str(numTactics) + " tactics...")
        for attackScenario in attackScenarios:
            #Set up attack scenario logic
            createAttackScenarioLogic(attackScenario)
            #Create tactics iterator
            #print("Tactic options: " + str(len(list(itertools.permutations(tacticsIter(),maxTactics)))))
            tacticOptions = itertools.combinations(tacticsIter(),numTactics)
            for tacticSet in tacticOptions:
                #Apply the set of tactics in that option
                for tactic in tacticSet:
                    #print tactic
                    args = tactic[1:]
                    if tactic[0] == "retract":
                        pyDatalog.retract_fact(*args)
                    else:
                        pyDatalog.assert_fact(*args)
                #Determine utility and add to part in dictionary
                #Includes cost of tactic: A cost of 1 per tactic
                utilities[str(sorted(list(tacticSet)))] += determineResidualUtility() - numTactics
                #Reverse tactic application
                for tactic in tacticSet:
                    #print tactic
                    args = tactic[1:]
                    if tactic[0] == "assert":
                        pyDatalog.retract_fact(*args)
                    else:
                        pyDatalog.assert_fact(*args)
    #print utilities
    bestOptions(utilities)

tryTacticOptions3(3)
#tryTacticOptions(3)
