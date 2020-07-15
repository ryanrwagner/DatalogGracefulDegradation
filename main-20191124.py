from pyDatalog import pyDatalog
from pyDatalog import Logic
import logging
from pyDatalog import pyEngine
pyEngine.Trace = True
import copy
import itertools
import gc
import sys
from operator import itemgetter
import pprint
import time

#This is the risk metric
Logic()
pyDatalog.create_terms('connectsTo,residesOn,runs,TargetHost,SourceHost,DestHost,TargetService,SourceService,compromised,connectsToWithPrivileges,questionableWithinRisk,functionQuestionableWithinRisk','allAttackerPathsCostPlus','F','F2','FuncName','U','U2','Util','allAttackerPathsCostPlus','SS','TS','IS1','functionDown','functionalityFree','Prob')
pyDatalog.create_terms('cTo,cToWithPrivileges,ServiceA,ServiceB,HostA,HostB,localRootExploit,remoteRootExploit,attackerConnectsToWithPrivileges,attackerReachable')
pyDatalog.create_terms('allPaths,allAttackerPaths,P,P2,IntermediateService1,attackerCanReachOneStep,ok,attackerCanReachTwoSteps,oneStepToBadness,twoStepsToBadness','shortestAttackerPathsPlus')
pyDatalog.create_terms('requires,Task,Hostname','remoteUserExploit','vulnExists','RiskForFunction','MaxR','OtherService','functionDownOrCompromised','probCompromised')
pyDatalog.create_terms('cutConnection','VulnType','isAccount','C','C2','cost','TotalC','TotalC2','E','E2','notConnectsTo','notResidesOn','notCompromised','notRemoteUserExploit','notRemoteRootExploit','notLocalRootExploit''a','b','c','suspicious','t1','t2','t3','t4','t5','TacticNumber','moveHostTo','transitiveConnects','transitiveConnectsSecure')
pyDatalog.create_terms('TestA','TestB','utility','FunctionA','resultingUtil','functionCompromised','functionUncompromised','FuncAUtil','allConnectionPaths','questionable','functionQuestionable','U','requiresConnection','networkConnectsTo','adHost','missingConnection','isType','allAttackerPathsWithTyping','ExploitAndTarget','ExploitAndTarget2','TargetType','questionableAtRisk','allAttackerPathsPlus','functionQuestionableWithinRiskPlus')
pyDatalog.create_terms('Functionality','Attribute','Data','Service','Impact','requiresSecurityAttribute','FunctionB','FunctionC','functionRequires','implements','implementedF','requiresAllConnections')
pyDatalog.create_terms('isType','validNewConnectsTo')
pyDatalog.create_terms('vulnExistsWithAttributes','remoteRootExploitWithAttributes','compromisedWithAttributes','functionCompromisedWithAttributes')
pyDatalog.create_terms('requiresSecurityAttribute','consumesDataWithAttributes','transitiveConnectsWithAttributes','producesData','requiresDataWithAttributes','COK','IOK','AOK','CRequired','IRequired','ARequired','CImpact','IImpact','AImpact')
pyDatalog.create_terms('CProvided','IProvided','AProvided','CProvided1','IProvided1','AProvided1','CProvided2','IProvided2','AProvided2','connectsToWithAttributes','consumesData','networkConnectsToWithAttributes','requiresFunction','transitiveConnectsWithAttributesOnPath')
pyDatalog.create_terms('consumesDataWithC','consumesDataWithI','consumesDataWithA','consumesDataWithAttributeProblems','consumesDataWithAttributesNoAlternative','allCompromised','someCompromised','attackPaths','pathCompromisesFunctionWithCost','pathCompromisesService')
pyDatalog.create_terms('isPath','X','Y','Z','pathCompromisesUtilities','pathCompromisesWithCost','worstCasePath','UtilPathPair','pathCompromisesFunctions','FList','worstCasePathValue','weightedWorstCastPath','probCapability','estimatedUtility','worstCasePathFromSource','SourceCost','compromisedCombo')

#Logic for Below Cases
@pyDatalog.predicate()
def providesIfRequired2(required,provided):
    return iter([not required or (required and provided)])

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
        #NOTE: Should I put this check back in?
        #if total != float(1):
        #    raise ProbabilityError

    def maxRisk(self):
        return self.maxR
    def probabilityOfRisk(self,r):
        return self.pdfDict[r]

#dict([(riskValue1,riskProbabilty1)...])
#riskDistribution = RiskPDF(dict([(0,0.30),(1,0.40),(2,0.20),(3,0.10)]))
#riskDistribution = RiskPDF(dict([(0,0.60),(1,0.30),(2,0.05),(3,0.05)]))
#Use below for network architecture baseline
#riskDistribution = RiskPDF(dict([(0,0.10),(1,0.10),(2,0.20),(3,0.60)]))
#Use below for satellite baseline
#riskDistribution = RiskPDF(dict([(0,0.30),(1,0.50),(2,0.20),(3,0.00)]))
#Use below for Spectre Simple
riskDistribution = RiskPDF(dict([(0,0.20),(1,0.20),(2,0.20),(3,0.20),(4,0.20)]))
#riskDistribution = RiskPDF(dict([(0,0.00),(1,0.50),(2,0.20),(3,0.30)]))


#riskDistribution = RiskPDF(dict([(0,0.0),(1,1.0),(2,0.0),(3,0.00)]))
#riskDistribution = RiskPDF(dict([(0,0.0),(1,0.0),(2,0.0),(3,0.0),(4,1.0)]))
#riskDistribution = RiskPDF(dict([(0,0.20),(1,0.30),(2,0.30),(3,0.15),(4,0.05)]))
#riskDistribution = RiskPDF(dict([(0,0.30),(1,0.60),(2,0.05),(3,0.05)]))



#riskDistribution = RiskPDF(dict([(0,0.001),(1,1.0),(2,0.0),(3,0.0)]))
maxRisk = riskDistribution.maxRisk()
bidirectional = True
#instanceFile = "banks.py"
#instanceFile = "multi-subnet.py"
#instanceFile = "icsArchInstance.py"
#instanceFile = "architectureInstance.py"
#instanceFile = "fw-test1.py"
#instanceFile = "spectre-simple.py"
instanceFile = "spectre-system.py"

#Logic for Below Cases
#def providesBoth(provided1,provided2):
#    return provided1 and provided2

def setup():
    #pyDatalog.load(open("architectureInstance.py","r").read())
    #pyDatalog.load(open("fw-test1.py","r").read())
    #pyDatalog.load(open("icsArchInstance.py","r").read())
    pyDatalog.load(open(instanceFile,"r").read())
    #Rules for the Architectural Style
    pyDatalog.load(open("architectureStyle.py","r").read())
    #Rules for Vulnerabilities (Architectural Style)
    pyDatalog.load(open("vulnerabilityStyle.py","r").read())
    #Rules for Functionalities
    pyDatalog.load(open("functionalStyle.py","r").read())
    #Make sure every component has every plausible vulnerability
    pyDatalog.load(open("applyAllVulnerabilities.py","r").read())

#Save this for later
setup()
noVulnLogic = Logic(True)
Logic()
setup()



#Determine the best case scenario if all possible functionalities work and are secure
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

def calculateProb(compromiseProbability,allCompromisedComponents):
    p = 1
    cList = []
    print "cp: " + str(compromiseProbability)
    print "acc: " + str(allCompromisedComponents)
    for component,prob in compromiseProbability:
        cList.append(component)
        p = p * prob
    return tuple([cList,p])

    #for componentProb in allCompromisedComponents:
        #print "componentProb: " + str(componentProb)
        #if componentProb in compromiseProbability:
        #    cList.append(componentProb[0])
        #    p = p * componentProb[1]
        #else:
        #    p = p * (1 - float(componentProb[1]))
    #return tuple([cList,p])


def getCombinations(compromisedComponents,debug=False):
    combos = iter([])
    combosList = [] # [[['internet', 0.99]], [['tepper', 0.1]], [['internet', 0.99], ['tepper', 0.1]]]
    comboComponents = [] # [['internet'], ['tepper'], ['internet', 'tepper']]
    #print "Compromised Components: " + str(compromisedComponents)
    for i in range(1,len(compromisedComponents)+1):
        #combos = itertools.chain(combos,itertools.combinations(compromisedComponents,i))
        #print "i: " + str(list(itertools.combinations(compromisedComponents,i)))
        newCombos = itertools.combinations(compromisedComponents,i)
        for c in newCombos:
            cList = []
            cc = []
            if debug:
                print "c:" + str(c)
            for comp,p in c: #compromised component, probability of compromise
                #print "comp,p:" + str(comp) + "||" + str(p)
                cList.append([comp,p])
                cc.append(comp)
            combosList.append(cList)
            comboComponents.append(cc)
    # [[['internet', 0.99]], [['tepper', 0.1]], [['internet', 0.99], ['tepper', 0.1]]]
    #print "Combos List Complete: " + str(combosList)
    #print "Combos List Components: " + str(comboComponents)
         #combosArray = combosArray.extend(itertools.combinations(compromisedComponents,i))
    #combosList = list(combos)

    componentCombinations = []
    noCompromiseProb = float(1) # for tracking the probability that nothing is compromised
    for combo in combosList: # combo: [['internet', 0.99], ['tepper', 0.1]]
        #print combo
        p = float(1)
        components = []
        for cp in compromisedComponents: # ['internet', 0.99]
            if list(cp) in combo:
                #print "In" + str(list(cp)) + "||" + str(combo)
                p = p * cp[1]
                components.append(cp[0])
            else:
                #print "Out" + str(list(cp)) + "||" + str(combo)
                p = p * (1 - cp[1])
        #print components
        #print p
        noCompromiseProb -= p
        componentCombinations.append([components,p])
    #print "No compromise prob: "
    #print noCompromiseProb
    componentCombinations.append([[],noCompromiseProb])
        #for component,prob in combo:
        #    if component in
    #for c in combos:
    #    combosArray.append(c)
    #print "CombosArray: " + str(combosArray)
    #for c in combos:
    #    print "Combination " + str(c)
    #for i in range(1,len(compromisedComponents)+1):
    #    combos = itertools.chain(combos,itertools.combinations(compromisedComponents,i))
    #componentCombinations = itertools.imap(calculateProb,combosList,compromisedComponents)
    #componentCombinations2 = componentCombinations
    if debug:
        for c in componentCombinations:
            print "Combination " + str(c)
    return componentCombinations

def determineResidualUtility(debug=False):
    rMax = riskDistribution.maxRisk()
    #Uncomment this after debugging
    #Time hog?
    #if debug:
    print "Calculating attack scenarios..."
    costsPlus = pyDatalog.ask("allAttackerPathsCostPlus(SourceService,TargetService,P,E,F,U,TotalC," + str(rMax) + ")")
    #if debug:
    print "Scenarios calculated."
    #if debug:
    #    print "Query: " + "allAttackerPathsCostPlus(SourceService,TargetService,P,E,F,U,TotalC," + str(rMax) + ")"
    #costsPlus = pyDatalog.ask("allAttackerPathsCostPlus(SourceService,TargetService,P,E,F,U,TotalC," + str(1) + ")")
    if costsPlus != None:
        costsPlusSorted = sorted(costsPlus.answers, key=itemgetter(5))
        if debug:
            print "No attack traces"
    else:
        costsPlusSorted = []
        if debug:
            print "Attack traces:"
            pprint.pprint(costsPlusSorted)

    #qFs = pyDatalog.ask("functionQuestionable(FuncName,Util)")
    #print("Questionable functions:")
    #print(qFs.answers)

    compromisedComponents = pyDatalog.ask("probCompromised(SourceService,Prob)")
    if compromisedComponents != None:
        #if debug:
        #    print "Compromised Components x:"
        #    print compromisedComponents.answers
        combos = getCombinations(compromisedComponents.answers,debug)
    else:
        #if debug:
        print "Nothing compromised"

    sumOverCombos = 0
    compromisedAllPossibleAnswer = pyDatalog.ask("compromised(SourceService)").answers
    compromisedAllPossible = [] #List of all possible compromised components
    if compromisedAllPossibleAnswer != None:
        for c in compromisedAllPossibleAnswer:
            compromisedAllPossible.append(c)

    #Loop over each possible combination of compromised components
    #print "Combos: " + str(combos)
    for compromiseCombo in combos:
        compromisedComponents = compromiseCombo[0]
        prob = compromiseCombo[1]
        if debug:
            print "Compromised Components:"
            print compromisedComponents
            print "Prob:"
            print prob


        #New Code to remove from database things that aren't compromised this iteration
        #There are probably better ways to do this for performance
        for cc in compromisedAllPossible:
            if cc[0] not in compromisedComponents:
                if debug:
                    print "Remove " + str(cc[0])
                pyDatalog.retract_fact("compromised",str(cc[0]))
        #Was this right to comment out?
        #costsPlus = pyDatalog.ask("allAttackerPathsCostPlus(SourceService,TargetService,P,E,F,U,TotalC," + str(rMax) + ")")
        #End New Code

        costsPlusSortedLimited = costsPlusSorted #These are just the attack traces with the currently compromised components
        #print costsPlusSorted
        #possibleConnections = itertools.ifilter(lambda connectionPair: connectionDoesNotExist(connectionPair),allPossibleConnections)
        #print CostPlusSorted[0][0]
        costsPlusSortedLimited = [trace for trace in costsPlusSorted if trace[0] in compromisedComponents]
        if debug:
            print "CostPlusSorted Length: "
            print len(costsPlusSorted)
            print len(costsPlusSortedLimited)
        #Find the worst case scenario for any given level of attacker capability
        riskUtilDict = {}
        if debug:
            fDict = {}
            #print "BROKEN CONNECTIONS:"
            #pprint.pprint(pyDatalog.ask("transitiveConnectionBroken(SourceService,TargetService)").answers)
            #print "RTU CONNECTIONS"
            #pprint.pprint(pyDatalog.ask("transitiveConnects('rtus',TargetService)").answers)
        downOrCompUtil = 0

        if False:
            downFunctions = pyDatalog.ask("functionDown(FunctionA,U)") # Required connections are down
            compromisedFunctions = pyDatalog.ask("functionCompromised(FunctionA,U)")
            if downFunctions != None:
                downUtils = downFunctions.answers
                #if debug:
                print "Down Utilities:"
                print downUtils
                #for [f,u] in downUtils:
                    #print u
                    #downUtil += u
            if compromisedFunctions != None:
                compromisedFs = compromisedFunctions.answers
                #if debug:
                print "Compromised Utilities:"
                print compromisedFs
        #Time hog?
        #if debug:
        print "Calculating Down and Compromised Functions"
        downOrCompromisedFunctions = pyDatalog.ask("functionDownOrCompromised(FunctionA,U)")
        #if debug:
        print "Down and Compromised Functions Calculated"
        if downOrCompromisedFunctions == None:
            if debug:
                print "Nothing Down or Compromised"
                fDict[0] = ""
            riskUtilDict[0] = 0
        else:
            downOrCompromisedUtils = downOrCompromisedFunctions.answers
            if debug:
                print "Down or Compromised Utilities:"
                print downOrCompromisedUtils
                #fDict[0] =
            for [f,u] in downOrCompromisedUtils:
                downOrCompUtil += u
            riskUtilDict[0] = downOrCompUtil


        for funcUtilRisk in costsPlusSortedLimited: #Limited to just ones starting from specific compromises
            #u is the questionable utility, not the residual utility
            if debug:
                f = funcUtilRisk[4]
            u = funcUtilRisk[5]
            r = funcUtilRisk[6]
            if r in riskUtilDict:
                #If this is a new worst case scenario for that level of attacker capability
                if u > riskUtilDict[r]:
                    riskUtilDict[r] = u
                    if debug:
                        fDict[r] = f
            #This is the first time seeing this level of risk
            else:
                riskUtilDict[r] = u
                if debug:
                    fDict[r] = f
        if debug:
            print "Worst case scenarios by attacker capability:"
            print riskUtilDict
            print fDict
            riskUtilDictAdjusted = {}

        sum = 0
        worstQuestionableU = downOrCompUtil #To track the worst case so far
        for r in range(0,maxRisk+1):
            if r in riskUtilDict:
                questionableU = riskUtilDict[r]
                if questionableU > worstQuestionableU:
                    worstQuestionableU = questionableU
            if debug:
                riskUtilDictAdjusted[r] = worstQuestionableU

            #Adjust the compromised components here to reflect the particular
            #combination under evaluation


            sum += (maxUtility - worstQuestionableU) * riskDistribution.probabilityOfRisk(r)
        #print("Residual utility: " + str(sum))
        if debug:
            print "Adjusted worst case scenarios:"
            print riskUtilDictAdjusted
            print "Sum: " + str(sum)
            print "Prob: " + str(prob)
        sumOverCombos += sum * prob

        #New code to put back in compromised components for next loop iteration
        for cc in compromisedAllPossible:
            if cc[0] not in compromisedComponents:
                if debug:
                    print "Add back " + str(cc[0])
                pyDatalog.assert_fact("compromised",str(cc[0]))
        #End new code
    if debug:
        print "Residual Utility:"
    #print sumOverCombos
    return sumOverCombos


#Define Tactics

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
#Changed
connectionsAnswer = pyDatalog.ask('networkConnectsToWithAttributes(ServiceA,ServiceB,COK,IOK,AOK)')
if connectionsAnswer == None:
    connections = []
else:
    connections = connectionsAnswer.answers
#connections = pyDatalog.ask('networkConnectsTo(ServiceA,ServiceB)').answers
# if bidirectional: #remove reversed connections so there are no duplicates
#     connectionsNoDuplicates = []
#     for connection in connections:
#         if tuple([connectionPair[1],connectionPair[0]]) in connections:

#firewalls = pyDatalog.ask('isType(ServiceA,firewallType)')
#print firewalls.answers

#print("Network Connections" + str(connections))

def connectionDoesNotExist(connectionPair):
    #print("Connection pair: " + str(connectionPair))
    if connectionPair in connections:
        #print "False"
        return False
    else:
        if bidirectional==True:
            if tuple([connectionPair[1],connectionPair[0]]) in connections: #should always eval to false because if the connection pair is in, it's reversed connection should also be in
                #print("Compared to: " + str(tuple([connectionPair[1],connectionPair[0]])))
                #print "Duplicate"
                return False
            else:
                #print("Compared to: " + str(tuple([connectionPair[1],connectionPair[0]])))
                #print "True-Bidirectional"
                return True
        else:
            print "True"
            return True

def createAddConnectionTactic(connectionPair):
    #Changed
    t = ["assert","networkConnectsToWithAttributes",connectionPair[0],connectionPair[1],True,True,True]
    return t

#TODO: Make generic tactic iters
#This only adds to iter if connection doesn't already exist and maybe if both source and target
#are internal to oranization
#For bidirectional connections, a connection is included once
#So just A,B and not B,A
def createAddNetworkConnectionIter(debug=False):
    #get list of services
    vcToAnswers = pyDatalog.ask("validNewConnectsTo(ServiceA,ServiceB)").answers
    vcToList = []
    for answer in vcToAnswers:
        vcToList.append(answer)
    print(len(vcToList))
    if debug:
        print("Valid Connects To: " + str(vcToList))
    #servicesAnswers = pyDatalog.ask("isAccount(ServiceA,'userAccount')").answers
    #servicesList = []
    #for answer in servicesAnswers:
    #    servicesList.append(answer[0])
    #print("Services: " + str(servicesList))
    #networkDeviceAnswers = pyDatalog.ask("isType(ServiceA,'networkDevice')").answers
    #networkDeviceList = []
    #for answer in networkDeviceAnswers:
    #    networkDeviceList.append(answer[0])
    #print("Network Devices: " + str(networkDeviceList))
    #get permutations of two services
    #if bidirectional:
        #for bidirectional connections, no repeats like A,B and B,A:
    #    allPossibleConnections = itertools.product(networkDeviceList,servicesList)
    #    allPossibleConnections = itertools.ifilter(lambda x:x[0] != x[1],allPossibleConnections)
    #    allPossibleConnectionsList = list(allPossibleConnections)
    #    print(len(allPossibleConnectionsList))
    #    print "Possible Valid Connections: " + str(allPossibleConnectionsList)
    #    print "Difference: " + str(list(set(allPossibleConnectionsList)-set(vcToList)))
    #else:
    #    allPossibleConnections1 = itertools.product(networkDeviceList,servicesList)
    #    allPossibleConnections1 = itertools.ifilter(lambda x:x[0] != x[1],allPossibleConnections1)
    #    allPossibleConnections2 = itertools.product(networkDeviceList,servicesList)
    #    allPossibleConnections2 = itertools.ifilter(lambda x:x[0] != x[1],allPossibleConnections2)
    #    allPossibleConnections = itertools.chain(allPossibleConnections1,allPossibleConnections2)

    #if bidirectional:
        #for bidirectional connections, no repeats like A,B and B,A:
    #    allPossibleConnections = itertools.combinations(servicesList,2)
    #else:
    #    #for directional connections:
    #    allPossibleConnections = itertools.permutations(servicesList,2)

    #remove permutations that represent services that are already directly connected
    #possibleConnections = itertools.ifilter(lambda connectionPair: connectionDoesNotExist(connectionPair),allPossibleConnections)
    possibleConnectionsTactics = itertools.imap(createAddConnectionTactic,vcToList)
    #print("Available new connections" + str(list(possibleConnectionsTactics)))
    return possibleConnectionsTactics

#For bidirectional connections, a connection is included once
#So just A,B and not B,A
def createCutNetworkConnectionIter():
    connectionIter = []
    for connection in connections:
        #Changed
        c = ["retract","networkConnectsTo",connection[0],connection[1],connection[2],connection[3],connection[4]]
        #print c
        if bidirectional: #append c only if it is not a duplicate of a reversed connection
            #TODO Is this a safe assumption that the reversed connection has the same CIA properties?
            cReversed = ["retract","networkConnectsTo",connection[1],connection[0],connection[2],connection[3],connection[4]]
            if cReversed not in connectionIter:
                connectionIter.append(c)
        else:
            connectionIter.append(c)
    return iter(connectionIter)

def insertFirewallIter():
    tacticsSetsIter = []
    getService = itemgetter(0)
    firewallsList = map(getService,firewalls.answers)
    connectionCombos = itertools.combinations(connections,len(firewallsList))
    for connectionCombo in connectionCombos:
        tacticSet = []
        fwNum = 0
        for connection in connectionCombo:
            tacticSet.append(["retract","networkConnectsTo",connection[0],connection[1]])
            tacticSet.append()
            #print c
        tacticsSetsIter.append(c)
    return iter(tacticsSetsIter)

def tacticsIter():
    #return createCutNetworkConnectionIter()
    #return createAddNetworkConnectionIter()
    #return createAddNetworkConnectionIter()
    return itertools.chain(createAddNetworkConnectionIter(),createCutNetworkConnectionIter())

#This is the tactic format:
#['retract', 'connectsTo', 'paymentServer', 'host1']

def createAttackScenarioLogic(currentAttackScenario):
    #for currentAttackScenario in attackScenarios:
        #Clear all vulnerabilities and add only those for a specific attack
        Logic()
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


def bestOptions(utilities):
    #print utilities
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
    #print("Best Tactics Options: " + str(bestTacticsSets))
    for ts in bestTacticsSets:
        print "************"
        print str(ts)




def tryTacticOptions(maxTactics,debug=False):
    #Initialize utilities dictionary for each of the tactic options
    utilities = {}
    #if debug:
    #bestUtility = float(0)
    originalUtil = float(determineResidualUtility())
    bestUtility = originalUtil
    print("Original utility: " + str(originalUtil))
    utilities[""] = originalUtil

    #For progress tracking
    numOptions = 0
    for numTactics in range(1,maxTactics+1):
        numOptions += len(list(itertools.combinations(tacticsIter(),numTactics)))
        #TODO? Put following line back in
        #utilities[None] = float(determineResidualUtility())

    setNumber = 0

    print("Tactic options: " + str(numOptions))
    #TODO Extra double-check to ensure logic is correct here...should be all possible vulnerabilities
    #TODO Also try zero tactics! Maybe current config is the best
    for numTactics in range(1,maxTactics+1):
        #Creator iterator of tactic sets to try
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
            #Apply the tactics in the selected tactic set
            for tactic in tacticSet:
                #print tactic
                args = tactic[1:]
                if tactic[0] == "retract":
                    pyDatalog.retract_fact(*args)
                    if bidirectional:
                        if tactic[1] == "networkConnectsTo": #retract the symmetric connection
                            #TODO Did we already do this in the code above? Is it a safe assumption that the reversed connection has the same CIA attributes?
                            #Changed
                            argsRev = [args[0],args[2],args[1],args[3],args[4],args[5]]
                            pyDatalog.retract_fact(*argsRev)
                else:
                    pyDatalog.assert_fact(*args)
            #Determine utility and put in dictionary
            #This weighted value includes cost of tactic: A cost of 1 per tactic
            tsStr = str(sorted(list(tacticSet))) #key
            residualUtil = float(determineResidualUtility() - numTactics) #value
            if debug and residualUtil>=bestUtility:
                print("New optimal: " + str(residualUtil) + str(tacticSet))
                bestUtility = residualUtil
            #TODO The check for multiple tactics may not be necessary in some versions of this code
            if tsStr in utilities:
                #print("MULTIPLE: " + tsStr + ": " + str(residualUtil))
                if residualUtil < utilities[tsStr]:
                    utilities[tsStr] = residualUtil
            else:
                utilities[tsStr] = residualUtil
            #Undo the tactic application
            for tactic in tacticSet:
                args = tactic[1:]
                if tactic[0] == "assert":
                    pyDatalog.retract_fact(*args)
                    #Changed
                    #TODO Is this a safe assumption that the reversed connection has the same CIA attributes?
                    if (tactic[1] == "networkConnectsToWithAttributes") and (bidirectional == True):
                        pyDatalog.retract_fact(args[0],args[2],args[1],args[3],args[4],args[5])
                else:
                    pyDatalog.assert_fact(*args)
    #pprint.pprint(utilities)
    #Find the best performing tactic set in the dictionary created earlier
    bestOptions(utilities)

#NOTE: Tactics should be applied only if they are not redundant
#For example, don't apply the same tactic twice, and don't apply
#a tactic like cutting a network connection when the connection
#doesn't exist. Otherwise, this will mess up the reversal of the
#tactics






#Additional Code for Later:
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

def addAllPossibleConnections():
    #get list of services
    servicesAnswers = pyDatalog.ask("isAccount(ServiceA,'userAccount')").answers
    servicesList = []
    for answer in servicesAnswers:
        servicesList.append(answer[0])
    #get permutations of two services
    allPossibleConnections = itertools.permutations(servicesList,2)
    #TODO remove permutations that represent services that are already directly connected
    #possibleConnections = itertools.ifilter(lambda connectionPair: connectionDoesNotExist(connectionPair),allPossibleConnections)
    #possibleConnectionsTactics = itertools.imap(createAddConnectionTactic,possibleConnections)
    #print("Available new connections" + str(list(possibleConnectionsTactics)))
    for c in allPossibleConnections:
        pyDatalog.assert_fact("networkConnectsTo",c[0],c[1])


            # #REMOVING THIS TO TEST
            # #Check for attacks
            # attackScenarios = getAttackScenarios()
            # #Find the cost of all the attacks
            # #costList includes all attacks, including maybe those above the risk threshold
            # costList = []
            # for attackScenario in attackScenarios:
            #     #print attackScenario
            #     costList.append(attackScenario[2])
            # sortedCosts = sorted(costList)
            # #Determine relatively likelihood of each attack
            # #I.e., the assumption is that easier attacks are more likely
            # attackLikelihoods = []
            # top = riskDistribution.maxRisk() + 1
            # #For all attack costs in the riskPDF
            # for r in range(0,top):
            #     costsUnderThisRisk = []
            #     inverseWeightedCosts = []
            #     inverseCostSum = float(0)
            #     for c in sortedCosts:
            #         if c <= r:
            #             costsUnderThisRisk.append(c)
            #             inverseCostSum += (1/float(c))
            #     for c in costsUnderThisRisk:
            #         inverseWeightedCosts.append([c,1/(c * inverseCostSum)])
            #     attackLikelihoods.append([r,riskDistribution.probabilityOfRisk(r), inverseWeightedCosts])
            # #print attackLikelihoods
            # # Determine the likelihood of an attack given a particular cost/risk value
            # #This dictionary looks up the overall likelihood of an attack given a cost
            # #It's based on the cost of the attack and the riskPDF
            # attackLikelihoodDict = {}
            # for r in range(0,top):
            #     attackLikelihoodDict[r] = float(0)
            # for riskLevel in attackLikelihoods:
            #     r = riskLevel[0]
            #     probabilityOfRisk = riskLevel[1]
            #     scenarios = riskLevel[2]
            #     lastR = -1
            #     for scenario in scenarios:
            #         #Don't repeat dictionary inclusion for a given attack risk/cost
            #         scenarioRisk = scenario[0]
            #         if scenarioRisk != lastR:
            #             attackLikelihoodDict[scenarioRisk] += (scenario[1] * probabilityOfRisk)
            #         lastR = scenarioRisk
            # #print attackLikelihoodDict
            # #print("Attack Scenarios: " + str(len(attackScenarios)))
            # #END REMOVAL TEST

MaxRisk=4
def printConnections(debug=True):
    #transitiveConnectsWithAttributesPathForFunction()
    #paths = pyDatalog.ask("transitiveConnectsWithAttributesOnPath(SourceService,TargetService,CProvided,IProvided,AProvided,P)").answers
    #paths = pyDatalog.ask("transitiveConnectsWithAttributesOnPath('opc','rtus',CProvided,IProvided,AProvided,P)").answers
    #BUG
    #paths = pyDatalog.ask("consumesDataWithAttributesNoAlternative(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P)").answers
    #paths = pyDatalog.ask("functionDownOrCompromised(FunctionA,U)").answers
    #paths = pyDatalog.ask("someCompromised(P)").answers
    #paths = pyDatalog.ask("allCompromised[P]").answers
    #paths = pyDatalog.ask("attackPaths(SourceService,TargetService,P,E,C," + str(3) + ")").answers
    #paths = pyDatalog.ask("attackPaths(SourceService,TargetService,P,E,C,4)").answers
    #MaxR = 4
    #query = "requires(FuncName,'relayLouie')"
    #query = "pathCompromisesFunctionWithCost(X,FuncName,Util,2)"
    #query = "pathCompromisesUtilities[X]==Y"
    #query = "pathCompromisesWithCost(X,2)"
    #query = "pathCompromisesFunctions[X]==Y"
    #query = "worstCasePathValue[3]==UtilPathPair"
    query = "weightedWorstCasePath[X]==Y"
    #query = "estimatedUtility[X]==Y"
    #query = "worstCasePathFromSource[X,Y]==Z"
    #query = "compromisedCombo(X)"
    #query = "probCapability[X]==Y"
    #query = "worstCasePathValue[X]==Y"
    #query = "attackPaths(SourceService,TargetService,P,E,C)"

    paths = pyDatalog.ask(query).answers
    #print(paths)


    if debug:
        print "Paths calculated."
        if paths != None:
            pprint.pprint(paths)
            print("Number of items: " + str(len(paths)))
        else:
            print "No paths found"

    #if debug:
    #    print "Query: " + "allAttackerPathsCostPlus(SourceService,TargetService,P,E,F,U,TotalC," + str(rMax) + ")"
    #costsPlus = pyDatalog.ask("allAttackerPathsCostPlus(SourceService,TargetService,P,E,F,U,TotalC," + str(1) + ")")
    #pprint.pprint(paths.answers)
        #costsPlusSorted = sorted(costsPlus.answers, key=itemgetter(5))
        #if debug:
            #print "No attack traces"
    #else:
    #    costsPlusSorted = []
    #    if debug:
    #        print "Attack traces:"
    #        pprint.pprint(costsPlusSorted)

start = time.time()
#tryTacticOptions(1)
#tryTacticOptions(3,True)
#getAttackScenarios()

#print determineResidualUtility(True)
printConnections()
end = time.time()
print(end - start)
