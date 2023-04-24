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
import csv

#This is the risk metric
Logic()
pyDatalog.create_terms('connectsTo,residesOn,runs,TargetHost,SourceHost,DestHost,TargetService,SourceService,compromised,connectsToWithPrivileges,questionableWithinRisk,functionQuestionableWithinRisk','allAttackerPathsCostPlus','F','F2','FuncName','U','U2','Util','allAttackerPathsCostPlus','SS','TS','IS1','functionDown','functionalityFree','Prob')
pyDatalog.create_terms('cTo,cToWithPrivileges,ServiceA,ServiceB,HostA,HostB,localRootExploit,remoteRootExploit,attackerConnectsTo,attackerReachable')
pyDatalog.create_terms('allPaths,allAttackerPaths,P,P2,P3,IntermediateService1,attackerCanReachOneStep,ok,attackerCanReachTwoSteps,oneStepToBadness,twoStepsToBadness','shortestAttackerPathsPlus')
pyDatalog.create_terms('requires,Task,Hostname','remoteUserExploit','vulnExists','RiskForFunction','MaxR','OtherService','functionDownOrCompromised','probCompromised')
pyDatalog.create_terms('cutConnection','VulnType','isAccount','C','C2','cost','TotalC','TotalC2','E','E2','E3','notConnectsTo','notResidesOn','notCompromised','notRemoteUserExploit','notRemoteRootExploit','notLocalRootExploit''a','b','c','suspicious','t1','t2','t3','t4','t5','TacticNumber','moveHostTo','transitiveConnects','transitiveConnectsSecure')
pyDatalog.create_terms('TestA','TestB','utility','FunctionA','resultingUtil','functionCompromised','functionUncompromised','FuncAUtil','allConnectionPaths','questionable','functionQuestionable','U','requiresConnection','networkConnectsTo','adHost','missingConnection','isType','allAttackerPathsWithTyping','ExploitAndTarget','ExploitAndTarget2','TargetType','questionableAtRisk','allAttackerPathsPlus','functionQuestionableWithinRiskPlus')
pyDatalog.create_terms('Functionality','Attribute','Data','Service','Impact','requiresSecurityAttribute','FunctionB','FunctionC','functionRequires','implements','implementedF','requiresAllConnections')
pyDatalog.create_terms('isType','validNewConnectsTo')
pyDatalog.create_terms('vulnExistsWithAttributes','remoteRootExploitWithAttributes','componentCompromisedWithAttributes','functionCompromisedWithAttributes')
pyDatalog.create_terms('requiresSecurityAttribute','consumesDataWithAttributes','transitiveConnectsWithAttributes','producesData','requiresDataWithAttributes','COK','IOK','AOK','CRequired','IRequired','ARequired','CImpact','IImpact','AImpact','CImpact2','IImpact2','AImpact2','CImpact3','IImpact3','AImpact3','CImpact4','IImpact4','AImpact4')
pyDatalog.create_terms('CProvided','IProvided','AProvided','CProvided1','IProvided1','AProvided1','CProvided2','IProvided2','AProvided2','connectsToWithAttributes','consumesData','networkConnectsToWithAttributes','requiresFunction','transitiveConnectsWithAttributesOnPath')
pyDatalog.create_terms('consumesDataWithC','consumesDataWithI','consumesDataWithA','consumesDataWithAttributeProblems','consumesDataWithAttributesNoAlternative','allCompromised','someCompromised','attackPaths','pathCompromisesFunctionWithCost','pathCompromisesService')
pyDatalog.create_terms('isPath','X','Y','Z','pathCompromisesUtilities','pathCompromisesWithCost','worstCasePath','UtilPathPair','pathCompromisesFunctions','FList','worstCasePathValue','weightedWorstCasePath','probCapability','estimatedUtility','worstCasePathFromSource','SourceCost','compromisedCombo','worstCasePathUtil')
pyDatalog.create_terms('consumesDataOnlyGoodPath','noIdealConsumption','transitiveConnectsWithAttributesOnPathUnderAttack','consumesDataWithCUnderAttack','consumesDataWithIUnderAttack','consumesDataWithAUnderAttack','consumesDataWithAttributesUnderAttack','UMod')
pyDatalog.create_terms('consumeseDataWithModifiedUtilityUnderAttack','PC','PC2','PC3','PC4','isSubType','isTypeOrSubType','isTypeOrSuperType','ComponentType','isVulnerable','existsExploit','Paths','Paths2','Exploits','AttackerMove','AttackerMoves','hasCredential','transitiveConnectsPath','consumesPath')
pyDatalog.create_terms('pathsConflict','pathsDontConflict','set','isdisjoint','intersection','attackPathDoesntCompromiseFlow','AP','DFP','consumesPathCompromised','numConsumesPaths','numConsumesPathsCompromised','concatConsumesPathsCompromised','defineComponentWithExploit','worstCasePaths')
pyDatalog.create_terms('worstCasePathSpecific','worstCasePathCombo','Combo','usesCredential','Credential','residualUtility','worstCasePathUtilInclusive','CompromiseSet','CompromiseSet2','APSet','APSet2','attackScenario','CumulativeP','CumulativeP2','CurrentP','CurrentP2')
pyDatalog.create_terms('hasCredentials','CredentialSet','SourceService2','SourceService3','TargetService2','TargetService3','Leaves','Leaves2','Leaves3','ConsumesSet','bestConsumesPath','CP','transitiveConnectsUnderAttack','consumesPathUnderAttack','AS','AS2','AS3','attackScenarioPiece','consumesAttackOverlap')

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
        for k,v in self.pdfDict.items():
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
    def items(self):
        return list(self.pdfDict.items())

#dict([(riskValue1,riskProbabilty1)...])
#riskDistribution = RiskPDF(dict([(0,0.30),(1,0.40),(2,0.20),(3,0.10)]))
#riskDistribution = RiskPDF(dict([(0,0.60),(1,0.30),(2,0.05),(3,0.05)]))
#Use below for network architecture baseline
#riskDistribution = RiskPDF(dict([(0,0.10),(1,0.10),(2,0.20),(3,0.60)]))
#Use below for satellite baseline
#riskDistribution = RiskPDF(dict([(0,0.30),(1,0.50),(2,0.20),(3,0.00)]))
#Use below for Spectre Simple
#riskDistribution = RiskPDF(dict([(0,0.20),(1,0.20),(2,0.20),(3,0.20),(4,0.20)])) #Paper default
#riskDistribution = RiskPDF(dict([(0,0.60),(1,0.30),(2,0.08),(3,0.01),(4,0.01)])) #Paper less sophisticated
#riskDistribution = RiskPDF(dict([(0,0.01),(1,0.01),(2,0.08),(3,0.30),(4,0.60)])) #Paper more sophisticated
#riskDict = dict([(0,0.01),(1,0.01),(2,0.08),(3,0.30),(4,0.60)])
#riskDict = dict([(0,1.0)])
#test A

#riskDistribution = RiskPDF(dict([(0,0.00),(1,0.50),(2,0.20),(3,0.30)]))


#riskDistribution = RiskPDF(dict([(0,0.0),(1,1.0),(2,0.0),(3,0.00)]))
#riskDistribution = RiskPDF(dict([(0,0.0),(1,0.0),(2,0.0),(3,0.0),(4,1.0)]))
#riskDistribution = RiskPDF(dict([(0,0.20),(1,0.30),(2,0.30),(3,0.15),(4,0.05)]))
#riskDistribution = RiskPDF(dict([(0,0.30),(1,0.60),(2,0.05),(3,0.05)]))



#riskDistribution = RiskPDF(dict([(0,0.001),(1,1.0),(2,0.0),(3,0.0)]))
#maxRisk = riskDistribution.maxRisk()
bidirectional = True
#instanceFile = "banks.py"
#instanceFile = "multi-subnet.py"
#instanceFile = "icsArchInstance.py"
#instanceFile = "architectureInstance.py"
#instanceFile = "tiers-test1.py"
#instanceFile = "spectre-simple.py"
#instanceFile = "spectre-system.py"
#instanceFile = "fw-test1.py"
#instanceFile = "dhs-abstracted-tiers.py"

#Logic for Below Cases
#def providesBoth(provided1,provided2):
#    return provided1 and provided2

def setup(instanceFile):
    pyDatalog.load(open(instanceFile,"r").read())
    #Rules for the Architectural Style
    pyDatalog.load(open("architectureStyle.py","r").read())
    #Rules for Vulnerabilities (Architectural Style)
    pyDatalog.load(open("vulnerabilityStyle.py","r").read())
    #Rules for Functionalities
    pyDatalog.load(open("functionalStyle.py","r").read())
    #Make sure every component has every plausible vulnerability
    #pyDatalog.load(open("applyAllVulnerabilities.py","r").read())

#Save this for later
def createEnvironment(instanceFile):
    setup(instanceFile)
    noVulnLogic = Logic(True)
    Logic()
    setup(instanceFile)



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

#maxUtility = sumAllUtilities()

def calculateProb(compromiseProbability,allCompromisedComponents):
    p = 1
    cList = []
    #print "cp: " + str(compromiseProbability)
    #print "acc: " + str(allCompromisedComponents)
    for component,prob in compromiseProbability:
        cList.append(component)
        p = p * prob
    return tuple([cList,p])


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
                print("c:" + str(c))
            for comp,p in c: #compromised component, probability of compromise
                #print "comp,p:" + str(comp) + "||" + str(p)
                cList.append([comp,p])
                cc.append(comp)
            combosList.append(cList)
            comboComponents.append(cc)

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
    if debug:
        for c in componentCombinations:
            print("Combination " + str(c))
    return componentCombinations

def compromisedCombos(compList,debug=False):
    combos = iter([])
    combosList = [] # [[['internet', 0.99]], [['tepper', 0.1]], [['internet', 0.99], ['tepper', 0.1]]]
    comboComponents = [] # [['internet'], ['tepper'], ['internet', 'tepper']]
    print("Compromised Components: " + str(compList))
    for i in range(1,len(compList)+1):
        #combos = itertools.chain(combos,itertools.combinations(compromisedComponents,i))
        #print "i: " + str(list(itertools.combinations(compromisedComponents,i)))
        newCombos = itertools.combinations(compList,i)
        for c in newCombos:
            cList = []
            cc = []
            if debug:
                print("c:" + str(c))
            for comp,p in c: #compromised component, probability of compromise
                #print "comp,p:" + str(comp) + "||" + str(p)
                cList.append([comp,p])
                cc.append(comp)
            combosList.append(cList)
            comboComponents.append(cc)
    # [[['internet', 0.99]], [['tepper', 0.1]], [['internet', 0.99], ['tepper', 0.1]]]
    #print "Combos List Complete: " + str(combosList)
    #print "Combos List Components: " + str(comboComponents)
    if debug:
        print("comboComponents:" + str(comboComponents))
    componentCombinations = []
    noCompromiseProb = float(1) # for tracking the probability that nothing is compromised
    for combo in combosList: # combo: [['internet', 0.99], ['tepper', 0.1]]
        if debug:
            print("combo:" + str(combo))
        p = float(1)
        components = []
        for cp in compList: # ['internet', 0.99]
            if debug:
                print("cp:" + str(cp))
            if list(cp) in combo:
                if debug:
                    print("In" + str(list(cp)) + "||" + str(combo))
                p = p * cp[1]
                components.append(cp[0])
            else:
                if debug:
                    print("Out" + str(list(cp)) + "||" + str(combo))
                p = p * (1 - cp[1])
        #print components
        #print p
        noCompromiseProb -= p
        componentCombinations.append([components,p])
    #print "No compromise prob: "
    #print noCompromiseProb
    componentCombinations.append([[],noCompromiseProb])
    if debug:
        for c in componentCombinations:
            print("Combination " + str(c))
    return componentCombinations

#Assumptions: capability ranges from 0 to MaxR (inclusive)
def addRisksToLogic(rD):
    riskStr = ""
    maxR = 0
    totalProb = float(0)
    #print(rD.items())
    for cap, prob in list(rD.items()):
        #pyDatalog.assert_fact(pC(cap,prob))
        #MaxR?
        #probCapability[cap] = prob
        print("probCapability[" + str(cap) + "] = " + str(prob) + "\n")
        riskStr += "probCapability[" + str(cap) + "] = " + str(prob) + "\n"
        if cap > maxR:
            maxR = cap
        totalProb += prob
    #print("MaxR=" + str(maxR) + "\n")
    riskStr += "MaxR=" + str(maxR) + "\n"
    #if totalProb != 1.00:
    #    print("FAIL: Probabilities add to " + str(totalProb))
    #else:
        #print("OK: Probabilities add to 1.00")
    pyDatalog.load(riskStr)
    return maxR

def determineResidualUtility(compromisedComponents,rD,debug=True):
    rMax = addRisksToLogic(rD)
    maxUtility = sumAllUtilities()
    print(("Maximum Utility with No Vulnerabilities: " + str(sumAllUtilities())))
    #query = "worstCasePathFromSource[SourceService,TotalC]"
    #utilitiesByAttackerCapability = pyDatalog.ask(query).answers
    combos = compromisedCombos(compromisedComponents)
    expectedValue = 0
    for combo,p in combos:
        print("Evaluating compromise combination:" + str(combo))
        for ccs in combo: #ccs is the component stripped out of the list
            #print "ccs:" + str(ccs)
            #Add in compromised components to logic
            #+ componentCompromisedWithAttributes('vpn',0.1,False,False,False)
            pyDatalog.assert_fact("compromised",str(ccs),str(p),"False","False","False")
        if debug:
            print("Probability for this combination: " + str(p))
            #query = "cToWithPrivileges(IntermediateService1,TargetService,VulnType,C)"
            #print("Connections in Graph:")
            #pprint.pprint(pyDatalog.ask(query).answers)
            #print("Probability for this combination: " + str(p))
            #query = "consumesPath(FunctionA,TargetService,Data,P)"
            #print("Consumption Paths in Graph:")
            #pprint.pprint(pyDatalog.ask(query).answers)
        expectedValue += determineResidualUtilityHelper(rD,maxUtility) * p
        for ccs in combo:
            #Remove compromised components from logic
            pyDatalog.retract_fact("componentCompromisedWithAttributes",str(ccs),str(p),"False","False","False")
    print("Final Expected Value:" + str(expectedValue))
    return expectedValue

#Do this for each combo of compromises
def oldDetermineResidualUtilityHelper(rD,maxUtility,debug=True):
    rMax = addRisksToLogic(rD)
    #rMax = 4
    query = "weightedWorstCasePath[X]==Y"
    utilitiesByAttackerCapabilityAnswers = pyDatalog.ask(query)
    if utilitiesByAttackerCapabilityAnswers != None:
        utilitiesByAttackerCapability = utilitiesByAttackerCapabilityAnswers.answers
    estimatedValue = 0
    #if debug:
        #print "Attacks calculated."
    if utilitiesByAttackerCapabilityAnswers != None:
        if debug:
            print("Utilities compromised by attacker capability:")
            #pprint.pprint(utilitiesByAttackerCapability)
            #if len(utilitiesByAttackerCapability) > 0:
            pprint.pprint(sorted(utilitiesByAttackerCapability,key=itemgetter(0)))

            #else:
            #    print("None")
            #print("Number of items: " + str(len(utilitiesByAttackerCapability)))
        capabilityUtilDict = dict(utilitiesByAttackerCapability)
        for capability in range(rMax+1):
            query2 = "worstCasePath[" + str(capability) + "] == X"
            wCPsAnswers = pyDatalog.ask(query2)
            if wCPsAnswers != None:
                wCPs = wCPsAnswers.answers
                #print "************"
                print("Worst case paths by attacker capability " + str(capability) + ": ")
                pprint.pprint(str(wCPs))
            if capability in capabilityUtilDict:
                #print riskDistribution[int(capability)]
                #print str(riskDistribution.probabilityOfRisk(capability)) + " * " + str(capabilityUtilDict[capability])
                #estimatedValue += riskDistribution.probabilityOfRisk(capability) * capabilityUtilDict[capability]
                estimatedValue += capabilityUtilDict[capability] #Changed because the weighting is done in Datalog

            else:
                print("Error: Attack traces for capability " + str(capability) + " not calculated")
    estimatedValue = maxUtility - estimatedValue
    if debug:
        print("Single Scenario Expected Value: " + str(estimatedValue))
    return estimatedValue

    #Do this for each combo of compromises
def determineResidualUtilityHelper(rD,maxUtility,debug=True):
    rMax = addRisksToLogic(rD)
    #rMax = 4
    for c,p in rD.items():
        s = "probCapability[" + str(c) + "] = " + str(p)
        pyDatalog.load(s)
    query = "weightedWorstCasePath[X]==Y"
    utilitiesByAttackerCapabilityAnswers = pyDatalog.ask(query)
    if utilitiesByAttackerCapabilityAnswers != None:
        utilitiesByAttackerCapability = utilitiesByAttackerCapabilityAnswers.answers
    estimatedValue = 0
    if debug:
        print("Attacks calculated.")
    if utilitiesByAttackerCapabilityAnswers != None:
        if debug:
            print("Utilities compromised by attacker capability:")
            #pprint.pprint(utilitiesByAttackerCapability)
            if len(utilitiesByAttackerCapability) > 0:
                pprint.pprint(sorted(utilitiesByAttackerCapability,key=itemgetter(0)))
            else:
                print("None")
            #print("Number of items: " + str(len(utilitiesByAttackerCapability)))
        estimatedValue = sum(map(itemgetter(1),utilitiesByAttackerCapability))

        #for capability in range(rMax+1):
            #query2 = "worstCasePath[" + str(capability) + "] == X"
            #wCPsAnswers = pyDatalog.ask(query2)
            #if wCPsAnswers != None:
                #wCPs = wCPsAnswers.answers
                #print "************"
                #print("Worst case paths by attacker capability " + str(capability) + ": ")
                #pprint.pprint(str(wCPs))
    estimatedValue = maxUtility - estimatedValue
    if debug:
        print("Single Scenario Expected Value: " + str(estimatedValue))
    return estimatedValue

def determineResidualUtilityOnceTest(rD,query="",debug=True):
    rMax = addRisksToLogic(rD)
    maxUtility = sumAllUtilities()
    #rMax = 4
    for c,p in rD.items():
        s = "probCapability[" + str(c) + "] = " + str(p)
        pyDatalog.load(s)
    #This needs to change
    if query == "":
        query = "attackPaths(SourceService,TargetService,P,E,AttackerMoves,TotalC)"
    #query = "worstCasePath[\"3\"] == Y"
    #query = "worstCasePath[TotalC] == Y"
    #query = "worstCasePathCombo[X,Combo] == Y"
    #query = "worstCasePathCombo[" + str(3) + ",[businessWorkstations]" + "] == Y"
    print("Query: " + query)
    #query = "worstCasePathSpecific[X,SourceService]==Y"
    utilitiesByAttackerCapabilityAnswers = pyDatalog.ask(query)
    if utilitiesByAttackerCapabilityAnswers != None:
        utilitiesByAttackerCapability = utilitiesByAttackerCapabilityAnswers.answers
    estimatedValue = 0
    if debug:
        print("Query calculated.")
    if utilitiesByAttackerCapabilityAnswers != None:
        if debug:
            print("Query Answers:")
            #print("Utilities compromised by attacker capability:")
            #pprint.pprint(utilitiesByAttackerCapability)
            if len(utilitiesByAttackerCapability) > 0:
                #print(sorted(utilitiesByAttackerCapability,key=itemgetter(0)))
                pprint.pprint(sorted(utilitiesByAttackerCapability,key=itemgetter(0)))
            else:
                print("No answers")
            #print("Number of items: " + str(len(utilitiesByAttackerCapability)))
        #Undo highlight later
        #estimatedValue = sum(map(itemgetter(1),utilitiesByAttackerCapability))

        #for capability in range(rMax+1):
            #query2 = "worstCasePath[" + str(capability) + "] == X"
            #wCPsAnswers = pyDatalog.ask(query2)
            #if wCPsAnswers != None:
                #wCPs = wCPsAnswers.answers
                #print "************"
                #print("Worst case paths by attacker capability " + str(capability) + ": ")
                #pprint.pprint(str(wCPs))
    
    #Undo highlight later
    #estimatedValue = maxUtility - estimatedValue
    #if debug:
    #    print("Single Scenario Expected Value: " + str(estimatedValue))
    return estimatedValue

def tryOptions():
    # for options
    return 0

#Define Tactics

def cutNetworkConnection(ServiceA, ServiceB,CProvided,IProvided,AProvided):
    pyDatalog.retract_fact("networkConnectsTo",ServiceA,ServiceB,CProvided,IProvided,AProvided)

def moveService(ServiceA,HostA,HostB):
    pyDatalog.retract_fact(residesOn,ServiceA,HostA)
    pyDatalog.assert_fact(residesOn,HostB)

def mitigate(ServiceA):
    pyDatalog.retract_fact(compromised,ServiceA)


#Search:
#Find connections to cut:
#Does this need to be refreshed?
#Changed
def connectionsAnswer():
    connectionsAnswer = pyDatalog.ask('networkConnectsTo(ServiceA,ServiceB,COK,IOK,AOK)')
    if connectionsAnswer == None:
        connections = []
    else:
        connections = connectionsAnswer.answers
    return connections
#connections = pyDatalog.ask('networkConnectsTo(ServiceA,ServiceB)').answers
# if bidirectional: #remove reversed connections so there are no duplicates
#     connectionsNoDuplicates = []
#     for connection in connections:
#         if tuple([connectionPair[1],connectionPair[0]]) in connections:

#firewalls = pyDatalog.ask('isType(ServiceA,firewallType)')
#print firewalls.answers

#print("Network Connections" + str(connections))

def connectionDoesNotExist(connectionPair):
    connections = connectionsAnswer()
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
            print("True")
            return True

def createAddConnectionTactic(connectionPair):
    #Changed
    t = ["assert","networkConnectsTo",connectionPair[0],connectionPair[1],True,True,True]
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
    print((len(vcToList)))
    if debug:
        print(("Valid Connects To: " + str(vcToList)))
    
    #remove permutations that represent services that are already directly connected
    #possibleConnections = itertools.ifilter(lambda connectionPair: connectionDoesNotExist(connectionPair),allPossibleConnections)
    possibleConnectionsTactics = map(createAddConnectionTactic,vcToList)
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
    firewallsList = list(map(getService,firewalls.answers))
    connectionCombos = itertools.combinations(connections,len(firewallsList))
    for connectionCombo in connectionCombos:
        tacticSet = []
        fwNum = 0
        for connection in connectionCombo:
            tacticSet.append(["retract","networkConnectsTo",connection[0],connection[1],connection[2],connection[3],connection[4]])
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

def createAttackScenarioLogic(currentAttackScenario,instanceFile):
    #for currentAttackScenario in attackScenarios:
        #Clear all vulnerabilities and add only those for a specific attack
        Logic()
        setup(instanceFile)
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
    print(("Best Utility: " + str(bestUtility)))
    #print("Best Tactics Options: " + str(bestTacticsSets))
    for ts in bestTacticsSets:
        print("************")
        print(str(ts))




def tryTacticOptions(maxTactics,debug=False):
    #Initialize utilities dictionary for each of the tactic options
    utilities = {}
    #if debug:
    #bestUtility = float(0)
    originalUtil = float(determineResidualUtility())
    bestUtility = originalUtil
    print(("Original utility: " + str(originalUtil)))
    utilities[""] = originalUtil

    #For progress tracking
    numOptions = 0
    for numTactics in range(1,maxTactics+1):
        numOptions += len(list(itertools.combinations(tacticsIter(),numTactics)))
        #TODO? Put following line back in
        #utilities[None] = float(determineResidualUtility())

    setNumber = 0

    print(("Tactic options: " + str(numOptions)))
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
            print((str(percentComplete) + "%...\r"), end=' ')
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
                print(("New optimal: " + str(residualUtil) + str(tacticSet)))
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
                    if (tactic[1] == "networkConnectsTo") and (bidirectional == True):
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
        pyDatalog.assert_fact("networkConnectsTo",c[0],c[1],True,True,True)


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


#attackPaths(SourceService,TargetService,P,E,AttackerMoves,TotalC)
def pprintAttackPaths(ap):
    s = ""
    s += "From: " + str(ap[0])
    s += "\nTo: " + str(ap[1])
    s += "\nCost: " + str(ap[5])
    s += "\nPath: " + str(ap[2])
    s += "\Exploits: " + str(ap[3])
    s += "\nAttackerMoves: " + str(ap[4]) #pprint this, too
    return s






















#Below here is for testing the above code

def printConnections(debug=True):
    #transitiveConnectsWithAttributesPathForFunction()
    #paths = pyDatalog.ask("transitiveConnectsWithAttributesOnPath(SourceService,TargetService,CProvided,IProvided,AProvided,P)").answers
    #paths = pyDatalog.ask("transitiveConnectsWithAttributesOnPath('opc','rtus',CProvided,IProvided,AProvided,P)").answers
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
    #query = "consumesDataWithAttributesNoAlternative(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P)"
    #query = "noIdealConsumption(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P)"
    #query = "consumesDataWithAttributesNoAlternative(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P)"
    #query = "consumesDataWithAttributes(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P)"
    #query = "transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)"

    #query = "consumesDataOnlyGoodPath(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P)"
    #query = "consumesDataWithAttributesNoAlternative(FunctionA,ServiceA,Data," + str(True) + ",CImpact," + str(True) + ",IImpact," + str(True) + ",AImpact,P)"
    #query = "weightedWorstCasePath[X]==Y"
    addRisksToLogic(dict([(0,0.2),(1,0.2),(2,0.2),(3,0.2),(4,0.2)]))
    #pyDatalog.assert_fact("compromised('vpn',0.9,False,False,False)")
    #query = "pathCompromisesWithCost(X,C)"
    #query = "attackPaths(SourceService,TargetService,P,E,AttackerMoves,4)"
    #query = "compromised(X)"
    #query = "cToWithPrivileges(SourceService,TargetService,VulnType,TotalC)"
    #query = "estimatedUtility[X]==Y"
    #query = "worstCasePathFromSource[X,Y]==Z"
    #query = "compromisedCombo(X)"
    #query = "probCapability[X]==Y"
    #query = "worstCasePathValue[X]==Y"
    #query = "attackPaths(SourceService,TargetService,P,E,C)"
    query = "connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided)"
    #query = "cToWithPrivileges(IntermediateService1,TargetService,VulnType,C)"
    #query = "cToWithPrivileges(IntermediateService1,TargetService,VulnType,C)"
    paths = pyDatalog.ask(query).answers
    #print(paths)
    if debug:
        print("Paths calculated.")
        if paths != None:
            print(("Number of items: " + str(len(paths))))
            pprint.pprint(paths)
        else:
            print("No paths found")

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


#components here are those that are connected to something
#this assumption may need to change
#Also uses possibleCompromises (set above)
def designOfExperiment(possibleCompromises,riskDict,debug=True):
    query = "networkConnectsTo(SourceService,TargetService,COK,IOK,AOK)"
    components = pyDatalog.ask(query).answers
    getService0 = itemgetter(0)
    getService1 = itemgetter(1)
    componentsList = list(map(getService0,iter(components)))
    componentsList2 = list(map(getService1,iter(components)))
    componentsList.extend(componentsList2)
    componentsList = list(set(componentsList))
    #pprint.pprint(componentsList)
    compromisedComponents = list(map(getService0,iter(possibleCompromises)))
    possibleCompromisesDict = dict(possibleCompromises)
    ledger = []
    #pprint.pprint(compromisedComponents)
    #print(possibleCompromisesDict.get("internet"))
    #sumComponentUtilCompromised = 0
    #sumComponentUtilUncompromised = 0
    for component in componentsList:
        newPossibleCompromises = possibleCompromisesDict
        newPossibleCompromises[component] = 1.0
        componentUtilCompromised = 1.0 #For code development only
        #componentUtilCompromised = determineResidualUtility(newPossibleCompromises,riskDict,True)
        newPossibleCompromises = possibleCompromisesDict
        if component in compromisedComponents:
            del newPossibleCompromises[component]
        componentUtilUncompromised = 0.0 #For code development only
        #componentUtilUncompromised = determineResidualUtility(newPossibleCompromises,riskDict,True)
        ledger.append([component,componentUtilCompromised,componentUtilUncompromised])
    pprint.pprint(ledger)


start = time.time()
#tryTacticOptions(1)
#tryTacticOptions(3,True)
#getAttackScenarios()
MaxRisk=4

#For DHS ICS Example
#instanceFile = "dhs-ics.py"
#possibleCompromises = [['internet',0.9],['businessWorkstations', 0.1]]
#Note: Changes in Python, too
#riskDict = dict([(0,0.2),(1,0.2),(2,0.2),(3,0.2),(4,0.2)])
#createEnvironment(instanceFile)
#query = "attackPaths(\"internet\",\"rtus\",P,E,AttackerMoves,TotalC)"
#determineResidualUtilityOnceTest(riskDict,query)


#WORKING HERE
#For Firewall Small Example
instanceFile = "fw-test1.py"
#instanceFile = "validation-perimeters-flat.py"
#possibleCompromises = [['attacker',1.0]]
#Note: Changes in Python, too
#riskDict = dict([(0,0.2),(1,0.2),(2,0.2),(3,0.2),(4,0.2)])
#addRisksToLogic(riskDict)
createEnvironment(instanceFile)
#query = "attackPaths(\"attacker\",\"server\",P,E,AttackerMoves,TotalC)"
#query = "connectsTo(\"attacker\",TargetService,CProvided,IProvided,AProvided)"
#query = "connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided)"
#query = "attackerConnectsTo(SourceService,TargetService,VulnType,C,CImpact,IImpact,AImpact)"
#query = "attackPaths(\"attacker\",TargetService,P,E,AttackerMoves,TotalC,CImpact,IImpact,AImpact)"
#query = "attackPaths(SourceService,TargetService,P,E,AttackerMoves,TotalC,CImpact,IImpact,AImpact)"
#query = "compromised(SourceService,True,CImpact,IImpact,AImpact)" #Works
#query = "compromised(SourceService,PC,CImpact,IImpact,AImpact)" #Works
#query = "isType(X,Y)"
#query = "pathCompromisesWithCost(X,C)"
#query = "pathCompromisesFunctions[X] == FList"
#query = "pathCompromisesUtilities[X] == U"
#query = "worstCasePath[X] == Y"
#query = "probCapability[C] == PC"
query = "worstCasePathUtil[C] == Y"
query = "pathCompromisesFunctionWithCost(X,FuncName,U2,C)"
#query = "weightedWorstCasePath[C] == Y"
query = "residualUtility[0] == X"
#query = "attackerConnectsTo(IntermediatService1,TargetService,VulnType,C,CImpact,IImpact,AImpact)"
#query = "attackScenarios(APSet,AttackerMoves,CumulativeP,E,SourceService,TargetService,CurrentP,CompromiseSet,PC,TotalC)"
query = "attackScenarioPiece(APSet,AttackerMoves,CumulativeP,E,Leaves,'TERMINATED','TERMINATED',[],CompromiseSet,PC,TotalC)"
#query = "attackScenarios(APSet,AttackerMoves,CumulativeP,E,'TERMINATED','TERMINATED',[],CompromiseSet,PC,TotalC) & (E[-1]=='serverExploit')"
#query = "attackScenarios(APSet,AttackerMoves,CumulativeP,E,'attacker','server',CurrentP,CompromiseSet,PC,TotalC)"
query = "attackScenario(APSet,AttackerMoves,CumulativeP,E,CompromiseSet,PC,TotalC)"
query = "attackScenarioPiece(APSet,AttackerMoves,CumulativeP,E,Leaves,SourceService,TargetService,CurrentP,CompromiseSet,PC,TotalC)"
#query = "attackScenario(APSet,AttackerMoves,CumulativeP,E,CompromiseSet,PC,TotalC)"
#uery = "transitiveConnects(SourceService,SourceService,P,CProvided,IProvided,AProvided)"
#query = "transitiveConnectsUnderAttack(AttackerMoves,SourceService,TargetService,P,CProvided,IProvided,AProvided)"
#query = "consumesAttackOverlap[FuncName,Data,CP,AttackerMoves] == Y"
#query = "attackerConnectsTo('fwA1','fwB1',VulnType,C,CImpact,IImpact,AImpact)"
#query = "weightedWorstCasePath[C] == U2"
#query = "worstCasePathUtilInclusive[C] == Y"
#query = "transitiveConnects(SourceService,TargetService,P,CProvided,IProvided,AProvided)"
#query = "consumesPath(FuncName,Data,SourceService,TargetService,P,CProvided,IProvided,AProvided)"
#query = "bestConsumesPath[FuncName,ConsumesSet,Data] == CP"
query = "consumesAttackOverlap[FuncName,Data,CP,AttackerMoves] == Y"
#query = "isVulnerable(IntermediateService1,VulnType,C,CImpact,IImpact,AImpact)"
#query = "consumesAttackOverlap(FuncName,Data,CP,AttackerMoves)"
stuff = pyDatalog.ask(query).answers
#print(("Number of items: " + str(len(stuff))))
pprint.pprint(query)
pprint.pprint(stuff,indent=4)
#print(determineResidualUtilityOnceTest(riskDict,query))

#TODO Next...using produces and consumes, what is the best path for data?
#...I can produce a path and multiply the C,I,A values for each segment and then
#...(CProvided*CRequired + IProvided*IRequired + AProvided*ARequired)/3 #This isn't right yet
#...then use the best path available given the requirements

# Provided | Required | Utility
# True     | True     | 1.0
# True     | False    | 1.0
# False    | True     | 0.0
# False    | False    | 1.0


#Note: Run the below to do individual queries for debugging
#possibleCompromises = [['vpn',0.1],['printer', 0.9]]
#Note: Changes in Python, too
#possibleCompromises = [['internet',0.9],['businessWorkstations', 0.1]]
#possibleCompromises = [['internet',0.9]]
#For abstracted version:
#possibleCompromises = [['businessDMZ', 0.1]]
#possibleCompromises = [['businessDMZ',0.9]]
#createEnvironment(instanceFile)
#printConnections()
#possibleCompromises = [['hmi',0.5]]
#riskDict = dict([(0,1.0)])
#Note: Changes in Python, too
#riskDict = dict([(0,0.2),(1,0.2),(2,0.2),(3,0.2),(4,0.2)])
#riskDict = dict([(0,0.60),(1,0.30),(2,0.08),(3,0.01),(4,0.01)])






#designOfExperiment(possibleCompromises,riskDict,True)

def riskTest():
    riskOptions = [0.0,0.2,0.4,0.6,0.8,1.0]
    # Creates a list containing 5 lists, each of 8 items, all set to 0
    riskRange,runRange,pRange = 5,126,5;
    riskRange = 5;
    #,runRange,pRange = 5,126,5;
    #matrix = [[[0 for x in range(riskRange)] for y in range(runRange)] for z in [0.0,0.2,0.4,0.6,0.8,1.0]]
    #matrix = [[[0 for x in range(riskRange)] for y in range(runRange)]]
    #matrixDict = {}
    with open('riskTest.csv', 'w') as csvfile:
        testWriter = csv.writer(csvfile, delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
        #spamwriter.writerow(['Spam'] * 5 + ['Baked Beans'])
        runNum = 0
        testWriter.writerow(["Run Number","C=0","C=1","C=2","C=3","C=4","Residual Utility"])
        s = ""
        for r0 in riskOptions:
            for r1 in riskOptions:
                if (r0 + r1) <= 1:
                    for r2 in riskOptions:
                        if (r0 + r1 + r2) <= 1:
                            for r3 in riskOptions:
                                if (r0 + r1 + r2 + r3) <= 1:
                                    for r4 in riskOptions:
                                        if (r0 + r1 + r2 + r3 + r4) == 1:
                                            rd = dict([(0,r0),(1,r1),(2,r2),(3,r3),(4,r4)])
                                            ru = determineResidualUtility(possibleCompromises,rd,True)
                                            #print str([r0,r1,r2,r3,r4])
                                            #data.addRow([2.3, 5.2, 102.1, 45.2]);
                                            testWriter.writerow([runNum,r0,r1,r2,r3,r4,ru])
                                            s += "data.addRow(" + str([runNum,0,r0,ru]) + ");\n"
                                            s += "data.addRow(" + str([runNum,1,r1,ru]) + ");\n"
                                            s += "data.addRow(" + str([runNum,2,r2,ru]) + ");\n"
                                            s += "data.addRow(" + str([runNum,3,r3,ru]) + ");\n"
                                            s += "data.addRow(" + str([runNum,4,r4,ru]) + ");\n"
                                            #matrixDict[runNum] = [ru,r0,r1,r2,r3,r4]
                                            #for riskNum in range(riskRange):
                                            #    matrix[riskNum[runNum]] = ru
                                            runNum += 1
        print(s)
        #Convert dict to matrix for printing
        #for runNum,v in matrixDict.items():
        #    for probRisks in v[1:]:
        #        for riskNum in range(riskRange):
        #            matrix[riskNum[runNum]] = v[0]
        #for riskNum in range(riskRange):
        #    for runNum in runRange:
        #    #testWriter.writerow("C" + str(riskNum),matrix[riskNum])
        #        print("C" + str(riskNum),matrix[riskNum])

#For architecture comparisons in the paper
#possibleCompromises = [['vpn',0.9],['printer', 0.9]]
#riskDict = dict([(0,0.1),(1,0.2),(2,0.3),(3,0.3),(4,0.1)])
#determineResidualUtility(possibleCompromises,riskDict,True)


#Sensitivity to changes to the attacker capability probabilities
#For the paper, this was run once with the printer attached to sw1 and once with it attached to sw3
#riskTest()

#Senstivity to changes to the probabilities of attacker points of presence
#For the paper, this was run with the printer attached to sw1
riskDict = dict([(0,0.2),(1,0.2),(2,0.2),(3,0.2),(4,0.2)])
def compromiseTest():
    with open('compromiseTest.csv', 'w') as csvfile:
        testWriter = csv.writer(csvfile, delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
        #runNum = 0
        testWriter.writerow(["","0.0","0.1","0.2","0.3","0.4","0.5","0.6","0.7","0.8","0.9","1.0"])
        #s = ""
        for vpnProb in [0.0,0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,1.0]:
            rowList = [str(vpnProb)]
            for printerProb in [0.0,0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,1.0]:
                print("************************************")
                print(("VPN Prob: " + str(vpnProb) + " Printer Prob: " + str(printerProb)))
                #[['internet',0.9],['businessDMZ', 0.1]]
                possibleCompromises = [['internet',vpnProb],['businessDMZ', printerProb]]
                ru = determineResidualUtility(possibleCompromises,riskDict,True)
                rowList.append(str(ru))
            print("####################################")
            print((str(rowList)))
            testWriter.writerow(rowList)

#compromiseTest()




#def utilTest():

#possibleCompromises = [['vpn',1.0],['printer', 1.0]]
#riskDict = dict([(0,0.2),(1,0.2),(2,0.2),(3,0.2),(4,0.2)])
#print(determineResidualUtility(possibleCompromises,riskDict,True))

#For fw-test1.py
#possibleCompromises = [['attacker',1.0]]
#For dhs-ics.py
#possibleCompromises = [['internet',0.9],['businessWorkstations', 0.1]]
#For dhs-abstracted-tiers.py
#possibleCompromises = [['internet',0.9],['businessDMZ', 0.9]]
#For dhs-ics.py
#possibleCompromises = [['internet',0.9],['businessWorkstations', 0.1]]
#possibleCompromises = [['internet',1.0]]
#possibleCompromises = [['controlAppServer',1.0]]
#possibleCompromises = [['businessWorkstations',1.0]]


#riskDict = dict([(0,0.2),(1,0.2),(2,0.2),(3,0.2),(4,0.2)])
#riskDict = dict([(0,0.1),(1,0.3),(2,0.4),(3,0.2)])
#riskDict = dict([(0,0.25),(1,0.25),(2,0.25),(3,0.25)])


#query = "attackPaths(SourceService,TargetService,P,E,AttackerMoves,TotalC)"
#stuff = pyDatalog.ask(query).answers
#print(("Number of items: " + str(len(stuff))))
#pprint.pprint(stuff)

#determineResidualUtilityOnceTest(riskDict)


#Undo this for paper
#print(determineResidualUtility(possibleCompromises,riskDict,True))

#query = "attackPaths(SourceService,TargetService,P,E,AttackerMoves,TotalC)"
#query = "attackPaths(\"internet\",\"businessWorkstations\",P,E,AttackerMoves,TotalC)"
#query = "attackPaths(\"internet\",\"businessFW\",P,E,AttackerMoves,TotalC)"
#query = "attackPaths(\"internet\",\"controlFW\",P,E,AttackerMoves,TotalC)"
#query = "attackPaths(\"internet\",\"rtus\",P,E,AttackerMoves,TotalC)"

#query = "attackPaths(\"internet\",\"rtus\",P,E,AttackerMoves,TotalC)"
#query = "cToWithPrivileges(IntermediateService1,TargetService,X,C)"
#query = "worstCasePathCombo[TotalC,Combo] == Y" #left side undefined
#query = "worstCasePath[TotalC] == Y" #left side undefined
#query = "weightedWorstCasePath[X]==Y" #works
#determineResidualUtilityOnceTest(riskDict,query)
#determineResidualUtility(possibleCompromises,riskDict)

end = time.time()
print((end - start))
