

+ isType('hmi','service')
+ isType('swA','networkDevice')
+ networkConnectsToWithAttributes('hmi','swA',True,True,True)


requiresFunction(FunctionA,FunctionC) <= requiresFunction(FunctionA,FunctionB) & requiresFunction(FunctionB,FunctionC)
+ requiresFunction('transmissionMgmt','transmissionF')

#Fact:
+ parent(bill, 'John Adams')

#Rule:
#Base case
ancestor(X,Y) <= parent(X,Y)
#Inductive case
ancestor(X,Y) <= parent(X,Z) & ancestor(Z,Y)




def determineResidualUtilityOld(debug=False):
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


#Find all attack scenarios within the cost metric
allAttackerPaths(SourceService,TargetService,P,E,TotalC) <= allAttackerPaths(SourceService,IntermediateService1,P2,E2,TotalC2) & cToWithPrivileges(IntermediateService1,TargetService,VulnType,C) & (SourceService!=TargetService) & (SourceService._not_in(P2)) & (TargetService._not_in(P2)) & (P==P2+[IntermediateService1]) & (E==E2+[VulnType]) & (TotalC==TotalC2+C) & (TotalC2+C <= maxRisk)
#Base case
allAttackerPaths(SourceService,TargetService,P,[VulnType],TotalC) <= cToWithPrivileges(SourceService,TargetService,VulnType,TotalC) & (P==[]) & (C==0)

#Find all attack scenarios within the cost metric
#allAttackerPathsPlus(SourceService,TargetService,P,E,TotalC,TotalC) <= allAttackerPathsPlus(SourceService,IntermediateService1,P2,E2,TotalC2,TotalC2) & cToWithPrivileges(IntermediateService1,TargetService,VulnType,C) & (SourceService!=TargetService) & (SourceService._not_in(P2)) & (TargetService._not_in(P2)) & (P==P2+[IntermediateService1]) & (E==E2+[VulnType]) & (TotalC==TotalC2+C) & (TotalC2+C <= maxRisk)
#Base case
#BUG? C=0 should be TotalC <= maxRisk?
#allAttackerPathsPlus(SourceService,TargetService,P,[VulnType],TotalC,TotalC) <= cToWithPrivileges(SourceService,TargetService,VulnType,TotalC) & (P==[]) & (C==0)

#Find all attack scenarios within the cost metric
allAttackerPathsPlus(SourceService,TargetService,P,E,TotalC,MaxR) <= allAttackerPathsPlus(SourceService,IntermediateService1,P2,E2,TotalC2,MaxR) & cToWithPrivileges(IntermediateService1,TargetService,VulnType,C) & (SourceService!=TargetService) & (SourceService._not_in(P2)) & (TargetService._not_in(P2)) & (P==P2+[IntermediateService1]) & (E==E2+[VulnType]) & (TotalC==TotalC2+C) & (TotalC2+C <= MaxR)
#Base case
allAttackerPathsPlus(SourceService,TargetService,P,[VulnType],TotalC,MaxR) <= cToWithPrivileges(SourceService,TargetService,VulnType,TotalC) & (P==[]) & (TotalC <= MaxR)




#Find all shortest attack scenarios within the cost metric...not finished
shortestAttackerPathsPlus(SourceService,TargetService,P,E,TotalC,TotalC) <= shortestAttackerPathsPlus(SourceService,IntermediateService1,P2,E2,TotalC2,TotalC2,TotalC2) & cToWithPrivileges(IntermediateService1,TargetService,VulnType,C) & (SourceService!=TargetService) & (SourceService._not_in(P2)) & (TargetService._not_in(P2)) & (P==P2+[IntermediateService1]) & (E==E2+[VulnType]) & (TotalC==TotalC2+C) & (TotalC2+C <= maxRisk)
#Base case
shortestAttackerPathsPlus(SourceService,TargetService,P,[VulnType],TotalC,TotalC) <= cToWithPrivileges(SourceService,TargetService,VulnType,TotalC) & (P==[]) & (C==0)
#allAttackPathsUnguided(SourceService,P,E,TotalC)
shortestAttackerPathsPlus(SourceService,TargetService,P,E,TotalC,TotalC) <= ~(shortestAttackerPathsPlus(SourceService,TargetService,P2,E2,TotalC2,TotalC2) & (TotalC2 < TotalC))

#A service is questionable if it's reachable within the risk metric from a compromised service
questionable(TargetService) <= compromised(SourceService) & allAttackerPaths(SourceService,TargetService,P,E,TotalC) & (TotalC <= maxRisk)
questionableWithinRisk(TargetService,RiskLimit) <= compromised(SourceService) & allAttackerPaths(SourceService,TargetService,P,E,TotalC) & (TotalC <= RiskLimit)
questionableAtRisk(TargetService,RiskLimit) <= compromised(SourceService) & allAttackerPaths(SourceService,TargetService,P,E,TotalC) & (TotalC == RiskLimit)

#FunctionA is questionable if ServiceA is questionable and FunctionA requires ServiceA
functionQuestionable(FunctionA,U) <= requires(FunctionA,ServiceA) & questionable(ServiceA) & utility(FunctionA,U)
functionQuestionableWithinRisk(FunctionA,U,RiskLimit) <= requires(FunctionA,ServiceA) & questionableWithinRisk(ServiceA,RiskLimit) & utility(FunctionA,U)
functionQuestionableWithinRiskPlus(FunctionA,U,RiskForFunction,RiskLimit) <= requires(FunctionA,ServiceA) & questionableAtRisk(ServiceA,RiskForFunction) & utility(FunctionA,U) & (RiskForFunction <= RiskLimit)



#+ functionsByService()

#TODO This should be functionUnavailable
#BUG below
#functionQuestionable(FunctionA,U) <= requiresConnection(FunctionA,SourceService,TargetService) & ~(connectsTo(SourceService,TargetService)) & utility(FunctionA,U)
functionQuestionable(FunctionA,U) <= requiresConnection(FunctionA,SourceService,TargetService) & ~(transitiveConnects(SourceService,TargetService)) & utility(FunctionA,U)
functionQuestionableWithinRisk(FunctionA,U,RiskLimit) <= requiresConnection(FunctionA,SourceService,TargetService) & ~(transitiveConnects(SourceService,TargetService)) & utility(FunctionA,U)
functionQuestionableAtRisk(FunctionA,U,RiskLimit) <= requiresConnection(FunctionA,SourceService,TargetService) & ~(transitiveConnects(SourceService,TargetService)) & utility(FunctionA,U)

#For debugging
missingConnection(SourceService,TargetService) <= requiresConnection(FunctionA,SourceService,TargetService) & ~(transitiveConnects(SourceService,TargetService))




#+ requires('transmissionF','powerProvider')
+ requiresFunction('transmissionF','opcF')
+ requiresSecurityAttribute('transmission','integrity','transmissionC2','opc',1.0)
#+ requires('transmission','opc')
+ requiresFunction('transmissionF','hmiF')
#+ requires('transmission','hmi')
+ requiresFunction('transmissionF','scadaServerF')
#+ requires('transmission','scadaServer')
+ requires('transmissionF','relayLouie')
+ requires('transmissionF','relayRicky')
+ requires('transmissionF','dmzFirewall')
+ requires('transmissionF','rtus')

#This needs to be about the data
+ consumesData('transmissionF','transmissionC2',False,0,True,1.0,False,0)
+ consumesDataForFunc()
hasRequiredConnections('transmissionF') <=  requiresConnection('transmissionF','opcF','scadaServerF') & requiresConnection('transmissionF','hmiF','scadaServerF') & requiresConnection('transmissionF','relayLouie','scadaServerF') & requiresConnection('transmissionF','relayRicky','scadaServerF') & requiresConnection('transmissionF','relayLouie','scadaServerF') & requiresConnection('transmissionF','rtu1','scadaServerF') & requiresConnection('transmissionF','rtu2','scadaServerF') & requiresConnection('transmissionF','rtu3','scadaServerF') & requiresConnection('transmissionF','rtu4','scadaServerF') & requiresConnection('transmissionF','rtu5','scadaServerF') & requiresConnection('transmissionF','rtu6','scadaServerF') & requiresConnection('transmissionF','rtu7','scadaServerF') & requiresConnection('transmissionF','rtu8','scadaServerF')

#requiresConnection('transmissionF','powerProvider','scadaServerF') & requiresConnection('transmissionF','opcF','scadaServerF') & requiresConnection('transmissionF','hmiF','scadaServerF') & requiresConnection('transmissionF','relayLouie','scadaServerF') & requiresConnection('transmissionF','relayRicky','scadaServerF') & requiresConnection('transmissionF','relayLouie','scadaServerF') & requiresConnection('transmissionF','rtu1','scadaServerF') & requiresConnection('transmissionF','rtu2','scadaServerF') & requiresConnection('transmissionF','rtu3','scadaServerF') & requiresConnection('transmissionF','rtu4','scadaServerF') & requiresConnection('transmissionF','rtu5','scadaServerF') & requiresConnection('transmissionF','rtu6','scadaServerF') & requiresConnection('transmissionF','rtu7','scadaServerF') & requiresConnection('transmissionF','rtu8','scadaServerF')
+ securityRequirement('transmissionF','integrity','actions')
+ securityRequirement('transmissionF','integrity','setPoints')
+ securityRequirement('transmissionF','integrity','status') #could overapproximate for integrity changes where it doesn't matter
+ securityRequirement('transmissionF','availability','actions')
+ securityRequirement('transmissionF','availability','setPoints')
+ securityRequirement('transmissionF','availability','status')
+ learns('transmissionF','hmi','status')
+ computes('transmissionF','hmi','setPoints')
+ learns('transmissionF','scadaServer','status')
+ learns('transmissionF','scadaServer','setPoints')
+ computes('transmissionF','scadaServer','actions')
+ learns('transmissionF','opc','actions')
+ learns('transmissionF','opc','status')
+ learns('transmissionF','relayRicky','actions')
+ learns('transmissionF','relayLouie','actions')
+ learns('transmissionF','relayLouie','actions')
+ learns('transmissionF','rtu1','status')

#+ dataFlow('functionality','datum','source','target')
#+ dataUsed('functionality','datum','ciaReq','service')
#+ interface('functionality','produces','datum','service') #links data produced to a physical service
#+ interface('functionality','consumes','datum','service') #links data consumed to a physical service
#+ securityRequirement('functionality','ciaReq','datum','source','destination')


#+ learns('transmissionF','engineerWorkstation','status')
#+ learns('transmissionF','engineerWorkstation','setPoints')
#+ computes('transmissionF','engineerWorkstation','setPoints')
