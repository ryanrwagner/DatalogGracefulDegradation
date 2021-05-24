
#Pick up here
#networkConnectsToWithAttributes('opc','sw4',True,True,True)
#networkConnectsToWithAttributes('SourceService','TargetService','COK','IOK','AOK') <= moveToNewSubnetWithAttributes('SourceService','TargetService','COK','IOK','AOK')

#networkConnectsToWithAttributes('SourceService','TargetService','COK','IOK','AOK') <= moveToNewSubnetWithAttributes('SourceService','TargetService','COK','IOK','AOK')

#Learns information
#learns(...) <=
#transmits(...) <= #transmits has different implications if encrypted or not

#Regular services have to interconnect via network devices (no plugging one service directly into another)
#validConnectsTo(SourceService,TargetService) <= isType(SourceService,'service') & isType(TargetService,'networkDevice') & ~(SourceService == TargetService) & bidirectional
#Network Device to Non-Network Device
#validNewConnectsTo(SourceService,TargetService) <= isType(SourceService,'networkDevice')  & isAccount(SourceService,'userAccount') & isType(TargetService,'service') & isAccount(TargetService,'userAccount') & ~(SourceService == TargetService) & ~connectsTo(SourceService,TargetService)#& ~validConnectsTo(TargetService,SourceService)
#Network Device to Network Device
#validNewConnectsTo(SourceService,TargetService) <= isType(SourceService,'networkDevice')  & isAccount(SourceService,'userAccount') & isType(TargetService,'networkDevice') & isAccount(TargetService,'userAccount') & ~(SourceService == TargetService) & (SourceService < TargetService) & ~connectsTo(SourceService,TargetService)
#validConnectsTo(SourceService,TargetService) <= validConnectsTo1(SourceService,TargetService) &

#isType(ServiceA,'networkDevice') <= isType(ServiceA,'switch')
#isType(ServiceA,'networkDevice') <= isType(ServiceA,'router')
#isType(ServiceA,'networkDevice') <= isType(ServiceA,'firewall')

#Type handling
isSubType(X,Z) <= isSubType(X,Y) & isSubType(Y,Z)
isSubType(X,Z) <= isType(X,Y) & isSubType(Y,Z)
isSubType(Z,Y) <= isType(X,Y) & isSubType(Z,X)
#isSubType(X,Z) <= isSubType(X,Y) & isType(Y,Z) #Wrong?
#isSubType(Y,Z) <= isSubType(X,Y) & isType(X,Z) #Wrong?
isTypeOrSubType(X,Y) <= isSubType(X,Y)
isTypeOrSubType(X,Y) <= isType(X,Y)
isTypeOrSuperType(X,Y) <= isSubType(Y,X)
isTypeOrSuperType(X,Y) <= isType(X,Y)


+ isSubType('switch','networkDevice')
+ isSubType('router','networkDevice')
+ isSubType('firewall','networkDevice')
#Change other uses of type to instance as in instance of type?
#Exploits go downward in type hierarchy...update vuln reasoning
#Ensure that no additional capability is spent on reused exploits
isVulnerable(ComponentType,Vulnerability,C,CImpact,IImpact,AImpact,Credentials) <= existsExploit(ComponentType,Vulnerability,C,CImpact,IImpact,AImpact,Credentials)
isVulnerable(X,Vulnerability,C,CImpact,IImpact,AImpact,Credentials) <= existsExploit(Y,Vulnerability,C,CImpact,IImpact,AImpact,Credentials) & isSubType(X,Y)

#ASKED
#Switch to Service
validNewConnectsTo(SourceService,TargetService) <= isTypeOrSuperType(SourceService,'switch')  & isAccount(SourceService,'userAccount') & isTypeOrSuperType(TargetService,'service') & isAccount(TargetService,'userAccount') & ~(SourceService == TargetService) & ~connectsTo(SourceService,TargetService)
#Switch to router
validNewConnectsTo(SourceService,TargetService) <= isTypeOrSuperType(SourceService,'switch')  & isAccount(SourceService,'userAccount') & isTypeOrSuperType(TargetService,'router') & isAccount(TargetService,'userAccount') & ~(SourceService == TargetService) & ~connectsTo(SourceService,TargetService)
#Firewall to switch
validNewConnectsTo(SourceService,TargetService) <= isTypeOrSuperType(SourceService,'firewall')  & isAccount(SourceService,'userAccount') & isTypeOrSuperType(TargetService,'switch') & isAccount(TargetService,'userAccount') & ~(SourceService == TargetService) & ~connectsTo(SourceService,TargetService)
#Firewall to firewall
validNewConnectsTo(SourceService,TargetService) <= isTypeOrSuperType(SourceService,'firewall')  & isAccount(SourceService,'userAccount') & isTypeOrSuperType(TargetService,'firewall') & isAccount(TargetService,'userAccount') & ~(SourceService == TargetService) & ~connectsTo(SourceService,TargetService)


#If a service residesOn a host (represented by the superuser), then there is a connection from the superuser to the host
#The host superuser and the host are proxies for each other
#connectsToWithPrivileges(SourceHost,SourceService) <= residesOn(SourceService,SourceHost)
#A user level service touches the superuser (without privileges)
connectsTo(SourceService,SourceHost) <= residesOn(SourceService,SourceHost)

#A network connection is a logical connection
connectsTo(SourceService,TargetService) <= networkConnectsTo(SourceService,TargetService)
connectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) <= networkConnectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided)

#Backward compatibility
connectsTo(SourceService,TargetService) <= connectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided)
networkConnectsTo(SourceService,TargetService) <= networkConnectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided)


#transitiveConnects defines a transitive closure of connectsTo
#Inductive case
transitiveConnects(SourceService,TargetService) <= transitiveConnects(SourceService,IntermediateService1) & connectsTo(IntermediateService1,TargetService)
#Base case
transitiveConnects(SourceService,TargetService) <= connectsTo(SourceService,TargetService)

#transitiveConnects defines a transitive closure of connectsTo
#Inductive case
transitiveConnectsPath(SourceService,TargetService,P) <= transitiveConnectsPath(SourceService,IntermediateService1,P2) & connectsTo(IntermediateService1,TargetService) & (P==P2+[IntermediateService1]) & (TargetService._not_in(P2)) & (SourceService._not_in(P2))
#Base case
transitiveConnectsPath(SourceService,TargetService,[]) <= connectsTo(SourceService,TargetService)
#This defines any path between consumer and producer
consumesPath(FunctionA,TargetService,Data,[[SourceService]+P+[TargetService]]) <= transitiveConnectsPath(SourceService,TargetService,P) & consumesData(FunctionA,TargetService,Data,COK,CImpact,IOK,IImpact,AOK,AImpact) & producesData(SourceService,Data)

#transitiveConnects defines a transitive closure of connectsTo
#Inductive case
transitiveConnectsSecure(SourceService,TargetService) <= transitiveConnectsSecure(SourceService,IntermediateService1) & connectsTo (IntermediateService1,TargetService) & ~compromised(SourceService) & ~compromised(TargetService) & ~compromised(IntermediateService1)
#Base case
transitiveConnectsSecure(SourceService,TargetService) <= connectsTo(SourceService,TargetService) & ~compromised(SourceService) & ~compromised(TargetService)

#For bidirectional network connections
networkConnectsTo(TargetService,SourceService) <= networkConnectsTo(SourceService,TargetService)
#networkConnectsTo(TargetService,SourceService) <= networkConnectsTo(SourceService,TargetService) & (bidirectional==True)
#ASKED
networkConnectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) <= networkConnectsToWithAttributes(TargetService,SourceService,CProvided,IProvided,AProvided)



#transitiveConnectsWithAttributes(ServiceA,ServiceB,CProvided,IProvided,AProvided)


#Inductive case
#transitiveConnectsWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) <= (CProvided == providesBoth(True,True)) & (IProvided == providesBoth(True,True)) & (AProvided == providesBoth(True,True)) & transitiveConnectsWithAttributes(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1) & connectsToWithAttributes (IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2)

#transitiveConnectsWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) <= (CProvided == providesBoth(CProvided1,CProvided2)) & (IProvided == providesBoth(IProvided1,IProvided2)) & (AProvided == providesBoth(AProvided1,AProvided2)) & transitiveConnectsWithAttributes(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1) & connectsToWithAttributes (IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2)

#Original:
#transitiveConnectsWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) <= (CProvided==(CProvided1 and CProvided2)) & (IProvided==(IProvided1 and IProvided2)) & (AProvided==(AProvided1 and AProvided2)) & transitiveConnectsWithAttributes(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1) & connectsToWithAttributes (IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2)

transitiveConnectsWithAttributes(SourceService,TargetService,CProvided,IProvided1,AProvided1) <=  transitiveConnectsWithAttributes(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1) & connectsToWithAttributes(IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2) & (CProvided==(CProvided1 and CProvided2)) & (IProvided==(IProvided1 and IProvided2)) & (AProvided==(AProvided1 and AProvided2))


#transitiveConnectsWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) <= (CProvided==True) & (IProvided==True) & (AProvided==True) & transitiveConnectsWithAttributes(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1) & connectsToWithAttributes (IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2)

#transitiveConnectsWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) <= (CProvided==True) & (IProvided==True) & (AProvided==True) & transitiveConnectsWithAttributes(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1) & connectsToWithAttributes (IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2)


#Base case
#TODO Add CIA for components on path
transitiveConnectsWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) <= connectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided)
#Backward compatibility:
transitiveConnects(SourceService,TargetService) <=  transitiveConnectsWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided)
connectsTo(SourceService,TargetService) <= connectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided)

#I want to be able to say that for each function, and for each dataflow, a connection continues to exist
#transitiveConnectsWithAttributesPathForFunction(SourceService,TargetService,CProvided,IProvided,AProvided,P) <=

#Inductive Cases
#TODO Intermediate devices must be network types
transitiveConnectsWithAttributesOnPath(SourceService,TargetService,CProvided,IProvided,AProvided,P) <=  transitiveConnectsWithAttributesOnPath(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1,P1) & connectsToWithAttributes(IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2) & (SourceService._not_in(P1)) & (TargetService._not_in(P1)) & (SourceService!=TargetService) & (P==P1+[TargetService]) & (CProvided==(CProvided1 and CProvided2)) & (IProvided==(IProvided1 and IProvided2)) & (AProvided==(AProvided1 and AProvided2)) & isType(IntermediateService1,'networkDevice') #& ~compromised(IntermediateService1)
#If there's a compromise, we're saying all CIA attributes are False
#Switch back
#transitiveConnectsWithAttributesOnPath(SourceService,TargetService,False,False,False,P) <=  transitiveConnectsWithAttributesOnPath(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1,P1) & connectsToWithAttributes(IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2) & (SourceService._not_in(P1)) & (TargetService._not_in(P1)) & (P==P1+[TargetService]) & (CProvided==(CProvided1 and CProvided2)) & (IProvided==(IProvided1 and IProvided2)) & (AProvided==(AProvided1 and AProvided2)) & isType(IntermediateService1,'networkDevice') & compromised(IntermediateService1)

#Base cases
transitiveConnectsWithAttributesOnPath(SourceService,TargetService,CProvided,IProvided,AProvided,P) <= connectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) & (P==[TargetService]) & ~compromised(SourceService) & ~compromised(TargetService)
#If there's a compromise, we're saying all CIA attributes are False
transitiveConnectsWithAttributesOnPath(SourceService,TargetService,False,False,False,P) <= connectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) & (P==[TargetService]) & compromised(SourceService)
transitiveConnectsWithAttributesOnPath(SourceService,TargetService,False,False,False,P) <= connectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) & (P==[TargetService]) & compromised(TargetService)







#New to include attack paths
#Inductive Cases
#TODO Intermediate devices must be network types
#This is when the TargetService is not in the AP
transitiveConnectsWithAttributesOnPathUnderAttack(SourceService,TargetService,CProvided,IProvided,AProvided,DFP,AP) <=  transitiveConnectsWithAttributesOnPathUnderAttack(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1,DFP1,AP) & connectsToWithAttributes(IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2) & (SourceService._not_in(P1)) & (TargetService._not_in(P1)) & (SourceService!=TargetService) & (P==P1+[TargetService]) & (CProvided==(CProvided1 and CProvided2)) & (IProvided==(IProvided1 and IProvided2)) & (AProvided==(AProvided1 and AProvided2)) & isType(IntermediateService1,'networkDevice') & (TargetService._not_in(AP))
#This is when the TargetService is in the AP
#TODO This should be more granular in propagating C,I,A
transitiveConnectsWithAttributesOnPathUnderAttack(SourceService,TargetService,False,False,False,DFP,AP) <=  transitiveConnectsWithAttributesOnPathUnderAttack(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1,DFP1,AP) & connectsToWithAttributes(IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2) & (SourceService._not_in(P1)) & (TargetService._not_in(P1)) & (SourceService!=TargetService) & (P==P1+[TargetService]) & (CProvided==(CProvided1 and CProvided2)) & (IProvided==(IProvided1 and IProvided2)) & (AProvided==(AProvided1 and AProvided2)) & isType(IntermediateService1,'networkDevice') & (TargetService._in(AP))
#If there's a compromise, we're saying all CIA attributes are False
#Switch back
#transitiveConnectsWithAttributesOnPath(SourceService,TargetService,False,False,False,P) <=  transitiveConnectsWithAttributesOnPath(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1,P1) & connectsToWithAttributes(IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2) & (SourceService._not_in(P1)) & (TargetService._not_in(P1)) & (P==P1+[TargetService]) & (CProvided==(CProvided1 and CProvided2)) & (IProvided==(IProvided1 and IProvided2)) & (AProvided==(AProvided1 and AProvided2)) & isType(IntermediateService1,'networkDevice') & compromised(IntermediateService1)

#Base cases
transitiveConnectsWithAttributesOnPathUnderAttack(SourceService,TargetService,CProvided,IProvided,AProvided,DFP,AP) <= connectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) & (DFP==[TargetService]) & ~compromised(SourceService) & ~compromised(TargetService) & (SourceService._not_in(AP)) & (TargetService._not_in(AP))
#If there's a compromise, we're saying all CIA attributes are False
#TODO Add granularity for compromise attributes and also if e.g. Source is compromised and Target is in AP
transitiveConnectsWithAttributesOnPathUnderAttack(SourceService,TargetService,False,False,False,DFP,AP) <= connectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) & (DFP==[TargetService]) & compromised(SourceService)
transitiveConnectsWithAttributesOnPathUnderAttack(SourceService,TargetService,False,False,False,DFP,AP) <= connectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) & (DFP==[TargetService]) & compromised(TargetService)


#dataPaths(FunctionA,Data,SourceService,TargetService,[[Path,C,I,A]]) <= [set of all paths of data for this function]

#transitiveConnectsWithAttributesPathForFunction(SourceService,TargetService,CProvided,IProvided,AProvided,P) <= (P==P2+[TargetService]) & (CProvided == (CProvided1 and CProvided2)) & (IProvided == (IProvided1 and IProvided2)) & (AProvided == (AProvided1 and AProvided2)) & transitiveConnectsWithAttributesPathForFunction(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1,P2) & connectsToWithAttributes(IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2)
#Base case
#transitiveConnectsWithAttributesPathForFunction(SourceService,TargetService,CProvided,IProvided,AProvided,P) <= (P==[SourceService,TargetService]) & connectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided)
#Backward compatibility:
#transitiveConnects(SourceService,TargetService) <= transitiveConnectsWithAttributesPathForFunction(SourceService,TargetService,CProvided,IProvided,AProvided,P)
connectsTo(SourceService,TargetService) <= connectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided)

## TODO: Signature and encryption logic (if signed, links don't need to provide integrity)

#+ securityRequirement('transmissionF','availability','status')
#+ requiresLearns('transmissionF','hmi','status')

#owns
#draws: drawsComputes, drawsLearns
#learns - confidentiality
#notConfidential('DatumA','ComponentA') <= learns('ComponentA','DatumA')
#computes - confidentiality, integrity (by function?)
#transmits - availability
#uses -> high medium low impact, used by function

#dmp3 over ethernet
#reliability and CIA goals
#backpropagate CIA requirements FTA-style
# CIA requirements
# Security requirements
# RTU loss - availablility -> M, integrity -> H , each monitors different points, phase, current, voltage, could model as 4 Ricky, 4 Louie
# UAV CIA
# 171B
# Formalize the analysis process, what does the user come up with
# Canadian regulator - Canadian Nuclear Safety Commission
#Nuclear - power gen is level 2, meltdown protection is level 1, balance of plant l2, enterprise is l3
#FERC, NERC (quasi commercial)
