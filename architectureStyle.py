#For bidirectional network connections
#networkConnectsTo(TargetService,SourceService,CProvided,IProvided,AProvided) <= networkConnectsTo(SourceService,TargetService,CProvided,IProvided,AProvided)
connectsTo(TargetService,SourceService,CProvided,IProvided,AProvided) <= connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided)

#Type handling
# If X is a type of Y, then X is a subtype of Y
isSubType(X,Y) <= isType(X,Y)
# If X is a subtype of Y, and Y is a subtype of Z, then X is a subtype of Z
isSubType(X,Z) <= isSubType(X,Y) & isSubType(Y,Z)

#DELETE - Unnecessary 
# If X is type Y and Y is a subtype of Z, then X is a subtype of Z
#isSubType(X,Z) <= isType(X,Y) & isSubType(Y,Z)
# If X is a type of Y
#isSubType(Z,Y) <= isType(X,Y) & isSubType(Z,X)
#isSubType(X,Z) <= isSubType(X,Y) & isType(Y,Z) #Wrong?
#isSubType(Y,Z) <= isSubType(X,Y) & isType(X,Z) #Wrong?
#isTypeOrSubType(X,Y) <= isSubType(X,Y)
#isTypeOrSubType(X,Y) <= isType(X,Y)
isTypeOrSuperType(X,Y) <= isSubType(Y,X)
#isTypeOrSuperType(X,Y) <= isType(X,Y)


+ isSubType('switch','networkDevice')
+ isSubType('router','networkDevice')
+ isSubType('firewall','networkDevice')

#Change other uses of type to instance as in instance of type?
#Exploits go downward in type hierarchy...update vuln reasoning
#Ensure that no additional capability is spent on reused exploits
#isVulnerable(ComponentType,Vulnerability,C,CImpact,IImpact,AImpact) <= existsExploit(ComponentType,Vulnerability,C,CImpact,IImpact,AImpact)
isVulnerable(X,VulnType,C,CImpact,IImpact,AImpact) <= isVulnerable(Y,VulnType,C,CImpact,IImpact,AImpact) & isSubType(X,Y)

#ASKED
#Switch to Service
validNewConnectsTo(SourceService,TargetService) <= isTypeOrSuperType(SourceService,'switch') & isTypeOrSuperType(TargetService,'service') & ~(SourceService == TargetService) & ~connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided)
#validNewConnectsTo(SourceService,TargetService) <= isTypeOrSuperType(SourceService,'switch')  & isAccount(SourceService,'userAccount') & isTypeOrSuperType(TargetService,'service') & isAccount(TargetService,'userAccount') & ~(SourceService == TargetService) & ~connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided)
#Switch to router
validNewConnectsTo(SourceService,TargetService) <= isTypeOrSuperType(SourceService,'switch') & isTypeOrSuperType(TargetService,'router') & ~(SourceService == TargetService) & ~connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided)
#validNewConnectsTo(SourceService,TargetService) <= isTypeOrSuperType(SourceService,'switch')  & isAccount(SourceService,'userAccount') & isTypeOrSuperType(TargetService,'router') & isAccount(TargetService,'userAccount') & ~(SourceService == TargetService) & ~connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided)
#Firewall to switch
validNewConnectsTo(SourceService,TargetService) <= isTypeOrSuperType(SourceService,'firewall') & isTypeOrSuperType(TargetService,'switch') & ~(SourceService == TargetService) & ~connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided)
#validNewConnectsTo(SourceService,TargetService) <= isTypeOrSuperType(SourceService,'firewall')  & isAccount(SourceService,'userAccount') & isTypeOrSuperType(TargetService,'switch') & isAccount(TargetService,'userAccount') & ~(SourceService == TargetService) & ~connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided)
#Firewall to firewall
validNewConnectsTo(SourceService,TargetService) <= isTypeOrSuperType(SourceService,'firewall')  & isTypeOrSuperType(TargetService,'firewall') & ~(SourceService == TargetService) & ~connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided)
#validNewConnectsTo(SourceService,TargetService) <= isTypeOrSuperType(SourceService,'firewall')  & isAccount(SourceService,'userAccount') & isTypeOrSuperType(TargetService,'firewall') & isAccount(TargetService,'userAccount') & ~(SourceService == TargetService) & ~connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided)


#If a service residesOn a host (represented by the superuser), then there is a connection from the superuser to the host
#The host superuser and the host are proxies for each other
#connectsToWithPrivileges(SourceHost,SourceService) <= residesOn(SourceService,SourceHost)
#A user level service touches the superuser (without privileges)
#TODO: This should probably be removed. Anyways, the resides on is not bidirectional
connectsTo(SourceService,SourceHost,1,1,1) <= residesOn(SourceService,SourceHost)
# The user level service communicates with the superuser
# with C,I, and A. This might would be different for a bus-like
# connection.
#connectsToWithAttributes(SourceService,SourceHost,True,True,True) <= residesOn(SourceService,SourceHost)

#A network connection is a logical connection
#connectsTo(SourceService,TargetService) <= networkConnectsTo(SourceService,TargetService)
#connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided) <= networkConnectsTo(SourceService,TargetService,CProvided,IProvided,AProvided)

#Backward compatibility
#connectsTo(SourceService,TargetService) <= connectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided)
#networkConnectsTo(SourceService,TargetService) <= networkConnectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided)

#Base cases
# transitiveConnects(SourceService,TargetService,P,CProvided,IProvided,AProvided)
# + producesData(SourceService,Data)
# + consumesData(FuncName,ConsumesSet,Data,CImpact,IImpact,AImpact)
# attackScenarios(APSet,AttackerMoves,CumulativeP,E,Leaves,SourceService,TargetService,CurrentP,CompromiseSet,PC,TotalC)
# For when producer and consumer are on the same component
transitiveConnects(SourceService,SourceService,[SourceService],1,1,1) <= producesData(SourceService,Data) & consumesData(FuncName,ConsumesSet,Data,CImpact,IImpact,AImpact) & (SourceService._in(ConsumesSet))
# transitiveConnects(SourceService,TargetService,P,CProvided,IProvided,AProvided)
#Make sure we account for a point of compromise, too. Maybe we need a global 'compromised' vuln that has 0,0,0 for effect?
#Base case for when trace crosses the producer
#TODO CHECK LATER
transitiveConnectsUnderAttack(AttackerMoves,SourceService,SourceService,[SourceService],CImpact,IImpact,AImpact) <= attackScenario(APSet,AttackerMoves,CumulativeP,E,CompromiseSet,PC,TotalC) & producesData(SourceService,Data) & consumesData(FuncName,ConsumesSet,Data,CImpact2,IImpact2,AImpact2) & AttackerMove._in(AttackerMoves) & (AttackerMove == [SourceService3,SourceService,VulnType]) & isVulnerable(SourceService,VulnType,C,CImpact,IImpact,AImpact)
#Base case for when trace doesn't cross the producer
#TODO CHECK LATER
transitiveConnectsUnderAttack(AttackerMoves,SourceService,SourceService,[SourceService],1,1,1) <= attackScenario(APSet,AttackerMoves,CumulativeP,E,CompromiseSet,PC,TotalC) & producesData(SourceService,Data) & consumesData(FuncName,ConsumesSet,Data,CImpact2,IImpact2,AImpact2) & SourceService._not_in(CumulativeP)
# For when producer and consumer are on different components
transitiveConnects(SourceService,TargetService,[SourceService,TargetService],CProvided,IProvided,AProvided) <= connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided) & producesData(SourceService,Data) & (SourceService != TargetService)
# For when producer and consumer are on different components and trace crosses them
# Do I need a special case when the producer is compromised?
# Base here for when trace crosses the producer
#transitiveConnectsUnderAttack(AttackerMoves,SourceService,SourceService,[SourceService],CImpact,IImpact,AImpact) <= attackScenario(APSet,AttackerMoves,CumulativeP,E,CompromiseSet,PC,TotalC) & producesData(SourceService,Data) & consumesData(FuncName,ConsumesSet,Data,CImpact2,IImpact2,AImpact2) & AttackerMove._in(AttackerMoves) & (AttackerMove == [SourceService3,SourceService,VulnType]) & isVulnerable(SourceService,VulnType,C,CImpact,IImpact,AImpact) #& (CImpact == CImpact2*CImpact3) & (IImpact == IImpact2*IImpact3) & (AImpact == AImpact2*AImpact3)
# Base here for when trace doesn't cross the producer
#transitiveConnectsUnderAttack(AttackerMoves,SourceService,SourceService,[SourceService],1,1,1) <= attackScenario(APSet,AttackerMoves,CumulativeP,E,CompromiseSet,PC,TotalC) & producesData(SourceService,Data) & consumesData(FuncName,ConsumesSet,Data,CImpact2,IImpact2,AImpact2) & SourceService._not_in(CumulativeP) #& AttackerMove._in(AttackerMoves) & (AttackerMove == [SourceService3,SourceService,VulnType]) & isVulnerable(SourceService,VulnType,C,CImpact3,IImpact3,AImpact3) & (CImpact == CImpact2*CImpact3) & (IImpact == IImpact2*IImpact3) & (AImpact == AImpact2*AImpact3)

#transitiveConnects defines a transitive closure of connectsTo
#Inductive case
transitiveConnects(SourceService,TargetService,P,CProvided,IProvided,AProvided) <= transitiveConnects(SourceService,IntermediateService1,P2,CProvided2,IProvided2,AProvided2) & connectsTo(IntermediateService1,TargetService,CProvided3,IProvided3,AProvided3) & (P == P2+[TargetService]) & (CProvided == CProvided2*CProvided3) & (IProvided == IProvided2*IProvided3) & (AProvided == AProvided2*AProvided3) & TargetService._not_in(P2)
# Inductive case for when under attack and trace crosses the producer
transitiveConnectsUnderAttack(AttackerMoves,SourceService,TargetService,P,CImpact,IImpact,AImpact) <= attackScenario(APSet,AttackerMoves,CumulativeP,E,CompromiseSet,PC,TotalC) & transitiveConnectsUnderAttack(AttackerMoves,SourceService,TargetService,P,CImpact,IImpact,AImpact) & producesData(SourceService,Data) & consumesData(FuncName,ConsumesSet,Data,CImpact2,IImpact2,AImpact2) & AttackerMove._in(AttackerMoves) & (AttackerMove == [SourceService3,TargetService,VulnType]) & isVulnerable(SourceService,VulnType,C,CImpact,IImpact,AImpact)
# Inductive case for when under attack and trace doesn't cross the producer
transitiveConnectsUnderAttack(AttackerMoves,SourceService,TargetService,P,CImpact,IImpact,AImpact) <= attackScenario(APSet,AttackerMoves,CumulativeP,E,CompromiseSet,PC,TotalC) & transitiveConnectsUnderAttack(AttackerMoves,SourceService,TargetService,P,CImpact,IImpact,AImpact) & producesData(SourceService,Data) & consumesData(FuncName,ConsumesSet,Data,CImpact2,IImpact2,AImpact2) & AttackerMove._in(AttackerMoves) & (AttackerMove == [SourceService3,TargetService,VulnType]) & isVulnerable(SourceService,VulnType,C,CImpact,IImpact,AImpact)



# TODO: More properly factor in the impacts to C,I,A given what is provided by the connection given the attack scenario
consumesPath(FuncName,Data,SourceService,TargetService,P,CProvided,IProvided,AProvided) <= transitiveConnects(SourceService,TargetService,P,CProvided2,IProvided2,AProvided2) & consumesData(FuncName,ConsumesSet,Data,CRequired,IRequired,ARequired) & (TargetService._in(ConsumesSet)) & (CProvided == (1-CRequired*(1-CProvided2))) & (IProvided == (1-IRequired*(1-IProvided2))) & (AProvided == (1-ARequired*(1-AProvided2))) 
#Add in the function list here in the consumesPathUnderAttack

(bestConsumesPath[FuncName,ConsumesSet,Data] == max_(CP, order_by=U)) <= consumesPath(FuncName,SourceService,TargetService,P,CProvided,IProvided,AProvided) & consumesData(FuncName,ConsumesSet,Data,CImpact,IImpact,AImpact) & (U == (CProvided+IProvided+AProvided)*100) & (CP == [SourceService,TargetService,P,CProvided,IProvided,AProvided])

# SourceService is the consumer and TargetService is the producer
#consumesAttackOverlap(FuncName,VulnType,CP,IntermediateService1) <= consumesPath(FuncName,Data,SourceService,TargetService,CP,CProvided,IProvided,AProvided) & attackScenario(APSet,AttackerMoves,CumulativeP,E,CompromiseSet,PC,TotalC) & IntermediateService1._in(CP) & IntermediateService1._in(CumulativeP) & isVulnerable(IntermediateService1,VulnType,C,CImpact,IImpact,AImpact) #& (X == [IntermediateService1,VulnType,CImpact,IImpact,AImpact])

#consumesAttackOverlap(FuncName,CumulativeP,CP,IntermediateService1) <= consumesPath(FuncName,Data,SourceService,TargetService,CP,CProvided,IProvided,AProvided) & attackScenario(APSet,AttackerMoves,CumulativeP,E,CompromiseSet,PC,TotalC) & IntermediateService1._in(CP) & AttackerMove._in(AttackerMoves) & (AttackerMove == [SourceService2,IntermediateService1,VulnType]) & isVulnerable(IntermediateService1,VulnType,C,CImpact,IImpact,AImpact) #& (X == [IntermediateService1,VulnType,CImpact,IImpact,AImpact])
(consumesAttackOverlap[FuncName,Data,CP,AttackerMoves] == tuple_(X, order_by=TargetService)) <= consumesPath(FuncName,Data,SourceService,TargetService,CP,CProvided,IProvided,AProvided) & attackScenario(APSet,AttackerMoves,CumulativeP,E,CompromiseSet,PC,TotalC) & IntermediateService1._in(P) & AttackerMove.in_(AttackerMoves) & (AttackerMove == [SourceService2,IntermediateService1,VulnType]) & isVulnerable(IntermediateService1,VulnType,C,CImpact,IImpact,AImpact) & (X == [IntermediateService1,VulnType,CImpact,IImpact,AImpact])
#If a component is compromised, it'll need a special case 
#(consumesAttackOverlap[FuncName,Data,P,AttackerMoves] == tuple_(X, order_by=TargetService)) <= consumesPath(FuncName,Data,SourceService,TargetService,P,CProvided,IProvided,AProvided) & attackScenario(APSet,AttackerMoves,CumulativeP,E,CompromiseSet,PC,TotalC) & IntermediateService1._in(P) & AttackerMove.in_(AttackerMoves) & (AttackerMove == [SourceService2,IntermediateService1,'compromised']) & compromised(IntermediateService1,PC,CImpact,IImpact,AImpact) & (X == [IntermediateService1,VulnType,CImpact,IImpact,AImpact])

#(consumesAttackOverlap[FuncName,Data,P,AttackerMoves] == tuple_(X, order_by=TargetService)) <= consumesPath(FuncName,Data,SourceService,TargetService,P,CProvided,IProvided,AProvided) & attackScenario(APSet,AttackerMoves,CumulativeP,E,CompromiseSet,PC,TotalC) & IntermediateService1._in(P) & IntermediateService1._in(CumulativeP) & (X == IntermediateService1) # AttackerMove.in_(AttackerMoves) & (AttackerMove == [SourceService2,IntermediateService1,VulnType]) & (X == [IntermediateService1,VulnType])


















#transitiveConnects(SourceService,TargetService) <= transitiveConnects(SourceService,IntermediateService1) & connectsTo(IntermediateService1,TargetService,CProvided,IProvided,AProvided)


#transitiveConnects defines a transitive closure of connectsTo
#Inductive case
transitiveConnectsPath(SourceService,TargetService,P) <= transitiveConnectsPath(SourceService,IntermediateService1,P2) & connectsTo(IntermediateService1,TargetService,CProvided,IProvided,AProvided) & (P==P2+[IntermediateService1]) & (TargetService._not_in(P2)) & (SourceService._not_in(P2))
#Base case
transitiveConnectsPath(SourceService,TargetService,[]) <= connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided)
#This defines any path between consumer and producer
#consumesPath(FuncName,SourceService,TargetService,P,CProvided,IProvided,AProvided)
#consumesData(FuncName,ConsumesSet,Data,CImpact,IImpact,AImpact)
consumesPath(FunctionA,TargetService,Data,[[SourceService]+P+[TargetService]],CImpact,IImpact,AImpact) <= transitiveConnectsPath(SourceService,TargetService,P) & consumesData(FunctionA,ConsumesSet,Data,CImpact,IImpact,AImpact) & producesData(SourceService,Data) & TargetService._in(ConsumesSet)

#transitiveConnects defines a transitive closure of connectsTo
#Inductive case
transitiveConnectsSecure(SourceService,TargetService) <= transitiveConnectsSecure(SourceService,IntermediateService1) & connectsTo (IntermediateService1,TargetService) & ~compromised(SourceService,PC2,CImpact2,IImpact2,AImpact2) & ~compromised(TargetService,PC3,CImpact3,IImpact3,AImpact3) & ~compromised(IntermediateService1,PC4,CImpact4,IImpact4,AImpact4)
#Base case
transitiveConnectsSecure(SourceService,TargetService) <= connectsTo(SourceService,TargetService,CProvided,Provided,AProvided) & ~compromised(SourceService,PC,CImpact,IImpact,AImpact) & ~compromised(TargetService,PC2,CImpact2,IImpact2,AImpact2)

#ASKED


#networkConnectsTo(TargetService,SourceService) <= networkConnectsTo(SourceService,TargetService) & (bidirectional==True)
#ASKED
#networkConnectsTo(SourceService,TargetService,CProvided,IProvided,AProvided) <= networkConnectsTo(TargetService,SourceService,CProvided,IProvided,AProvided)



#transitiveConnectsWithAttributes(ServiceA,ServiceB,CProvided,IProvided,AProvided)


#Inductive case
#transitiveConnectsWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) <= (CProvided == providesBoth(True,True)) & (IProvided == providesBoth(True,True)) & (AProvided == providesBoth(True,True)) & transitiveConnectsWithAttributes(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1) & connectsToWithAttributes (IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2)

#transitiveConnectsWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) <= (CProvided == providesBoth(CProvided1,CProvided2)) & (IProvided == providesBoth(IProvided1,IProvided2)) & (AProvided == providesBoth(AProvided1,AProvided2)) & transitiveConnectsWithAttributes(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1) & connectsToWithAttributes (IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2)

#Original:
#transitiveConnectsWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) <= (CProvided==(CProvided1 and CProvided2)) & (IProvided==(IProvided1 and IProvided2)) & (AProvided==(AProvided1 and AProvided2)) & transitiveConnectsWithAttributes(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1) & connectsToWithAttributes (IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2)

transitiveConnectsWithAttributes(SourceService,TargetService,CProvided,IProvided1,AProvided1) <=  transitiveConnectsWithAttributes(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1) & connectsTo(IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2) & (CProvided==(CProvided1 and CProvided2)) & (IProvided==(IProvided1 and IProvided2)) & (AProvided==(AProvided1 and AProvided2))

#Base case
#TODO Add CIA for components on path
transitiveConnectsWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided) <= connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided)
#Backward compatibility:
transitiveConnects(SourceService,TargetService) <=  transitiveConnectsWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided)
#connectsTo(SourceService,TargetService) <= connectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided)

#I want to be able to say that for each function, and for each dataflow, a connection continues to exist
#transitiveConnectsWithAttributesPathForFunction(SourceService,TargetService,CProvided,IProvided,AProvided,P) <=

#Inductive Cases
#TODO Intermediate devices must be network types
transitiveConnectsWithAttributesOnPath(SourceService,TargetService,CProvided,IProvided,AProvided,P) <=  transitiveConnectsWithAttributesOnPath(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1,P1) & connectsTo(IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2) & (SourceService._not_in(P1)) & (TargetService._not_in(P1)) & (SourceService!=TargetService) & (P==P1+[TargetService]) & (CProvided==(CProvided1 and CProvided2)) & (IProvided==(IProvided1 and IProvided2)) & (AProvided==(AProvided1 and AProvided2)) & isType(IntermediateService1,'networkDevice') #& ~compromised(IntermediateService1)
#If there's a compromise, we're saying all CIA attributes are False
#Switch back
#transitiveConnectsWithAttributesOnPath(SourceService,TargetService,False,False,False,P) <=  transitiveConnectsWithAttributesOnPath(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1,P1) & connectsToWithAttributes(IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2) & (SourceService._not_in(P1)) & (TargetService._not_in(P1)) & (P==P1+[TargetService]) & (CProvided==(CProvided1 and CProvided2)) & (IProvided==(IProvided1 and IProvided2)) & (AProvided==(AProvided1 and AProvided2)) & isType(IntermediateService1,'networkDevice') & compromised(IntermediateService1)

#Base cases
transitiveConnectsWithAttributesOnPath(SourceService,TargetService,CProvided,IProvided,AProvided,P) <= connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided) & (P==[TargetService]) & ~compromised(SourceService,PC,CImpact,IImpact,AImpact) & ~compromised(TargetService,PC2,CImpact2,IImpact2,AImpact2)
#If there's a compromise, we're saying all CIA attributes are False
transitiveConnectsWithAttributesOnPath(SourceService,TargetService,False,False,False,P) <= connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided) & (P==[TargetService]) & compromised(SourceService,PC,CImpact,IImpact,AImpact)
transitiveConnectsWithAttributesOnPath(SourceService,TargetService,False,False,False,P) <= connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided) & (P==[TargetService]) & compromised(TargetService,PC,CImpact,IImpact,AImpact)

#New to include attack paths
#Inductive Cases
#TODO Intermediate devices must be network types
#This is when the TargetService is not in the AP
transitiveConnectsWithAttributesOnPathUnderAttack(SourceService,TargetService,CProvided,IProvided,AProvided,DFP,AP) <=  transitiveConnectsWithAttributesOnPathUnderAttack(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1,DFP1,AP) & connectsTo(IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2) & (SourceService._not_in(P1)) & (TargetService._not_in(P1)) & (SourceService!=TargetService) & (P==P1+[TargetService]) & (CProvided==(CProvided1 and CProvided2)) & (IProvided==(IProvided1 and IProvided2)) & (AProvided==(AProvided1 and AProvided2)) & isType(IntermediateService1,'networkDevice') & (TargetService._not_in(AP))
#This is when the TargetService is in the AP
#TODO This should be more granular in propagating C,I,A
transitiveConnectsWithAttributesOnPathUnderAttack(SourceService,TargetService,False,False,False,DFP,AP) <=  transitiveConnectsWithAttributesOnPathUnderAttack(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1,DFP1,AP) & connectsTo(IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2) & (SourceService._not_in(P1)) & (TargetService._not_in(P1)) & (SourceService!=TargetService) & (P==P1+[TargetService]) & (CProvided==(CProvided1 and CProvided2)) & (IProvided==(IProvided1 and IProvided2)) & (AProvided==(AProvided1 and AProvided2)) & isType(IntermediateService1,'networkDevice') & (TargetService._in(AP))
#If there's a compromise, we're saying all CIA attributes are False
#Switch back
#transitiveConnectsWithAttributesOnPath(SourceService,TargetService,False,False,False,P) <=  transitiveConnectsWithAttributesOnPath(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1,P1) & connectsToWithAttributes(IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2) & (SourceService._not_in(P1)) & (TargetService._not_in(P1)) & (P==P1+[TargetService]) & (CProvided==(CProvided1 and CProvided2)) & (IProvided==(IProvided1 and IProvided2)) & (AProvided==(AProvided1 and AProvided2)) & isType(IntermediateService1,'networkDevice') & compromised(IntermediateService1)

#Base cases
transitiveConnectsWithAttributesOnPathUnderAttack(SourceService,TargetService,CProvided,IProvided,AProvided,DFP,AP) <= connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided) & (DFP==[TargetService]) & ~compromised(SourceService,PC,CImpact,IImpact,AImpact) & ~compromised(TargetService,PC2,CImpact2,IImpact2,AImpact2) & (SourceService._not_in(AP)) & (TargetService._not_in(AP))
#If there's a compromise, we're saying all CIA attributes are False
#TODO Add granularity for compromise attributes and also if e.g. Source is compromised and Target is in AP
transitiveConnectsWithAttributesOnPathUnderAttack(SourceService,TargetService,False,False,False,DFP,AP) <= connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided) & (DFP==[TargetService]) & compromised(SourceService,PC,CImpact,IImpact,AImpact)
transitiveConnectsWithAttributesOnPathUnderAttack(SourceService,TargetService,False,False,False,DFP,AP) <= connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided) & (DFP==[TargetService]) & compromised(TargetService,PC,CImpact,IImpact,AImpact)


#dataPaths(FunctionA,Data,SourceService,TargetService,[[Path,C,I,A]]) <= [set of all paths of data for this function]

#transitiveConnectsWithAttributesPathForFunction(SourceService,TargetService,CProvided,IProvided,AProvided,P) <= (P==P2+[TargetService]) & (CProvided == (CProvided1 and CProvided2)) & (IProvided == (IProvided1 and IProvided2)) & (AProvided == (AProvided1 and AProvided2)) & transitiveConnectsWithAttributesPathForFunction(SourceService,IntermediateService1,CProvided1,IProvided1,AProvided1,P2) & connectsToWithAttributes(IntermediateService1,TargetService,CProvided2,IProvided2,AProvided2)
#Base case
#transitiveConnectsWithAttributesPathForFunction(SourceService,TargetService,CProvided,IProvided,AProvided,P) <= (P==[SourceService,TargetService]) & connectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided)
#Backward compatibility:
#transitiveConnects(SourceService,TargetService) <= transitiveConnectsWithAttributesPathForFunction(SourceService,TargetService,CProvided,IProvided,AProvided,P)
#connectsTo(SourceService,TargetService) <= connectsToWithAttributes(SourceService,TargetService,CProvided,IProvided,AProvided)

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
