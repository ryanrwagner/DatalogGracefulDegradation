#TODO Add in declaration of names to main.py
#Functions are similar to PRA Master Logic Diagram
# Data consumption always is part of a subFunction
# subFunctions have no utility
# OR is treated as finding the maximum
# AND is treated as multiplication


#+ consumesData('userManagement',['client'],'serverData',0.0,0.75,0.25) #formerly dataTransit
#+ consumesData('userAuthorization',['client'],'serverData',0.0,0.75,0.25) #formerly dataTransit2
#+ consumesData('primaryDB',['client'],'dataA',0.0,0.75,0.25) #formerly dataTransit2
#+ consumesData('backupDB',['client'],'dataB',0.0,0.75,0.25) #formerly dataTransit2
#+ fNodeOr('databaseTables',['primaryDB','backupDB'])
#+ fNodeAnd('databases',['userAuthorization','databaseTables'])
consumesOptimalUnderAttackU(FName,Data,AttackerMoves,CP,UFraction) <= (consumesOptimalUnderAttack[FName,Data,AttackerMoves] == X) & (X == [CP,UFraction])
#Leaf node evaluation
#fNodeEvaluated(FName,UFraction,[CP],AttackerMoves,[[FName,CP,UFraction]]) <=  (consumesOptimalUnderAttack[FName,Data,AttackerMoves] == X) & (X == [CP,UFraction]) #& (Artifacts == [[FName,CP,UFraction]]) & (CPSet == [CP]) #& (Artifacts == [FName,UFraction,CPSet])
fNodeEvaluated(FName,UFraction,CPSet,AttackerMoves,Artifacts) <=  (consumesOptimalUnderAttack[FName,Data,AttackerMoves] == X) & (X == [CP,UFraction]) & (Artifacts == [[FName,CP,UFraction]]) & (CPSet == [CP]) #& (Artifacts == [FName,UFraction,CPSet])
#fNodeEvaluated(FName,UFraction,CPSet,AttackerMoves,Artifacts) <=  consumesOptimalUnderAttackU(FName,Data,AttackerMoves,CP,UFraction) & (Artifacts == [[FName,CP,UFraction]]) & (CPSet == [CP]) #& (Artifacts == [FName,UFraction,CPSet])

#OR:
#fNode(FName,UFraction) <= + consumesData('dataTransit2',['client'],'dataB',0.0,0.75,0.25) & SourceService in ConsumesSet
#Base case
#We have an OR node, the calculation isn't complete, we pop the first element of the remaining set, so this subnode is the best so far
fNodeOrPartial(FName,FNodeSet,UFraction,CPSet,AttackerMoves,Artifacts) <= fNodeOr(FName,FNodeSet2) & (FNodeSet2 != []) & (FName2 == FNodeSet2[0]) & (FNodeSet == FNodeSet2[1:]) & fNodeEvaluated(FName2,UFraction,CPSet,AttackerMoves,Artifacts)
#Inductive case for this new subnode being better (Next is equal or worse)
#We have an OR node, the calculation isn't complete, we pop the first element of the remaining set, and this path node is better or equal to the previous node
fNodeOrPartial(FName,FNodeSet,UFraction,CPSet,AttackerMoves,Artifacts) <= fNodeOrPartial(FName,FNodeSet2,UFraction2,CPSet2,AttackerMoves,Artifacts2) & (FNodeSet2 != []) & (FName2 == FNodeSet2[0]) & (FNodeSet == FNodeSet2[1:]) & fNodeEvaluated(FName2,UFraction3,CPSet3,AttackerMoves,Artifacts3) & (UFraction3 > UFraction2) & (UFraction == UFraction3) & (CPSet == CPSet3) & (Artifacts == Artifacts3)
#Inductive case for this new subnode being equal or worse
#We have an OR node, the calculation isn't complete, we pop the first element of the remaining set, and this path node is better or equal to the previous node
fNodeOrPartial(FName,FNodeSet,UFraction,CPSet,AttackerMoves,Artifacts) <= fNodeOrPartial(FName,FNodeSet2,UFraction2,CPSet2,AttackerMoves,Artifacts2) & (FNodeSet2 != []) & (FName2 == FNodeSet2[0]) & (FNodeSet == FNodeSet2[1:]) & fNodeEvaluated(FName2,UFraction3,CPSet3,AttackerMoves,Artifacts3) & (UFraction3 <= UFraction2) & (UFraction == UFraction2) & (CPSet == CPSet2) & (Artifacts == Artifacts2)
#Clean up to create another fNode
fNodeEvaluated(FName,UFraction,CPSet,AttackerMoves,Artifacts) <= fNodeOrPartial(FName,FNodeSet,UFraction,CPSet,AttackerMoves,Artifacts) & (FNodeSet == [])
#AND:
#Base case
#We have an AND node, the calculation isn't complete, we pop the first element of the remaining set, so this subnode is all we have so far
fNodeAndPartial(FName,FNodeSet,UFraction,CPSet,AttackerMoves,Artifacts) <= fNodeAnd(FName,FNodeSet2) & (FNodeSet2 != []) & (FName2 == FNodeSet2[0]) & (FNodeSet == FNodeSet2[1:]) & fNodeEvaluated(FName2,UFraction,CPSet,AttackerMoves,Artifacts)
#Inductive case
#We have an AND node, the calculation isn't complete, we pop the first element of the remaining set, and we multiply the utility of this subnode with the product so far
fNodeAndPartial(FName,FNodeSet,UFraction,CPSet,AttackerMoves,Artifacts) <= fNodeAndPartial(FName,FNodeSet2,UFraction2,CPSet2,AttackerMoves,Artifacts2) & (FNodeSet2 != []) & (FName2 == FNodeSet2[0]) & (FNodeSet == FNodeSet2[1:]) & fNodeEvaluated(FName2,UFraction3,CPSet3,AttackerMoves,Artifacts3) & (UFraction ==  UFraction2 * UFraction3) & (CPSet == CPSet2 + CPSet3) & (Artifacts == Artifacts2 + Artifacts3)
#Clean up to create another fNode
fNodeEvaluated(FName,UFraction,CPSet,AttackerMoves,Artifacts) <= fNodeAndPartial(FName,FNodeSet,UFraction,CPSet,AttackerMoves,Artifacts) & (FNodeSet == [])
#mission() <= fNode() & utility() #objective? task? mission success criteria?
#missionEvaluated
# sum_ (P[X]==sum_(Y, for_each=Z)) <= body : P[X] is the sum of Y for each Z. (Z is used to distinguish possibly identical Y values)
fNodeResidualU(FName,U,AttackerMoves,Artifacts) <= fNodeEvaluated(FName,UFraction,CPSet,AttackerMoves,Artifacts) & utility(FName,U2) & (U == UFraction * U2)
(totalResidualUtility[AttackerMoves,Artifacts] == sum_(U, for_each=FName)) <= fNodeResidualU(FName,U,AttackerMoves,Artifacts)







# New, refactored logic
# C,I,A tracking
# Functionality evaluated in context of an attack trace
# Backups
# (Later, maybe: Data flows)







# OLD LOGIC Before Refactoring
# 


#function is compromised/questionable if service is required and compromised/questionable
#requiresSecurityAttribute('transmissionMgmt','integrity','trMgmtCommandData','engineerWorkstation','1.0')
functionCompromised(FunctionA,U) <= requires(FunctionA,ServiceA) & compromised(ServiceA,PC,CImpact,IImpact,AImpact) & utility(FunctionA,U)
functionCompromisedWithAttributes(FunctionA,U,Confidentiality,Integrity,Availability) <= requiresSecurityAttribute(FunctionA,DatumA,ServiceA,PercentDegradation) #Can I do product here like sum? compromisedWithAttributes(ServiceA,Confidentiality,Integrity,Availability)
#function is compromised/questionable if two connected services are both required and can't reach each other
#functionCompromised(FunctionA,C) <= requires(FunctionA,ServiceA) & compromised(ServiceA) & utility(FunctionA,C)
#I don't know that the below statement works
functionUncompromised(FunctionA,U) <= ~(functionCompromised(FunctionA,U))

#questionable(TargetService) means in allAttackerPaths(SourceService,TargetService,P,E,TotalC) where SourceService is any compromised service, P is anything, E is anything, and TotalC is a chosen risk metric
functionDownOrCompromised(FunctionA,U) <= functionCompromised(FunctionA,U)
functionDownOrCompromised(FunctionA,U) <= functionDown(FunctionA,U)
#Transitive Down or Compromised
functionDownOrCompromised(FunctionA,U) <= utility(FunctionA,U) & requires(FunctionA,FunctionB) & functionDownOrCompromised(FunctionB,U2)


#Transitive Requires
#Function A requires Function C if (Function A requires Function B) and (Function B requires Function C)
requiresFunction(FunctionA,FunctionC) <= requiresFunction(FunctionA,FunctionB) & requiresFunction(FunctionB,FunctionC)
#NOTE: Do we need a data-need hierarchy, too?
#TODO: Requires OR for functions, requires AND for functions, with utility decreases

# This could explode the state space
# If I don't include AP as an argument, then I have to build all the paths and run the calculations later
# If I do include AP as an arguement, then I have more state to track
# I want to stop generating this path when a better one exists or if required C,I,A is all gone (if AP is an argument)
# I might need to limit the number of hops in the path
# I don't want cycles in the path
# Do I need to track the C,I,A for each component?
# I'm doing the multiplication on the APs. I should do that here, instead?
#consumesDataOnPath()