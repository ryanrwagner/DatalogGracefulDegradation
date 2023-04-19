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