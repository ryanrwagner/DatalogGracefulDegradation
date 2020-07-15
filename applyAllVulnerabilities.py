#For each component (service), assume it has every relevant vulnerability possible
#If an exploit cost is not already specified, we make it equal to 1
#TODO: How to handle switches, routers, and firewalls?
remoteUserExploit(TargetService,1) <= isAccount(TargetService,'userAccount') & ~remoteUserExploit(TargetService,C)
localRootExploit(TargetService,1) <= isAccount(TargetService,'userAccount') & ~localRootExploit(TargetService,C)
remoteRootExploit(TargetService,1) <= isAccount(TargetService,'superUserAccount') & residesOn(IntermediateService1,TargetService) & ~remoteRootExploit(TargetService,C)
#Apply C, I, A vulns only if they have impact to functionalities
#For now, we're just doing one of C,I,A, but this should be all possible combinations
remoteRootExploitWithAttributes(TargetService,1,True,False,False) <= isAccount(TargetService,'superUserAccount') & residesOn(IntermediateService1,TargetService)
remoteRootExploitWithAttributes(TargetService,1,False,True,False) <= isAccount(TargetService,'superUserAccount') & residesOn(IntermediateService1,TargetService)
remoteRootExploitWithAttributes(TargetService,1,False,False,True) <= isAccount(TargetService,'superUserAccount') & residesOn(IntermediateService1,TargetService)
#TODO: Attacks on connectors
#UPPAAL?

#For Observations
#Backward compatibility
#remoteUserExploit(TargetService,C) <= remoteUserExploitWithAttributes(TargetService,C,CImpact,IImpact,AImpact)
#remoteUserExploitWithAttributes(TargetService,C,CImpact,IImpact,AImpact) <= remoteUserExploitWithAttObs(TargetService,C,CImpact,IImpact,AImpact,PObs)

#remoteRootExploit(TargetService,C) <= remoteRootExploitWithAttributes(TargetService,C,CImpact,IImpact,AImpact)
#emoteRootExploitWithAttributes(TargetService,C,CImpact,IImpact,AImpact) <= remoteRootExploitWithAttObs(TargetService,C,CImpact,IImpact,AImpact,PObs)
