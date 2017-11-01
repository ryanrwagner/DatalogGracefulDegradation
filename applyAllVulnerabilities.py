remoteUserExploit(TargetService,1) <= isA(TargetService,'userAccount')
localRootExploit(TargetService,1) <= isA(TargetService,'userAccount')
remoteRootExploit(TargetService,1) <= isA(TargetService,'superUserAccount') & residesOn(IntermediateService1,TargetService)
