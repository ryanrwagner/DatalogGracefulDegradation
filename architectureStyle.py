# HOST LOGIC

#If a service residesOn a host (represented by the superuser), then there is a connection from the superuser to the host
#The host superuser and the host are proxies for each other
connectsToWithPrivileges(SourceHost,SourceService) <= residesOn(SourceService,SourceHost)
#A user level service touches the superuser (without privileges)
connectsTo(SourceService,SourceHost) <= residesOn(SourceService,SourceHost)

#A network connection is a logical connection
connectsTo(SourceService,TargetService) <= networkConnectsTo(SourceService,TargetService)

transitiveConnects(SourceService,TargetService) <= transitiveConnects(SourceService,IntermediateService1) & connectsTo (IntermediateService1,TargetService)
transitiveConnects(SourceService,TargetService) <= connectsTo(SourceService,TargetService)

#is the component operational?
#attack/tactics pairing
#Get 0 utility if any contributing service not running or any is compromised
resultingUtil(FunctionA,-FuncAUtil) <= functionCompromised(FunctionA) & utility(FunctionA,FuncAUtil)
#Get full utility if all contributing services are running and all not compromised
resultingUtil(FunctionA,FuncAUtil) <= utility(FunctionA,FuncAUtil)
# resultingUtil(FunctionA,FuncAUtil) <= ~functionCompromised(FunctionA) & utility(FunctionA,FuncAUtil)

#resultingUtil(FunctionA,FuncAUtil) <= utility(FunctionA,FuncAUtil) & ~functionCompromised(FunctionA)


#Find all connection paths within the cost metric
#(TotalC==TotalC2+C) was changed to TotalC2+1 below. If there's a network path cost metric, this should be changed back
allConnectionPaths(SourceService,TargetService,P,TotalC) <= allConnectionPaths(SourceService,IntermediateService1,P2,TotalC2) & connectsTo(IntermediateService1,TargetService) & (SourceService!=TargetService) & (SourceService._not_in(P2)) & (TargetService._not_in(P2)) & (P==P2+[IntermediateService1]) & (TotalC==TotalC2+1) & (TotalC2+C <= maxRisk)
#Base case
allConnectionPaths(SourceService,TargetService,P,TotalC) <= connectsTo(SourceService,TargetService) & (P==[]) & (C==0)
