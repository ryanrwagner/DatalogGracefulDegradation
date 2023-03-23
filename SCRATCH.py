#P is the Attack Path and 
#attackPathDoesntCompromiseFlow(P,FuncName,TargetService,Data) <= attackPaths(SourceService,TargetService,P,E,AttackerMoves,TotalC) & consumesPath(FuncName,TargetService,Data,P2) & consumesData(FuncName,TargetService,Data,COK,CImpact,IOK,IImpact,AOK,AImpact) & (len_(list(set(P).intersection(set(P2)))) > 0)

