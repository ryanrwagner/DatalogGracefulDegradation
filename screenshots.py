+ utility('transmissionMgmt',50)
+ requiresFunction('transmissionMgmt','transmissionF')
+ utility('transmissionF',100)
+ requiresFunction('transmissionF','opcF')
+ implements('opcF','opc',0)
+ consumesData('transmissionMgmt','engineerWorkstation','statusRestData',False,0,True,1,True,0.5)

#Allocation/Deployments
+isType('opc','service')
+isType('switchA','switch')
+ networkConnectsToWithAttributes('opc','switchA',True,True,True)

#Style
validConnection(SourceService,TargetService) <= isType(SourceService,'switch') & isType(TargetService,'service')
