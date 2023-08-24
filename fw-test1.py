#Attacker Profile
#probCapability[Capability] = PC where PC is the probability that the attacker has this capability
probCapability[0.0] = 0.2
probCapability[1.0] = 0.2
probCapability[2.0] = 0.2
probCapability[3.0] = 0.2
probCapability[4.0] = 0.2


#isA(Service,Type)
#num3=list(set(num1+num2))
+ isSubType('fwA','firewall')
#isVulnerable('fwA','fwAExploit',1.0,1.0,1.0,1.0)

+ isSubType('fwB','firewall')
#isVulnerable('fwB','fwAExploit',1.0,1.0,1.0,1.0)


# A server is a type of switch for this example (allows for direct connections to firewalls)
+ isSubType('serverType','switch')
+ isSubType('server2Type','switch')


#Attacker
#+ isA('attacker','userAccount')
+ isType('attacker','switch')
+ hasCredentials('attacker',[]) #To make Datalog happy
+ usesCredential('attacker','null') #To make Datalog happy

#Client
#+ isA('client','userAccount')
+ isType('client','clientType')
+ isSubType('clientType','switch')
+ hasCredentials('client',[])


#Firewall A1
#+ isAccount('fwA1','userAccount')
+ isType('fwA1','fwA')
#Note that A1 has the "credentials" to exploit fwB firewalls
#+ hasCredentials('fwA1',['fwBExploit'])
+ hasCredentials('fwA1',[])


#Firewall A2
#+ isAccount('fwA2','userAccount')
+ isType('fwA2','fwA')
+ hasCredentials('fwA2',[])

#Firewall B1
+ isType('fwB1','fwB')
+ hasCredentials('fwB1',[])
#+ isAccount('fwB1','userAccount')

#Firewall B2
+ isType('fwB2','fwB')
+ hasCredentials('fwB2',[])
#+ isAccount('fwB2','userAccount')

#+ isVulnerable('fwA','fwAExploit',1.0,0.0,0.0,0.0)
+ isVulnerable('fwA','fwAExploit',1.0,0.5,0.5,0.5)
+ isVulnerable('fwB','fwBExploit',1.0,0.0,0.0,0.0)
#+ isVulnerable('serverType','serverExploit',1.0,0.0,0.0,0.0)
+ isVulnerable('serverType','serverExploit',1.0,0.9,0.9,0.9)
+ isVulnerable('server2Type','server2Exploit',1.0,0.9,0.9,0.9)



#Server
#+ isAccount('server','userAccount')
+ isType('server','serverType')
+ hasCredentials('server',[])
#BackupServer
+ isType('serverBackup','server2Type')
#Note: Reusing credentials for server and serverBackup should be a problem since it's a similar vulnerability
+ hasCredentials('serverBackup',[])

#For compatibility
+ isAccount('serverHost','superUserAccount')
+ isType('serverHost','switch')
+ hasCredential('serverHost',[])
+ residesOn('server','serverHost')

+ producesData('server','serverData')
+ producesData('serverBackup','serverData')
+ producesData('server','dataA')
+ producesData('serverBackup','dataB')
+ consumesData('dataTransit',['client'],'serverData',0.0,0.75,0.25)
+ consumesData('dataTransit2',['client'],'serverData',0.0,0.75,0.25)
+ consumesData('dataTransit2',['client'],'dataA',0.0,0.75,0.25)
+ consumesData('dataTransit2',['client'],'dataB',0.0,0.75,0.25)
#+ consumesData('dataTransit',['attacker'],'serverData',0.0,1.0,0.5)

#TODO Add in definition of names
#Functions are similar to PRA Master Logic Diagram
# Data consumption always is part of a subFunction
# subFunctions have no utility
# OR is treated as finding the maximum
# AND is treated as multiplication
fLeaf(FName,UFraction) <= consumesData(FuncName,ConsumesSet,Data,CImpact,IImpact,AImpact)
#OR:
fNode(FName,UFraction) <= + consumesData('dataTransit2',['client'],'dataB',0.0,0.75,0.25) & SourceService in ConsumesSet
fNode(FName,UFraction,AttackerMoves) <= con
#Base case
fNodeOrPartial(FName,UFraction,FNodeSet) <= fNodeOr(FNodeSet2) & (FNodeSet2 != []) & ([FName2,UFraction2] == fNodeSet2[0]) & (fNodeSet == fNodeSet2[1:]) & (UFraction ==  UFraction2)
#Inductive case
fNodeOrPartial(FName,UFraction,fNodeSet) <= fNodeOrPartial(FName2,UFraction2,fNodeSet2) & (fNodeSet2 != []) & ([FName2,UFraction3] == fNodeSet2[0]) & (fNodeSet == fNodeSet2[1:]) & (UFraction ==  UFraction2 * UFraction3)
#Clean up to create another fNode
fNode(FName,UFraction) <= fNodeOrPartial(FName,UFraction,fNodeSet) & (fNodeSet == [])
#AND:
fNode(FName,UFraction) <= + consumesData('dataTransit2',['client'],'dataB',0.0,0.75,0.25) & SourceService in ConsumesSet
fNode(FName,)
#Base case
fNodeAndPartial(FName,UFraction,fNodeSet) <= fNodeAnd(fNodeSet2) & (fNodeSet2 != []) & ([FName2,UFraction2] == fNodeSet2[0]) & (fNodeSet == fNodeSet2[1:]) & (UFraction ==  UFraction2)
#Inductive case
fNodeAndPartial(FName,UFraction,fNodeSet) <= fNodeAndPartial(FName2,UFraction2,fNodeSet2) & (fNodeSet2 != []) & ([FName2,UFraction3] == fNodeSet2[0]) & (fNodeSet == fNodeSet2[1:]) & (UFraction ==  UFraction2 + UFraction3)
#Clean up to create another fNode
fNode(FName,UFraction) <= fNodeAndPartial(FName,UFraction,fNodeSet) & (fNodeSet == [])
#mission() <= fNode() & utility() #objective? task? mission success criteria?

#Connections are bidirectional and between services
# connectsTo(SourceService,TargetService)
#Configuration for availability
# client -> fwA1 -> fwA2 -> server
# client -> fwB1 -> fwB2 -> server
+ connectsTo('attacker','fwA1',0.0,0.0,0.0)
+ connectsTo('attacker','fwB1',0.0,0.0,0.0)
+ connectsTo('client','fwA1',1.0,1.0,1.0)
+ connectsTo('client','fwB1',1.0,1.0,1.0)
+ connectsTo('fwA1','fwA2',0.5,0.5,0.5)
+ connectsTo('fwB1','fwB2',1.0,1.0,1.0)
#+ connectsTo('fwA2','server',1.0,1.0,1.0)
#+ connectsTo('fwB2','server',1.0,1.0,1.0)
+ connectsTo('fwA2','serverBackup',1.0,1.0,1.0)
+ connectsTo('fwB2','serverBackup',1.0,1.0,1.0)

#Configuration for security
#+ connectsTo('attacker','fwA1',True,True,True)
#+ connectsTo('attacker','fwA2',True,True,True)
#+ connectsTo('client','fwA1',True,True,True)
#+ connectsTo('client','fwA2',True,True,True)
#+ connectsTo('fwA1','fwB1',True,True,True)
#+ connectsTo('fwA2','fwB2',True,True,True)
#+ connectsTo('fwB1','server',True,True,True)
#+ connectsTo('fwB2','server',True,True,True)


#+ compromised('attacker')
#+ probCompromised('attacker',1.0)
+ compromised('attacker',1.0,True,True,True)

+ requires('attackerFunction','attacker')
+ requires('firewall','fwA1')
+ requires('firewall','fwA2')
+ requires('firewall','fwB1')
+ requires('firewall','fwB2')
+ requires('dataTransit','server')
+ requires('dataTransit','serverBackup')

#+ requiresData('dataTransit')
#TODO make the consumesAttackImact not function-specific
#+ fRequiresData(function,data,U,Impact) ... I need some sort of and / or structure...maybe with + and *? maybe as andFD orFD with arrays?
#+ fRequresFunction(function,function,U,Impact)
# rUtility('totalSystem',AttackerMoves,CP,RU) = rUtility(')

#+ requires('nothing','attackerClient')
#+ utility('nothing',0)

#Utility
+ utility('attackerFunction',0.0)
+ utility('dataTransit',100.0)
+ utility('firewall',10.0)
+ utility('dataTransit2',50.0)


