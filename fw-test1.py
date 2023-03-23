#Attacker Profile
#probCapability[Capability] = PC where PC is the probability that the attacker has this capability
probCapability[0] = 0.2
probCapability[1] = 0.2
probCapability[2] = 0.2
probCapability[3] = 0.2
probCapability[4] = 0.2


#isA(Service,Type)
#num3=list(set(num1+num2))
+ isSubType('fwA','firewall')
#isVulnerable('fwA','fwAExploit',1,1,1,1)

+ isSubType('fwB','firewall')
#isVulnerable('fwB','fwAExploit',1,1,1,1)


# A server is a type of switch for this example (allows for direct connections to firewalls)
+ isSubType('serverType','switch')

#Attacker
#+ isA('attacker','userAccount')
+ isType('attacker','switch')
+ hasCredential('attacker','null') #To make Datalog happy
+ usesCredential('attacker','null') #To make Datalog happy

#Client
#+ isA('client','userAccount')
+ isType('client','clientType')
+ isSubType('clientType','switch')

#+ hasCredential('client',[])


#Firewall A1
#+ isAccount('fwA1','userAccount')
+ isType('fwA1','fwA')
#Note that A1 has the "credentials" to exploit fwB firewalls
#+ hasCredential('fwA1',['fwBExploit'])

#Firewall A2
#+ isAccount('fwA2','userAccount')
+ isType('fwA2','fwA')
#+ hasCredential('fwA2',[])

#Firewall B1
+ isType('fwB1','fwB')
#+ hasCredential('fwB1',[])
#+ isAccount('fwB1','userAccount')

#Firewall B2
+ isType('fwB2','fwB')
#+ hasCredential('fwB2',[])
#+ isAccount('fwB2','userAccount')

+ isVulnerable('fwA','fwAExploit',1,0,0,0)
+ isVulnerable('fwB','fwBExploit',1,0,0,0)
+ isVulnerable('serverType','serverExploit',1,0,0,0)

#Server
#+ isAccount('server','userAccount')
+ isType('server','serverType')
#+ hasCredential('server',[])


#For compatibility
+ isAccount('serverHost','superUserAccount')
+ isType('serverHost','switch')
#+ hasCredential('serverHost',[])
+ residesOn('server','serverHost')

+ producesData('server','serverData')
+ consumesData('dataTransit','client','serverData',False,0,True,1,True,0.5)

#Connections are bidirectional and between services
# connectsTo(SourceService,TargetService)
#Configuration for availability
# client -> fwA1 -> fwA2 -> server
# client -> fwB1 -> fwB2 -> server
+ connectsTo('attacker','fwA1',True,True,True)
+ connectsTo('attacker','fwB1',True,True,True)
+ connectsTo('client','fwA1',True,True,True)
+ connectsTo('client','fwB1',True,True,True)
+ connectsTo('fwA1','fwA2',True,True,True)
+ connectsTo('fwB1','fwB2',True,True,True)
+ connectsTo('fwA2','server',True,True,True)
+ connectsTo('fwB2','server',True,True,True)

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


#+ requires('nothing','attackerClient')
#+ utility('nothing',0)

#Utility
+ utility('attackerFunction',0)
+ utility('dataTransit',100)
+ utility('firewall',10)
