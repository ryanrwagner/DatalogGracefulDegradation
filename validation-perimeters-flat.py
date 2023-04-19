#Attacker Profile
#probCapability[Capability] = PC where PC is the probability that the attacker has this capability
probCapability[0] = 0.2
probCapability[1] = 0.2
probCapability[2] = 0.2
probCapability[3] = 0.2
probCapability[4] = 0.2
+ compromised('attacker',0.9,True,True,True)
+ compromised('client',0.1,True,True,True)
+ isType('attacker','switch') #Making the attacker a switch type allows her to connect directly to any other component
+ hasCredential('attacker','null') #To make Datalog happy
+ usesCredential('attacker','null') #To make Datalog happy

#Additional architecture style information
#Firewalls
+ isSubType('fwA','firewall')
#+ isVulnerable('fwA','fwAExploit',1,0,0,0)
+ isVulnerable('fwA','fwAExploit',1,0.5,0.5,0.5)
+ isSubType('fwB','firewall')
+ isVulnerable('fwB','fwBExploit',1,0.1,0.1,0.1)
#+ isVulnerable('fwB','fwBExploit',1,0,0,0)
#Server
#+ isSubType('serverType','switch')
+ isVulnerable('serverType','serverExploit',1,0,0,0)
#Client
#+ isSubType('clientType','switch')
+ isVulnerable('clientType','clientExploit',1,0,0,0)
#Switch
+ isVulnerable('switch','switchPassThroughNoExploit',0,1,1,1)

#Client
+ isType('client','clientType')
+ hasCredentials('client',[])
#Firewall A1
+ isType('fwA1','fwA')
#+ hasCredentials('fwA1',[])
+ hasCredentials('fwA1',['fwPassword'])
+ usesCredential('fwA1','fwPassword')
#Firewall A2
+ isType('fwB1','fwB')
+ hasCredentials('fwB1',[])
#+ hasCredentials('fwB1',[])
+ usesCredential('fwB1','fwPassword')
#Server
+ isType('server','serverType')
+ hasCredentials('server',[])
#Switch1
+ isType('switch1','switch')
+ hasCredentials('switch1',[])
#For backwards compatibility
+ isType('serverHost','serverType')
+ hasCredentials('server',[])
+ residesOn('server','serverHost')
+ isAccount('serverHost','superUserAccount')
+ hasCredentials('serverHost',[])

#For compatibility now
+ producesData('server','serverData')
# + consumesData(FuncName,ConsumesSet,Data,CImpact,IImpact,AImpact)
+ consumesData('dataTransit',['client'],'serverData',0,1,0.5)

#Connections are bidirectional and between services

#No perimeter -- star topology
#+ connectsTo('attacker','switch1',True,True,True)
#+ connectsTo('fwA1','switch1',True,True,True)
#+ connectsTo('fwB1','switch1',True,True,True)
#+ connectsTo('client','switch1',True,True,True)
#+ connectsTo('server','switch1',True,True,True)

#Perimeter -- star topology on internal network
#+ connectsTo('attacker','fwA1',True,True,True)
#+ connectsTo('fwA1','switch1',True,True,True)
#+ connectsTo('fwB1','switch1',True,True,True)
#+ connectsTo('client','switch1',True,True,True)
#+ connectsTo('server','switch1',True,True,True)

#Tiers Degenerate: Two Firewalls in a Row
+ connectsTo('attacker','fwA1',True,True,True)
+ connectsTo('fwA1','fwB1',True,True,True)
+ connectsTo('fwB1','switch1',True,True,True)
+ connectsTo('client','switch1',True,True,True)
+ connectsTo('server','switch1',True,True,True)
#This is for an insider attack
#+ compromised('client',0.2,True,True,True)

#Tiers: Three Tiers
#+ connectsTo('attacker','fwA1',True,True,True)
#+ connectsTo('fwA1','switch1',True,True,True)
#+ connectsTo('client','switch1',True,True,True)
#+ connectsTo('switch1','fwB1',True,True,True)
#+ connectsTo('fwB1','switch2',True,True,True)
# connectsTo('server','switch2',True,True,True)
#+ isType('switch2','switch')
#This is for an insider attack
#+ compromised('client',0.2,True,True,True)


+ requires('attackerFunction','attacker')
+ requires('firewall','fwA1')
#+ requires('firewall','fwA2')
+ requires('firewall','fwB1')
#+ requires('firewall','fwB2')
+ requires('dataTransit','server')


#+ requires('nothing','attackerClient')
#+ utility('nothing',0)

#Utility
+ utility('attackerFunction',0)
+ utility('dataTransit',100)
+ utility('firewall',10)
