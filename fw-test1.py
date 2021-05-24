#isA(Service,Type)
#num3=list(set(num1+num2))
+ isSubType('fwA','firewall')
+ isSubType('fwB','firewall')
+ isSubType('serverType','switch')
+ isA('attacker','userAccount')
+ isType('attacker','switch')
+ hasCredentials('attacker',[])
+ isA('client','userAccount')
+ isType('client','switch')
+ hasCredentials('client',[])
+ isAccount('server','userAccount')
+ isType('server','serverType')
+ hasCredentials('server',[])
+ isAccount('fwA1','userAccount')
+ isType('fwA1','fwA')
+ hasCredentials('fwA1',['fwBExploit'])
+ isAccount('fwA2','userAccount')
+ isType('fwA2','fwA')
+ hasCredentials('fwA2',[])
+ isAccount('fwB1','userAccount')
+ isType('fwB1','fwB')
+ hasCredentials('fwB1',[])
+ isAccount('fwB2','userAccount')
+ isType('fwB2','fwB')
+ hasCredentials('fwB2',[])
+ existsExploit('fwA','fwAExploit',1,0,0,0,False)
+ existsExploit('fwB','fwBExploit',1,0,0,0,False)
+ existsExploit('serverType','serverExploit',0,0,0,0,False)
#For compatibility
+ isAccount('serverHost','superUserAccount')
+ isType('serverHost','switch')
+ hasCredentials('serverHost',[])
+ residesOn('server','serverHost')

+ producesData('server','serverData')
+ consumesData('dataTransit','client','serverData',False,0,True,1,True,0.5)

#Connections are directional and between services
# connectsTo(SourceService,TargetService)
#Configuration for availability
# client -> fwA1 -> fwA2 -> server
# client -> fwB1 -> fwB2 -> server
#+ networkConnectsToWithAttributes('attacker','fwA1',True,True,True)
#+ networkConnectsToWithAttributes('attacker','fwB1',True,True,True)
#+ networkConnectsToWithAttributes('client','fwA1',True,True,True)
#+ networkConnectsToWithAttributes('client','fwB1',True,True,True)
#+ networkConnectsToWithAttributes('fwA1','fwA2',True,True,True)
#+ networkConnectsToWithAttributes('fwB1','fwB2',True,True,True)
#+ networkConnectsToWithAttributes('fwA2','server',True,True,True)
#+ networkConnectsToWithAttributes('fwB2','server',True,True,True)

#Configuration for security
+ networkConnectsToWithAttributes('attacker','fwA1',True,True,True)
+ networkConnectsToWithAttributes('attacker','fwA2',True,True,True)
+ networkConnectsToWithAttributes('client','fwA1',True,True,True)
+ networkConnectsToWithAttributes('client','fwA2',True,True,True)
+ networkConnectsToWithAttributes('fwA1','fwB1',True,True,True)
+ networkConnectsToWithAttributes('fwA2','fwB2',True,True,True)
+ networkConnectsToWithAttributes('fwB1','server',True,True,True)
+ networkConnectsToWithAttributes('fwB2','server',True,True,True)


#+ compromised('attacker')
#+ probCompromised('attacker',1.0)
+ componentCompromisedWithAttributes('attacker',1.0,True,True,True)

+ requires('firewall','fwA1')
+ requires('firewall','fwA2')
+ requires('firewall','fwB1')
+ requires('firewall','fwB2')

#+ requires('nothing','attackerClient')
#+ utility('nothing',0)

#Utility
#+ requires('dataTransit','server')
+ utility('dataTransit',100)
+ utility('firewall',0)
