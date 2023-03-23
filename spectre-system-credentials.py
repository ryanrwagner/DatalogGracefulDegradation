#Signatures:
#networkConnectsToWithAttributes(ServiceA,ServiceB,CProvided,IProvided,AProvided)
#consumesData(FunctionA,ServiceA,Data)
#producesData(ServiceB,Data)
#requiresDataWithAttributes(FunctionA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact)

#Note the differences below for historian, engineerWorkstation,
#ntp, and power-provider

+isAccount('opc','userAccount')
+usesCredential('opc','admin')
+isType('opc','service')
#NOTE: Address backups later
#+isAccount('opc-backup','userAccount')
#+isType('opc-backup','service')
+isAccount('hmi','userAccount')
+usesCredential('hmi','admin')
+isType('hmi','service')
+isAccount('scadaServer','userAccount')
+usesCredential('scadaServer','admin')
+isType('scadaServer','service')
+isAccount('relayRicky','userAccount')
+isType('relayRicky','service')
+isAccount('relayLouie','userAccount')
+isType('relayLouie','service')
+isAccount('rtus','userAccount')
+isType('rtus','service')
+isAccount('secondaryHistorian','userAccount')
+isType('secondaryHistorian','service')

#Internal Primary
+isAccount('printer','userAccount')
+usesCredential('printer','admin1')
+isType('printer','service')
+isAccount('ntp','userAccount')
+usesCredential('ntp','admin1')
+isType('ntp','service')
+isAccount('historian','userAccount')
+usesCredential('historian','admin1')
+isType('historian','service')
+isAccount('engineerWorkstation','userAccount')
+usesCredential('engineerWorkstation','admin1')
#Note that this has the credential
+hasCredential('engineerWorkstation','admin1')
+isType('engineerWorkstation','service')
+isAccount('sw1','userAccount')
+isType('sw1','switch')

#Internal Hot Backup
#+isAccount('printer','userAccount') #Only one is needed
#+isType('printer','service')
+isAccount('ntp2','userAccount')
+isType('ntp2','service')
+isAccount('historian2','userAccount')
+isType('historian2','service')
+isAccount('engineerWorkstation2','userAccount')
+isType('engineerWorkstation2','service')
+isAccount('sw12','userAccount')
+isType('sw12','switch')

#DMZ to Internet
+isAccount('dmzFirewall','userAccount')
+isType('dmzFirewall','firewall')
+isAccount('sw3','userAccount')
+isType('sw3','switch')
+isAccount('vpn','userAccount')
+isType('vpn','service')
+isAccount('vpnSU','superUserAccount')
+isType('vpnSU','service')
+residesOn('vpn','vpnSU')
+isType('vpnSU','service')

#Just for allAttackerPathsWithTyping
#For testing when connections go down
#+isAccount('sw4','userAccount')
#+isType('sw4','switch')
+isAccount('router','userAccount')
+isType('router','router')
+ networkConnectsToWithAttributes('opc','sw4',True,True,True)
+ networkConnectsToWithAttributes('sw4','router',True,True,True)
+ networkConnectsToWithAttributes('relayRicky','sw4',True,True,True)

#+ networkConnectsToWithAttributes('rtus','scadaServer',True,True,True)

#Switched back
+ networkConnectsToWithAttributes('opc','sw1',True,True,True)
#+ networkConnectsToWithAttributes('opc','sw1',False,True,True)
+ networkConnectsToWithAttributes('hmi','sw1',True,True,True)
+ networkConnectsToWithAttributes('scadaServer','sw1',True,True,True)
+ networkConnectsToWithAttributes('relayRicky','sw1',True,True,True)
+ networkConnectsToWithAttributes('relayLouie','sw1',True,True,True)
+ networkConnectsToWithAttributes('rtus','sw1',True,True,True)

#+ networkConnectsToWithAttributes('rtus','sw1',True,True,True)
#+ networkConnectsToWithAttributes('opcScadaRelaysRTUs','sw1')
#+ networkConnectsToWithAttributes('printer','sw1',True,True,True)
+ networkConnectsToWithAttributes('ntp','sw1',True,True,True)
+ networkConnectsToWithAttributes('historian','sw1',True,True,True)
+ networkConnectsToWithAttributes('engineerWorkstation','sw1',True,True,True)
+ networkConnectsToWithAttributes('sw1','router',True,True,True)
+ networkConnectsToWithAttributes('router','sw2',True,True,True)
+ networkConnectsToWithAttributes('sw1','dmzFirewall',True,True,True)
+ networkConnectsToWithAttributes('dmzFirewall','sw3',True,True,True)
+ networkConnectsToWithAttributes('sw3','vpn',True,True,True)
+ networkConnectsToWithAttributes('sw3','secondaryHistorian',True,True,True)

+ networkConnectsToWithAttributes('printer','sw1',True,True,True)
#NOTE: opc-backup isn't connected to anything just yet

#Secondary Connection Set
+ networkConnectsToWithAttributes('opc2','sw12',True,True,True)
#+ networkConnectsToWithAttributes('opc2','sw12',False,True,True)
+ networkConnectsToWithAttributes('hmi2','sw12',True,True,True)
+ networkConnectsToWithAttributes('scadaServer2','sw12',True,True,True)
#+ networkConnectsToWithAttributes('relayRicky','sw1',True,True,True)
#+ networkConnectsToWithAttributes('relayLouie','sw1',True,True,True)
#+ networkConnectsToWithAttributes('rtus','sw1',True,True,True)
#+ networkConnectsToWithAttributes('rtus','sw1',True,True,True)
#+ networkConnectsToWithAttributes('opcScadaRelaysRTUs','sw1')
#+ networkConnectsToWithAttributes('printer','sw1',True,True,True)
+ networkConnectsToWithAttributes('ntp2','sw12',True,True,True)
+ networkConnectsToWithAttributes('historian2','sw12',True,True,True)
+ networkConnectsToWithAttributes('engineerWorkstation2','sw12',True,True,True)
+ networkConnectsToWithAttributes('sw12','router',True,True,True)
+ networkConnectsToWithAttributes('sw12','dmzFirewall',True,True,True)


+ utility('transmissionF',100)
#NOTE: This should ultimately be something like hmiF probably for handling backups
#Maybe with a list of options
#Or multiple consumesData facts might do just as well
#NOTE: Are multiple consumes statements ands or ors?
#Producer type and consumer type
#Port property for function or each port represent a single function. Probably one-to-one function/port
#Protocol stack: connectors could have reprentations or just connector properties (probably the latter)
#Can't write a constraint that looks from port up to component (undecideable)
#Past research: STRIDE on data flow

+ producesData('rtus','statusModbusData')
+ consumesData('transmissionF','opcF','statusModbusData',False,0,True,1,True,0.5)
+ implements('opc','opcF')
+ implements('opc2','opcF')
#TODO: I need a rule saying that if opc2 consumes the data, then it produces the data--a producesIfConsumes rule
#+ consumesData('transmissionF','opc','statusModbusData',False,0,True,1,True,0.5)
#+ consumesData('transmissionF','opc2','statusModbusData',False,0,True,1,True,0.5)

#+ requiresDataWithAttributes('transmissionF','statusModbusData',False,0,True,1,True,0.5)

+ producesData('opc','statusRestData')
+ consumesData('transmissionF','scadaServer','statusRestData',False,0,True,1,True,0.5)
+ consumesData('transmissionF','hmi','statusRestData',False,0,True,1,True,0.5)

#+ requiresDataWithAttributes('transmissionF','statusRestData',False,0,True,1,True,0.5)

+ producesData('scadaServer','actionsRickyRestData')
+ consumesData('transmissionF','opc','actionsRickyRestData',True,0,True,1,True,1.0)
#+ requiresDataWithAttributes('transmissionF','',False,0,True,1,True,1.0)

+ producesData('scadaServer','actionsLouieRestData')
+ consumesData('transmissionF','opc','actionsLouieRestData',False,0,True,1,True,1.0)
#+ requiresDataWithAttributes('transmissionF','',False,0,True,1,True,1.0)

+ producesData('opc','actionsRickyModbusData')
+ consumesData('transmissionF','relayRicky','actionsRickyModbusData',False,0,True,1,True,1.0)
#+ requiresDataWithAttributes('transmissionF','actionsRickyModbusData',False,0,True,1,True,1.0)

+ producesData('opc','actionsLouieModbusData')
+ consumesData('transmissionF','relayLouie','actionsLouieModbusData',False,0,True,1,True,1.0)
#+ requiresDataWithAttributes('transmissionF','actionsRickyModbusData',False,0,True,1,True,1.0)

#+ consumesData('transmissionF','relayLouie','actionsLouieModbusData')
#+ consumesData('transmissionF','relayRicky','actionsRickyModbusData')
#+ requiresDataWithAttributes('transmissionF','actionsRickyRestData',False,0,True,1,True,1.0)
#+ requiresDataWithAttributes('transmissionF','actionsLouieRestData',False,0,True,1,True,1.0)
#+ requiresDataWithAttributes('transmissionF','actionsModbusData',False,0,True,1,True,1.0)





+ implements('opcF','opc',0)
#NOTE: Address backups later
#+ implements('opcF','opc-backup',0)
+ implements('hmiF','hmi',0)
#+ implements('hmiF','hmi-backup',-5)
+ implements('scadaServerF','scadaServer',0)
#+ implements('scadaServerF','scadaServer-backup',-5)




+ utility('transmissionMgmt',50)
# Note the workstation is required here but not for transmission
#+ requires('transmissionMgmt','engineerWorkstation')
+ producesData('engineerWorkstation','trMgmtCommandData')
+ consumesData('transmissionMgmt','scadaServer','trMgmtCommandData',False,0,True,1,True,0.5)
#+ requiresDataWithAttributes('transmissionMgmt','trMgmtCommandData',False,0,True,1,True,0.5)

+ consumesData('transmissionMgmt','engineerWorkstation','statusRestData',False,0,True,1,True,0.5)
#+ requiresDataWithAttributes('transmissionMgmt','statusRestData',False,0,True,1,True,0.5)

+ requiresFunction('transmissionMgmt','transmissionF')

#+ requires('transmissionMgmt','opc')
#+ requires('transmissionMgmt','hmi')
#+ requires('transmissionMgmt','scadaServer')
#+ requires('transmissionMgmt','relayLouie')
#+ requires('transmissionMgmt','relayRicky')

#+ requires('transmissionMgmt','router')
#+ requires('transmissionMgmt','dmzFirewall')
#+ requires('transmissionMgmt','rtus')
#+ requiresConnection('transmissionMgmt','engineerWorkstation','scadaServer')
#+ requiresConnection('transmissionMgmt','opc','scadaServer')
#+ requiresConnection('transmissionMgmt','hmi','scadaServer')
#+ requiresConnection('transmissionMgmt','relayLouie','scadaServer')
#+ requiresConnection('transmissionMgmt','relayRicky','scadaServer')
#+ requiresConnection('transmissionMgmt','relayLouie','scadaServer')
#+ requiresConnection('transmissionMgmt','rtus','scadaServer')
#+ requires('transmissionMgmt','rtu1')
#+ requires('transmissionMgmt','rtu2')
#+ requires('transmissionMgmt','rtu3')
#+ requires('transmissionMgmt','rtu4')
#+ requires('transmissionMgmt','rtu5')
#+ requires('transmissionMgmt','rtu6')
#+ requires('transmissionMgmt','rtu7')
#+ requires('transmissionMgmt','rtu8')
#requiresAllConnections('transmissionMgmt') <= requiresConnection('transmissionMgmt','engineerWorkstation','scadaServer') & requiresConnection('transmissionMgmt','opc','scadaServer') & requiresConnection('transmissionMgmt','hmi','scadaServer') & requiresConnection('transmissionMgmt','relayLouie','scadaServer') & requiresConnection('transmissionMgmt','relayRicky','scadaServer') & requiresConnection('transmissionMgmt','relayLouie','scadaServer') & requiresConnection('transmissionMgmt','rtu1','scadaServer') & requiresConnection('transmissionMgmt','rtu2','scadaServer') & requiresConnection('transmissionMgmt','rtu3','scadaServer') & requiresConnection('transmissionMgmt','rtu4','scadaServer') & requiresConnection('transmissionMgmt','rtu5','scadaServer') & requiresConnection('transmissionMgmt','rtu6','scadaServer') & requiresConnection('transmissionMgmt','rtu7','scadaServer') & requiresConnection('transmissionMgmt','rtu8','scadaServer')

+ utility('transmissionLogs',20)
+ requires('transmissionLogs','historian')
+ requires('transmissionLogs','ntp')
+ requires('transmissionLogs','opc')
#+ requires('transmissionLogs','hmi')
+ requires('transmissionLogs','scadaServer')
+ requires('transmissionLogs','relayLouie')
+ requires('transmissionLogs','relayRicky')
+ requires('transmissionLogs','secondaryHistorian')
#+ requires('transmissionLogs','router')
#+ requires('transmissionLogs','dmzFirewall')
+ requires('transmissionLogs','rtus')
+ requiresConnection('transmissionLogs','ntp','historian')
+ requiresConnection('transmissionLogs','scadaServer','historian')
+ requiresConnection('transmissionLogs','opc','historian')
+ requiresConnection('transmissionLogs','hmi','historian')
+ requiresConnection('transmissionLogs','relayLouie','historian')
+ requiresConnection('transmissionLogs','relayRicky','historian')
+ requiresConnection('transmissionLogs','relayLouie','historian')
+ requiresConnection('transmissionLogs','rtus','historian')
+ requiresConnection('transmissionLogs','ntp','secondaryHistorian')
+ requiresConnection('transmissionLogs','scadaServer','secondaryHistorian')
+ requiresConnection('transmissionLogs','opc','secondaryHistorian')
+ requiresConnection('transmissionLogs','hmi','secondaryHistorian')
+ requiresConnection('transmissionLogs','relayLouie','secondaryHistorian')
+ requiresConnection('transmissionLogs','relayRicky','secondaryHistorian')
+ requiresConnection('transmissionLogs','relayLouie','secondaryHistorian')
+ requiresConnection('transmissionLogs','rtus','secondaryHistorian')
#+ requires('transmissionLogs','rtu1')
#+ requires('transmissionLogs','rtu2')
#+ requires('transmissionLogs','rtu3')
#+ requires('transmissionLogs','rtu4')
#+ requires('transmissionLogs','rtu5')
#+ requires('transmissionLogs','rtu6')
#+ requires('transmissionLogs','rtu7')
#+ requires('transmissionLogs','rtu8')
#requiresAllConnections('transmissionLogs') <= requiresConnection('transmissionLogs','ntp','historian') & requiresConnection('transmissionLogs','scadaServer','historian') & requiresConnection('transmissionLogs','opc','historian') & requiresConnection('transmissionLogs','hmi','historian') & requiresConnection('transmissionLogs','relayLouie','historian') & requiresConnection('transmissionLogs','relayRicky','historian') & requiresConnection('transmissionLogs','relayLouie','historian') & requiresConnection('transmissionLogs','rtu1','historian') & requiresConnection('transmissionLogs','rtu2','historian') & requiresConnection('transmissionLogs','rtu3','historian') & requiresConnection('transmissionLogs','rtu4','historian') & requiresConnection('transmissionLogs','rtu5','historian') & requiresConnection('transmissionLogs','rtu6','historian') & requiresConnection('transmissionLogs','rtu7','historian') & requiresConnection('transmissionLogs','rtu8','historian')

+ utility('enterprise',5)
#+ requires('enterprise','printer')
+ producesData('hmi','printJobData')
+ consumesData('enterprise','printer','printJobData',False,0,True,1,True,0.5)
#+ requiresDataWithAttributes('enterprise','printJobData',False,0,True,1,True,0.5)

+ utility('remoteEnterprise',5)
+ requires('remoteEnterprise','printer')
+ requires('remoteEnterprise','vpn')
+ requiresConnection('remoteEnterprise','vpn','printer')
#requiresAllConnections('remoteEnterprise') <= requiresConnection('remoteEnterprise','internet','vpn') & requiresConnection('remoteEnterprise','vpn','printer')


+ utility('firewall',0)
+ requires('firewall','dmzFirewall')
+ require('firewall','router')
+ requires('firewall','sw1')
+ requires('firewall','sw2')
+ requires('firewall','sw3')


#Switch back
#+ compromised('vpn')
#+ probCompromised('vpn',0.9)
#+ compromised('printer')
#+ probCompromised('printer',0.1)
#+ compromised('sw1')
#+ probCompromised('sw1',0.9)
#+ componentCompromisedWithAttributes('printer',0.9,False,False,False)
#This is what I want to use #Changed 20210110
+ compromised('vpn',0.9,False,False,False)
#But why isn't this working?
#+ componentCompromisedWithAttributes('vpn',0.1,False,False,False)
#+ componentCompromisedWithAttributes('sw1',0.9,False,False,False)
#+ compromised('sw4')
#+ probCompromised('sw4',0.4)



#Notes on future additions:
#OR operator (or similar) for backups
#Ability to specify when a primary is better than a backup
#Nested functionality (e.g., transmissionMgmt requires transmission)
#The above is through is-a and requires relationships
#Need to specify that specific links handle specific protocols,
#so topological changes don't put an RTU with a serial connection on
#an enterprise network
#Limits on moving
#Threat is access to OPC server rather than taking one down, so having a second one is an additional point of compromise
