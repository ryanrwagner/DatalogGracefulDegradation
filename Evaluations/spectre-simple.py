#Spectre Simple Architecture

#Note the differences below for historian, engineerWorkstation,
#ntp, and power-provider

+isAccount('opc','userAccount')
+isType('opc','service')
+isAccount('hmi','userAccount')
+isType('hmi','service')
+isAccount('scadaServer','userAccount')
+isType('scadaServer','service')
+isAccount('relayRicky','userAccount')
+isType('relayRicky','service')
+isAccount('relayLouie','userAccount')
+isType('relayLouie','service')
+isAccount('rtus','userAccount')
+isType('rtus','service')
+isAccount('printer','userAccount')
+isType('printer','service')
+isAccount('ntp','userAccount')
+isType('ntp','service')
+isAccount('historian','userAccount')
+isType('historian','service')
+isAccount('engineerWorkstation','userAccount')
+isType('engineerWorkstation','service')
+isAccount('sw1','userAccount')
+isType('sw1','networkDevice')
+isAccount('dmzFirewall','userAccount')
+isType('dmzFirewall','networkDevice')
+isAccount('sw3','userAccount')
+isType('sw3','networkDevice')
+isAccount('vpn','userAccount')
+isType('vpn','service')
+isAccount('vpnSU','superUserAccount')
+isType('vpnSU','service')
+residesOn('vpn','vpnSU')
+isType('vpnSU','service')

+ networkConnectsTo('opc','sw1')
+ networkConnectsTo('hmi','sw1')
+ networkConnectsTo('scadaServer','sw1')
+ networkConnectsTo('relayRicky','sw1')
+ networkConnectsTo('relayLouie','sw1')
+ networkConnectsTo('rtus','sw1')
#+ networkConnectsTo('opcScadaRelaysRTUs','sw1')
#+ networkConnectsTo('printer','sw1')
+ networkConnectsTo('ntp','sw1')
+ networkConnectsTo('historian','sw1')
+ networkConnectsTo('engineerWorkstation','sw1')
#+ networkConnectsTo('sw1','router')
#+ networkConnectsTo('router','sw2')
+ networkConnectsTo('sw1','dmzFirewall')
+ networkConnectsTo('dmzFirewall','sw3')
+ networkConnectsTo('sw3','vpn')
+ networkConnectsTo('printer','sw3')



+ utility('transmission',100)
#Note the power provider is required here but not for management
#+ requires('transmission','powerProvider')
#+ requiresFunction('transmissionF','opcF')
+ requires('transmission','opc')
#+ requiresFunction('transmissionF','hmiF')
+ requires('transmission','hmi')
#+ requiresFunction('transmissionF','scadaServerF')
+ requires('transmission','scadaServer')
+ requires('transmission','relayLouie')
+ requires('transmission','relayRicky')
#necessary?
+ requires('transmission','router')
#+ requires('transmission','dmzFirewall')
+ requires('transmission','rtus')
#+ requires('transmissionF','rtu1')
#+ requires('transmissionF','rtu2')
#+ requires('transmissionF','rtu3')
#+ requires('transmissionF','rtu4')
#+ requires('transmissionF','rtu5')
#+ requires('transmissionF','rtu6')
#+ requires('transmissionF','rtu7')
#+ requires('transmissionF','rtu8')
#requiresAllConnections('transmissionF') <=
#+ requiresConnection('transmission','powerProvider','scadaServer')
+ requiresConnection('transmission','opc','scadaServer')
+ requiresConnection('transmission','hmi','scadaServer')
+ requiresConnection('transmission','relayLouie','scadaServer')
+ requiresConnection('transmission','relayRicky','scadaServer')
+ requiresConnection('transmission','relayLouie','scadaServer')
+ requiresConnection('transmission','rtus')
#requiresConnection('transmissionF','rtu1','scadaServerF')
#requiresConnection('transmissionF','rtu2','scadaServerF')
#requiresConnection('transmissionF','rtu3','scadaServerF')
#requiresConnection('transmissionF','rtu4','scadaServerF')
#requiresConnection('transmissionF','rtu5','scadaServerF')
#requiresConnection('transmissionF','rtu6','scadaServerF')
#requiresConnection('transmissionF','rtu7','scadaServerF')
#requiresConnection('transmissionF','rtu8','scadaServerF')

#+ implementsF('opcF','opc',0)
#+ implementsF('opcF','opc-backup',0)
#+ implementsF('hmiF','hmi',0)
#+ implementsF('hmiF','hmi-backup',-5)
#+ implementsF('scadaServerF','scadaServer',0)
#+ implementsF('scadaServerF','scadaServer-backup',-5)

+ dataFlow('functionality','datum','source','target')
+ dataUsed('functionality','datum','ciaReq','service')
+ interfaceProducer('functionality','produces','datum','service') #links data produced to a physical service
+ interfaceConsumer('functionality','consumes','datum','service') #links data consumed to a physical service
+ securityRequirement('functionality','ciaReq','datum','source','destination') #thinking through if source is necessary here

+ utility('transmissionMgmt',50)
#Transmission management requires integrity of the command data on the engineering workstation. The impact to the transmission management function of the loss of integrity of this data on this host is loss of 100% of the utility.
#integrity from whom?
+ requiresSecurityAttribute('transmissionMgmt','integrity','trMgmtCommandData','engineerWorkstation','1.0')
+ requiresSecurityAttribute('transmissionMgmt','integrity','trLogData','engineerWorkstation','1.0')
+ requiresSecurityAttribute('transmissionMgmt','availability','trMgmtCommandData','engineerWorkstation','0.5')
+ requiresSecurityAttribute('transmissionMgmt','availability','trLogData','engineerWorkstation','0.25')

#OPC and router should be generated automatically, since it's a transit point only and not an end point
#What if a component produces and consumes its own data?
#Should we have functionality<->functionality and component<->component C,I,A?

+ requiresSecurityAttribute('transmissionMgmt','integrity','trMgmtCommandData','hmi','1.0')
+ requiresSecurityAttribute('transmissionMgmt','integrity','trLogData','hmi','1.0')
+ requiresSecurityAttribute('transmissionMgmt','availability','trMgmtCommandData','hmi','1.0')
+ requiresSecurityAttribute('transmissionMgmt','availability','trLogData','hmi','0.5')

+ requiresSecurityAttribute('transmissionMgmt','integrity','trMgmtCommandData','scadaServer','1.0')
+ requiresSecurityAttribute('transmissionMgmt','integrity','trLogData','scadaServer','1.0')
+ requiresSecurityAttribute('transmissionMgmt','availability','trMgmtCommandData','scadaServer','1.0')
+ requiresSecurityAttribute('transmissionMgmt','availability','trLogData','scadaServer','0.5')

+ requiresSecurityAttribute('transmissionMgmt','integrity','trMgmtCommandData','relayLouie','1.0')
+ requiresSecurityAttribute('transmissionMgmt','integrity','trLogData','relayLouie','1.0')
+ requiresSecurityAttribute('transmissionMgmt','availability','trMgmtCommandData','relayLouie','1.0')
+ requiresSecurityAttribute('transmissionMgmt','availability','trLogData','relayLouie','0.5')

+ requiresSecurityAttribute('transmissionMgmt','integrity','trMgmtCommandData','relayRicky','1.0')
+ requiresSecurityAttribute('transmissionMgmt','integrity','trLogData','relayRicky','0.25')
+ requiresSecurityAttribute('transmissionMgmt','availability','trMgmtCommandData','relayRicky','1.0')
+ requiresSecurityAttribute('transmissionMgmt','availability','trLogData','relayRicky','0.25')

+ requiresSecurityAttribute('transmissionMgmt','integrity','trLogData','rtus','1.0')
+ requiresSecurityAttribute('transmissionMgmt','availability','trLogData','rtus','0.5')

# Note the workstation is required here but not for transmission
#+ requires('transmissionMgmt','engineerWorkstation')
+ requires('transmissionMgmt','opc')
#+ requires('transmissionMgmt','hmi')
#+ requires('transmissionMgmt','scadaServer')
#+ requires('transmissionMgmt','relayLouie')
#+ requires('transmissionMgmt','relayRicky')
+ requires('transmissionMgmt','router')
#+ requires('transmissionMgmt','dmzFirewall')
#+ requires('transmissionMgmt','rtus')
#+ requires('transmissionMgmt','rtu1')
#+ requires('transmissionMgmt','rtu2')
#+ requires('transmissionMgmt','rtu3')
#+ requires('transmissionMgmt','rtu4')
#+ requires('transmissionMgmt','rtu5')
#+ requires('transmissionMgmt','rtu6')
#+ requires('transmissionMgmt','rtu7')
#+ requires('transmissionMgmt','rtu8')
#requiresAllConnections('transmissionMgmt') <=
+ requiresConnection('transmissionMgmt','engineerWorkstation','scadaServer')
+ requiresConnection('transmissionMgmt','opc','scadaServer')
+ requiresConnection('transmissionMgmt','hmi','scadaServer')
+ requiresConnection('transmissionMgmt','relayLouie','scadaServer')
+ requiresConnection('transmissionMgmt','relayRicky','scadaServer')
+ requiresConnection('transmissionMgmt','relayLouie','scadaServer')
+ requiresConnection('transmissionMgmt','rtus','scadaServer')
#+ requiresConnection('transmissionMgmt','rtu1','scadaServer')
#requiresConnection('transmissionMgmt','rtu2','scadaServer')
#requiresConnection('transmissionMgmt','rtu3','scadaServer')
#requiresConnection('transmissionMgmt','rtu4','scadaServer')
#requiresConnection('transmissionMgmt','rtu5','scadaServer')
#requiresConnection('transmissionMgmt','rtu6','scadaServer')
#requiresConnection('transmissionMgmt','rtu7','scadaServer')
#requiresConnection('transmissionMgmt','rtu8','scadaServer')

+ utility('transmissionLogs',20)
+ requires('transmissionLogs','historian')
+ requires('transmissionLogs','ntp')
+ requires('transmissionLogs','opc')
#+ requires('transmissionLogs','hmi')
+ requires('transmissionLogs','scadaServer')
+ requires('transmissionLogs','relayLouie')
+ requires('transmissionLogs','relayRicky')
+ requires('transmissionLogs','router')
+ requires('transmissionLogs','dmzFirewall')
+ requires('transmissionLogs','rtus')
#+ requires('transmissionLogs','rtu1')
#+ requires('transmissionLogs','rtu2')
#+ requires('transmissionLogs','rtu3')
#+ requires('transmissionLogs','rtu4')
#+ requires('transmissionLogs','rtu5')
#+ requires('transmissionLogs','rtu6')
#+ requires('transmissionLogs','rtu7')
#+ requires('transmissionLogs','rtu8')
#requiresAllConnections('transmissionLogs') <=
+ requiresConnection('transmissionLogs','ntp','historian')
+ requiresConnection('transmissionLogs','scadaServer','historian')
+ requiresConnection('transmissionLogs','opc','historian')
+ requiresConnection('transmissionLogs','hmi','historian')
+ requiresConnection('transmissionLogs','relayLouie','historian')
+ requiresConnection('transmissionLogs','relayRicky','historian')
+ requiresConnection('transmissionLogs','relayLouie','historian')
+ requiresConnection('transmissionLogs','rtus','historian')
#requiresConnection('transmissionLogs','rtu1','historian')
#requiresConnection('transmissionLogs','rtu2','historian')
#requiresConnection('transmissionLogs','rtu3','historian')
#requiresConnection('transmissionLogs','rtu4','historian')
#requiresConnection('transmissionLogs','rtu5','historian')
#requiresConnection('transmissionLogs','rtu6','historian')
#requiresConnection('transmissionLogs','rtu7','historian')
#requiresConnection('transmissionLogs','rtu8','historian')

+ utility('enterprise',5)
+ requires('enterprise','printer')

+ utility('remoteEnterprise',5)
+ requires('remoteEnterprise','printer')
+ requires('remoteEnterprise','vpn')
#requiresAllConnections('remoteEnterprise') <=
#requiresConnection('remoteEnterprise','internet','vpn')
requiresConnection('remoteEnterprise','vpn','printer')

+ utility('firewall',0)
+ requires('firewall','dmzFirewall')
+ requires('firewall','sw1')
+ requires('firewall','sw2')
+ requires('firewall','sw3')




+ compromised('vpn')
#+ probCompromised('vpn',0.99)
+ probCompromised('vpn',0.90)
+ compromised('printer')
#+ probCompromised('printer',0.05)
+ probCompromised('printer',0.10)


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
