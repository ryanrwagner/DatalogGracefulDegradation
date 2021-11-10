#These two lines are just for testing purposes and should be removed.
#They should be added dynamically by Python
#The name of the component and the exploit are the same for this case
#That way, if there are two components of the same type, it's possible
#for just one to be compromised
#+ existsExploit('internet','internet',0,0,0,0,False)
#+ existsExploit('businessWorkstations','businessWorkstations',0,0,0,0,False)
+ componentCompromisedWithAttributes('internet',0.9,False,False,False)
+ componentCompromisedWithAttributes('businessWorkstations',0.1,False,False,False)
#+ componentCompromisedWithAttributes('controlFW',0.01,False,False,False)
+ hasPassword('businessFW','controlFWPW')
+ usesPassword('controlFW','controlFWPW')

#+ hasCredential("extBusCommFW","firewallPassword")
#+ hasCredential("businessFW","firewallPassword")
#+ hasCredential("controlFW","firewallPassword")
#existsExploit(ServiceA,E,0,0,0,0,False) <= hasCredential(ServiceA,E)

#+ componentCompromisedWithAttributes('internet',0.9,False,False,False)
#+ componentCompromisedWithAttributes('businessWorkstations',0.1,False,False,False)

#+ componentCompromisedWithAttributes('internet',1.0,False,False,False)
#+ componentCompromisedWithAttributes('businessWorkstations',1.0,False,False,False)
#+ componentCompromisedWithAttributes('controlAppServer',1.0,False,False,False)


#For services only
#defineComponentWithExploit('name','type','exploitName')
isAccount(ServiceA,'userAccount') <= defineComponentWithExploit(ServiceA,X,Y,E)
isType(ServiceA,X) <= defineComponentWithExploit(ServiceA,X,E)
isSubType(X,'service') <= defineComponentWithExploit(ServiceA,X,E)
existsExploit(X,E,1,0,0,0,False) <= defineComponentWithExploit(ServiceA,X,E)
#Note the special exploit for components compromised during the initial state
#The service name and exploit name are the same --
#This is to differentiate between the compromise of that component
#and the compromise of that entire type of component
isAccount(ServiceA,'userAccount') <= componentCompromisedWithAttributes(ServiceA,P,CProvided,IProvided,AProvided)
isType(ServiceA,ServiceA) <= componentCompromisedWithAttributes(ServiceA,P,CProvided,IProvided,AProvided)
isSubType(ServiceA,'service') <= componentCompromisedWithAttributes(ServiceA,P,CProvided,IProvided,AProvided)
#Zero cost exploit of compromised component
#New changed from noExploit to compromised
existsExploit(ServiceA,ServiceA,0,0,0,0,False) <= componentCompromisedWithAttributes(ServiceA,P,CProvided,IProvided,AProvided)


+isAccount('internet','userAccount')
+isType('internet','switch')
+ networkConnectsToWithAttributes('internet','corporateFW',True,True,True)

+isAccount('corporateFW','userAccount')
+isType('corporateFW','enterpriseFirewall1')
+ existsExploit('enterpriseFirewall1','enterpriseFW1Exploit',1,0,0,0,False)
+isSubType('enterpriseFirewall1','firewall')

+isAccount('dnsDMZ','userAccount')
+isType('dnsDMZ','switch')
+ networkConnectsToWithAttributes('corporateFW','dnsDMZ',True,True,True)

+ defineComponentWithExploit('dnsServer','dnsServerT','dnsServerExploit')
+ networkConnectsToWithAttributes('dnsDMZ','dnsServer',True,True,True)

+isAccount('emailDMZ','userAccount')
+isType('emailDMZ','switch')
+ networkConnectsToWithAttributes('corporateFW','emailDMZ',True,True,True)

+ defineComponentWithExploit('emailServer','emailServerT','emailServerExploit')
+ networkConnectsToWithAttributes('emailDMZ','emailServer',True,True,True)

+isAccount('webDMZ','userAccount')
+isType('webDMZ','switch')
+ networkConnectsToWithAttributes('corporateFW','webDMZ',True,True,True)

+ defineComponentWithExploit('webServer','webServerT','webServerExploit')
+ networkConnectsToWithAttributes('webDMZ','webServer',True,True,True)

+isAccount('ftpDMZ','userAccount')
+isType('ftpDMZ','switch')
+ networkConnectsToWithAttributes('corporateFW','ftpDMZ',True,True,True)

+ defineComponentWithExploit('ftpServer','ftpServerT','ftpServerExploit')
+ networkConnectsToWithAttributes('ftpDMZ','ftpServer',True,True,True)

+isAccount('authDMZ','userAccount')
+isType('authDMZ','switch')
+ networkConnectsToWithAttributes('corporateFW','authDMZ',True,True,True)

+ defineComponentWithExploit('authServer','authServerT','authServerExploit')
+ networkConnectsToWithAttributes('authDMZ','authServer',True,True,True)

+isAccount('wirelessDMZ','userAccount')
+isType('wirelessDMZ','switch')
+ networkConnectsToWithAttributes('corporateFW','wirelessDMZ',True,True,True)

+isAccount('wirelessAP','userAccount')
+isType('wirelessAP','switch')
+ networkConnectsToWithAttributes('wirelessDMZ','wirelessAP',True,True,True)

+ defineComponentWithExploit('corpModems','corpModemsT','corpModemsExploit')
+ networkConnectsToWithAttributes('corporateFW','corpModems',True,True,True)

+ defineComponentWithExploit('corpPBX','corpPBXT','corpPBXExploit')
+ networkConnectsToWithAttributes('corporateFW','corpPBX',True,True,True)

+isAccount('telephonyFW','userAccount')
+isType('telephonyFW','voipFirewall')
+isSubType('voipFirewall','firewall')
+ existsExploit('voipFirewall','voipFWExploit',1,0,0,0,False)
+ networkConnectsToWithAttributes('telephonyFW','corpPBX',True,True,True)
+ networkConnectsToWithAttributes('internet','telephonyFW',True,True,True)

+isAccount('corporateLAN','userAccount')
+isType('corporateLAN','switch')
+ networkConnectsToWithAttributes('corporateFW','corporateLAN',True,True,True)

+ defineComponentWithExploit('businessServers','businessServersT','businessServersExploit')
+ networkConnectsToWithAttributes('corporateLAN','businessServers',True,True,True)

+ defineComponentWithExploit('businessWorkstations','businessWorkstationsT','businessWorkstationsExploit')
+ networkConnectsToWithAttributes('corporateLAN','businessWorkstations',True,True,True)

+ defineComponentWithExploit('webAppServers','webAppServersT','webAppServersExploit')
+ networkConnectsToWithAttributes('corporateLAN','webAppServers',True,True,True)

+isAccount('businessFW','userAccount')
+isType('businessFW','enterpriseFirewall2')
+ existsExploit('enterpriseFirewall2','enterpriseFW1Exploit',1,0,0,0,False)
+isSubType('enterpriseFirewall2','firewall')


+isAccount('VPN','userAccount')
+isType('VPN','switch')
#+ networkConnectsToWithAttributes('VPN','businessFW',True,True,True)
+ networkConnectsToWithAttributes('VPN','corporateFW',True,True,True)
+ networkConnectsToWithAttributes('internet','VPN',True,True,True)

+isAccount('busCommDMZ','userAccount')
+isType('busCommDMZ','switch')
+ networkConnectsToWithAttributes('businessFW','busCommDMZ',True,True,True)

+ defineComponentWithExploit('extBusCommServer','extBusCommServerT','extBusCommServerExploit')
+ networkConnectsToWithAttributes('busCommDMZ','extBusCommServer',True,True,True)
+ implements('extBusCommServer','extBusCommServerF',1)

+ defineComponentWithExploit('extBusCommServer2','extBusCommServer2T','extBusCommServerExploit2')
+ networkConnectsToWithAttributes('busCommDMZ','extBusCommServer2',True,True,True)
+ implements('extBusCommServer2','extBusCommServerF',0.5)


+isAccount('extBusCommFW','userAccount')
+isType('extBusCommFW','enterpriseFirewall3')
+ existsExploit('enterpriseFirewall3','enterpriseFW1Exploit',1,0,0,0,False)
+isSubType('enterpriseFirewall3','firewall')
+ networkConnectsToWithAttributes('internet','extBusCommFW',True,True,True)
+ networkConnectsToWithAttributes('extBusCommServer','extBusCommFW',True,True,True)

+isAccount('webServerDMZ','userAccount')
+isType('webServerDMZ','switch')
+ networkConnectsToWithAttributes('businessFW','webServerDMZ',True,True,True)

+ defineComponentWithExploit('wwwServer','wwwServerT','wwwServerExploit')
+ networkConnectsToWithAttributes('webServerDMZ','wwwServer',True,True,True)

+isAccount('dbDMZ','userAccount')
+isType('dbDMZ','switch')
+ networkConnectsToWithAttributes('businessFW','dbDMZ',True,True,True)

+ defineComponentWithExploit('dbHistorianServer','dbHistorianServerT','dbHistorianServerExploit')
+ networkConnectsToWithAttributes('dbDMZ','dbHistorianServer',True,True,True)

+isAccount('securityDMZ','userAccount')
+isType('securityDMZ','switch')
+ networkConnectsToWithAttributes('businessFW','securityDMZ',True,True,True)

+ defineComponentWithExploit('securityServer','securityServerT','securityServerExploit')
+ networkConnectsToWithAttributes('securityDMZ','securityServer',True,True,True)

+isAccount('busAuthDMZ','userAccount')
+isType('busAuthDMZ','switch')
+ networkConnectsToWithAttributes('businessFW','busAuthDMZ',True,True,True)

+ defineComponentWithExploit('busAuthServer','busAuthServerT','busAuthServerExploit')
+ networkConnectsToWithAttributes('busAuthDMZ','busAuthServer',True,True,True)

+isAccount('controlSystemLAN','userAccount')
+isType('controlSystemLAN','switch')
+ networkConnectsToWithAttributes('businessFW','controlSystemLAN',True,True,True)

+ defineComponentWithExploit('controlAppServer','controlAppServerT','controlAppServerExploit')
+ networkConnectsToWithAttributes('controlSystemLAN','controlAppServer',True,True,True)

+ defineComponentWithExploit('historian','historianT','historianExploit')
+ networkConnectsToWithAttributes('controlSystemLAN','historian',True,True,True)

+ defineComponentWithExploit('controlDBServer','controlDBServerT','controlDBServerExploit')
+ networkConnectsToWithAttributes('controlSystemLAN','controlDBServer',True,True,True)

+ defineComponentWithExploit('configServer','configServerT','configServerExploit')
+ networkConnectsToWithAttributes('controlSystemLAN','configServer',True,True,True)

+ defineComponentWithExploit('hmi','hmiT','hmiExploit')
+ networkConnectsToWithAttributes('controlSystemLAN','hmi',True,True,True)

+ defineComponentWithExploit('engWorkstation','engWorkstationT','engWorkstationExploit')
+ networkConnectsToWithAttributes('controlSystemLAN','engWorkstation',True,True,True)

+isAccount('controlFW','userAccount')
+isType('controlFW','controlSystemFirewall')
+isSubType('controlSystemFirewall','firewall')
+ existsExploit('controlSystemFirewall','controlSystemFWExploit',1,0,0,0,False)
+ networkConnectsToWithAttributes('controlSystemLAN','controlFW',True,True,True)

+ defineComponentWithExploit('rtus','rtusT','rtusExploit')
+ networkConnectsToWithAttributes('controlFW','rtus',True,True,True)

+isAccount('scadaFW','userAccount')
+isType('scadaFW','controlSystemFirewall')
+ networkConnectsToWithAttributes('controlSystemLAN','scadaFW',True,True,True)

+ defineComponentWithExploit('scadaServer','scadaServerT','scadaServerExploit')
+ networkConnectsToWithAttributes('scadaFW','scadaServer',True,True,True)

+isAccount('vpnSU','superUserAccount')
+isType('vpnSU','service')
+residesOn('vpn','vpnSU')
+isType('vpnSU','service')

+ utility('transmissionMgmt',50)
+ requiresFunction('transmissionMgmt','transmissionF')
+ requires('transmissionMgmt','engWorkstation') #

+ utility('transmissionF',100)
+ requires('transmissionF','rtus') #
+ requires('transmissionF','scadaServer') #
+ requires('transmissionF','controlAppServer') #
+ requires('transmissionF','historian') #
+ requires('transmissionF','controlDBServer') #
+ requires('transmissionF','configServer') #
+ requires('transmissionF','hmi') #

+ utility('transmissionLogs',20)
+ requiresFunction('transmissionLogs','transmissionF')
+ requires('transmissionLogs','historian') #
+ requires('transmissionLogs','dbHistorianServer') #

+ utility('enterprise',5)
+ requires('enterprise','dnsServer') #
+ requires('enterprise','emailServer') #
+ requires('enterprise','webServer') #
+ requires('enterprise','ftpServer') #
+ requires('enterprise','authServer') #
+ requires('enterprise','businessServers') #
+ requires('enterprise','businessWorkstations') #
+ requires('enterprise','webAppServers') #
# comment out for implments
+ requires('enterprise','extBusCommServer') #
# replaced with extBusCommServerF
+ requires('enterprise','extBusCommServerF') #
+ requires('enterprise','wwwServer') #
+ requires('enterprise','dbHistorianServer') #
+ requires('enterprise','securityServer') #
+ requires('enterprise','busAuthServer') #

+ utility('remoteEnterprise',5)
+ requiresFunction('remoteEnterprise','enterprise')
+ requires('remoteEnterprise','corpModems') #
+ requires('remoteEnterprise','corpPBX') #
+ requires('remoteEnterprise','telephonyFW') #
+ requires('remoteEnterprise','VPN') #
+ requires('remoteEnterprise','vpnSU') #

#To allow passing through switches without effort
+ existsExploit('switch','noExploit',0,0,0,0,False)
+ utility('network',0)
+ requires('network','internet') #
+ requires('network','corporateFW') #
+ requires('network','dnsDMZ') #
+ requires('network','emailDMZ') #
+ requires('network','webDMZ') #
+ requires('network','ftpDMZ') #
+ requires('network','authDMZ') #
+ requires('network','wirelessDMZ') #
+ requires('network','corporateLAN') #
+ requires('network','businessFW') #
+ requires('network','busCommDMZ') #
+ requires('network','webServerDMZ') #
+ requires('network','dbDMZ') #
+ requires('network','securityDMZ') #
+ requires('network','busAuthDMZ') #
+ requires('network','controlSystemLAN') #
+ requires('network','controlFW') #
+ requires('network','extBusCommFW') #
+ requires('network','scadaFW') #
+ requires('network','wirelessAP') #

#For future compatibility:
+ producesData('rtus','rtuData')
+ consumesData('transmissionF','controlAppServer','rtuData',False,0,True,1,True,0.5)
