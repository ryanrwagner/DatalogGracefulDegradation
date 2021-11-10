#+ componentCompromisedWithAttributes('internet',0.9,False,False,False)
#Note: Change from corporateLAN to controlSystemServer to businessDMZ
#Note: Changes must follow in Python, too
+ componentCompromisedWithAttributes('businessDMZ',0.1,False,False,False)

+ networkConnectsToWithAttributes('internet','corporateFW',True,True,True)
+ networkConnectsToWithAttributes('corporateFW','corporateLAN',True,True,True)
+ networkConnectsToWithAttributes('corporateLAN','businessWorkstations',True,True,True)
+ networkConnectsToWithAttributes('corporateFW','businessFW',True,True,True)
+ networkConnectsToWithAttributes('internet','VPN',True,True,True)
+ networkConnectsToWithAttributes('VPN','businessFW',True,True,True)
+ networkConnectsToWithAttributes('businessFW','businessDMZ',True,True,True)
+ networkConnectsToWithAttributes('businessFW','controlSystemLAN',True,True,True)
+ networkConnectsToWithAttributes('controlSystemLAN','controlSystemServer',True,True,True)
+ networkConnectsToWithAttributes('controlSystemLAN','controlSystemFirewall',True,True,True)
+ networkConnectsToWithAttributes('businessFW','controlFW',True,True,True)
+ networkConnectsToWithAttributes('controlFW','rtus',True,True,True)
+ networkConnectsToWithAttributes('controlSystemLAN','scadaFirewall',True,True,True)
#+ networkConnectsToWithAttributes('businessFW','scadaFW',True,True,True)
+ networkConnectsToWithAttributes('scadaFW','scadaServer',True,True,True)





+isAccount('internet','userAccount')
+isType('internet','switch')

+isAccount('corporateFW','userAccount')
+isType('corporateFW','enterpriseFirewall1')
+ existsExploit('enterpriseFirewall1','enterpriseFW1Exploit',1,0,0,0,False)
+isSubType('enterpriseFirewall1','firewall')

#+isAccount('corpModems','userAccount')
#+isType('corpModems','service')
#+ existsExploit('corpModems','corpModemsExploit',1,0,0,0,False)
#+ networkConnectsToWithAttributes('corporateFW','corpModems',True,True,True)

#+isAccount('corpPBX','userAccount')
#+isType('corpPBX','service')
#+ existsExploit('corpPBX','corpPBXExploit',1,0,0,0,False)
#+ networkConnectsToWithAttributes('corporateFW','corpPBX',True,True,True)

#+isAccount('telephonyFW','userAccount')
#+isType('telephonyFW','voipFirewall')
#+isSubType('voipFirewall','firewall')
#+ existsExploit('voipFirewall','voipFWExploit',1,0,0,0,False)
#+ networkConnectsToWithAttributes('telephonyFW','corpPBX',True,True,True)
#+ networkConnectsToWithAttributes('internet','telephonyFW',True,True,True)

+isAccount('corporateLAN','userAccount')
+isType('corporateLAN','corporateLANT')
+isSubType('corporateLANT','service')
+ existsExploit('corporateLANT','corporateLANExploit',1,0,0,0,False)

+isAccount('businessFW','userAccount')
+isType('businessFW','enterpriseFirewall2')
+ existsExploit('enterpriseFirewall2','enterpriseFW2Exploit',1,0,0,0,False)
+isSubType('enterpriseFirewall2','firewall')


+isAccount('VPN','userAccount')
+isType('VPN','vpnT')
+isSubType('vpnT','service')
+ existsExploit('vpnT','VPNExploit',1,0,0,0,False)


#+isAccount('extBusCommFW','userAccount')
#+isType('extBusCommFW','enterpriseFirewall3')
#+ existsExploit('enterpriseFirewall3','enterpriseFW3Exploit',1,0,0,0,False)
#+isSubType('enterpriseFirewall3','firewall')
#+ networkConnectsToWithAttributes('internet','extBusCommFW',True,True,True)
#+ networkConnectsToWithAttributes('businessDMZ','extBusCommFW',True,True,True)

+isAccount('businessDMZ','userAccount')
+isType('businessDMZ','businessDMZT')
+isSubType('businessDMZT','service')
+ existsExploit('businessDMZT','businessDMZExploit',1,0,0,0,False)

+isAccount('controlSystemLAN','userAccount')
+isType('controlSystemLAN','switch')

+isAccount('controlSystemServer','userAccount')
+isType('controlSystemServer','controlSystemServerT')
+isSubType('controlAppServerT','service')
+ existsExploit('controlSystemServerT','controlSystemServerExploit',1,0,0,0,False)


+isAccount('controlFW','userAccount')
+isType('controlFW','controlSystemFirewall')
+isSubType('controlSystemFirewall','firewall')
+ existsExploit('controlSystemFirewall','controlSystemFWExploit',1,0,0,0,False)


+isAccount('rtus','userAccount')
+isType('rtus','rtusT')
+isSubType('rtusT','service')
+ existsExploit('rtusT','rtusExploit',1,0,0,0,False)

+isAccount('scadaFW','userAccount')
+isType('scadaFW','controlSystemFirewall')



+isAccount('scadaServer','userAccount')
+isType('scadaServer','scadaServerT')
+isSubType('scadaServerT','service')
+ existsExploit('scadaServerT','scadaServerExploit',1,0,0,0,False)

+isAccount('vpnSU','superUserAccount')
+isType('vpnSU','service')
+residesOn('vpn','vpnSU')
+isType('vpnSU','service')

+ utility('transmissionMgmt',50)
+ requiresFunction('transmissionMgmt','transmissionF')
+ requires('transmissionMgmt','controlSystemServer') #

+ utility('transmissionF',100)
+ requires('transmissionF','rtus') #
+ requires('transmissionF','scadaServer') #
+ requires('transmissionF','controlSystemServer') #

+ utility('transmissionLogs',20)
+ requiresFunction('transmissionLogs','transmissionF')
+ requires('transmissionLogs','controlSystemServer') #
+ requires('transmissionLogs','businessDMZ') #

+ utility('enterprise',5)
+ requires('enterprise','businessDMZ') #
+ requires('enterprise','corporateLAN') #

+ utility('remoteEnterprise',5)
+ requiresFunction('remoteEnterprise','enterprise')
#+ requires('remoteEnterprise','corpModems')
#+ requires('remoteEnterprise','corpPBX')
#+ requires('remoteEnterprise','telephonyFW')
+ requires('remoteEnterprise','VPN') #
+ requires('remoteEnterprise','vpnSU') #

#To allow passing through switches without effort
+ existsExploit('switch','noExploit',0,0,0,0,False)
+ utility('network',0)
+ requires('network','internet') #
+ requires('network','corporateFW') #
#+ requires('network','dnsDMZ')
#+ requires('network','emailDMZ')
#+ requires('network','webDMZ')
#+ requires('network','ftpDMZ')
#+ requires('network','authDMZ')
#+ requires('network','wirelessDMZ')
+ requires('network','corporateLAN') #
+ requires('network','businessFW') #
#+ requires('network','busCommDMZ')
#+ requires('network','webServerDMZ')
#+ requires('network','dbDMZ')
#+ requires('network','securityDMZ')
#+ requires('network','busAuthDMZ')
+ requires('network','controlSystemLAN') #
+ requires('network','controlFW') #
#+ requires('network','extBusCommFW')
+ requires('network','scadaFW') #
#+ requires('network','wirelessAP')

#For future compatibility:
+ producesData('rtus','rtuData')
+ consumesData('transmissionF','controlAppServer','rtuData',False,0,True,1,True,0.5)
