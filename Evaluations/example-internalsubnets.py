+ isA('attackerClient','userAccount')
+ isA('attackerHost','superUserAccount')
+ isA('scs1','userAccount')
+ isA('scs2','userAccount')
+ isA('tepper1','userAccount')
+ isA('tepper2','userAccount')
+ isA('fw0','userAccount')
+ isA('fwSU0','superUserAccount')
+ isA('fw1','userAccount')
+ isA('fwSU1','superUserAccount')
+ isA('fw2','userAccount')
+ isA('fwSU2','superUserAccount')




+ isA('attackerClient','userAccount')
+ isA('attackerHost','superUserAccount')
+ isA('webServer','userAccount')
+ isA('host1','superUserAccount')
+ isA('paymentServer','userAccount')
+ isA('pos','userAccount')
+ isA('posHost','superUserAccount')
+ isA('activeDirService','userAccount')
+ isA('adHost','superUserAccount')
+ isA('host2','superUserAccount')
+ isA('fw','userAccount')
+ isA('fwSU','superUserAccount')

# residesOn(Service,Host)
+ residesOn('attackerClient','attackerHost')
+ residesOn('webServer','host1')
#+ residesOn('paymentServer','host1')
+ residesOn('paymentServer','host2')
+ residesOn('pos','posHost')
+ residesOn('activeDirService','adHost')
+ residesOn('fw','fwSU')

#Connections are directional and between services
# connectsTo(SourceService,TargetService)
+ networkConnectsTo('attackerClient','webServer')
+ networkConnectsTo('webServer','activeDirService')
#changed below to webServer from webService
+ networkConnectsTo('activeDirService','webServer')
+ networkConnectsTo('paymentServer','activeDirService')
+ networkConnectsTo('activeDirService','paymentServer')
#TEST CUT
+ networkConnectsTo('paymentServer','pos')
#+ networkConnectsTo('activeDirService','pos')
#+ networkConnectsTo('webServer','pos')
#Best Utility: 57.0
#+ networkConnectsTo('attackerClient','fw')
#+ networkConnectsTo('fw','webServer')

# compromised(Host) OR compromised(Service)

#BUG Change back below
#+ compromised('attackerHost')
+ compromised('attackerClient')

#For testing only
#+ compromised('webServer')
#+ compromised('host1')

+ requires('web','webServer')
#changed from adServer to activeDirService
+ requires('web','activeDirService')
+ requires('payments','pos')
+ requires('payments','paymentServer')
#Test remove requires
+ requires('payments','activeDirService') ## Comment from Matt: Ryan, is this right? Shouldn't it be adHost?
#+ functionalityFree('fw')
+ requires('firewall','fw')

+ requiresConnection('payments','paymentServer','pos')
+ requiresConnection('web','webServer','activeDirService')
+ requiresConnection('web','activeDirService','webServer')
+ requiresConnection('internet','attackerClient','webServer')

#Utility
+ utility('web',30)
+ utility('payments',50)
+ utility('internet',20)
+ utility('firewall',1)

#For two firewall test
+ isType('fw','firewallType')
+ isType('fw2','firewallType')
+ isA('fw2','userAccount')
+ isA('fwSU2','superUserAccount')
+ residesOn('fw2','fwSU2')
+ requires('firewall2','fw2')
