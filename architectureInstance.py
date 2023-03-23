

+ isAccount('attackerClient','userAccount')
+ isAccount('attackerHost','superUserAccount')
+ isAccount('webServer','userAccount')
+ isAccount('host1','superUserAccount')
+ isAccount('paymentServer','userAccount')
+ isAccount('pos','userAccount')
+ isAccount('posHost','superUserAccount')
+ isAccount('activeDirService','userAccount')
+ isAccount('adHost','superUserAccount')
+ isAccount('host2','superUserAccount')

# residesOn(Service,Host)
+ residesOn('attackerClient','attackerHost')
+ residesOn('webServer','host1')
#+ residesOn('paymentServer','host1')
+ residesOn('paymentServer','host2')
+ residesOn('pos','posHost')
+ residesOn('activeDirService','adHost')

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


# compromised(Host) OR compromised(Service)

#+ compromised('attackerHost')
+ compromised('attackerClient',1.0,True,True,True)

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

+ requiresConnection('payments','paymentServer','pos')
+ requiresConnection('web','webServer','activeDirService')
+ requiresConnection('web','activeDirService','webServer')
+ requiresConnection('internet','attackerClient','webServer')

#Utility
+ utility('web',30)
+ utility('payments',50)
+ utility('internet',20)
