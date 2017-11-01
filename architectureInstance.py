

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
#+ networkConnectsTo('paymentServer','pos')

# compromised(Host) OR compromised(Service)
+ compromised('attackerHost')
#For testing only
#+ compromised('webServer')
#+ compromised('host1')

+ requires('web','webServer')
#changed from adServer to activeDirService
+ requires('web','activeDirService')
+ requires('payments','pos')
+ requires('payments','paymentServer')
+ requires('payments','adServer') ## Comment from Matt: Ryan, is this right? Shouldn't it be adHost?

+ requiresConnection('payments','paymentServer','pos')
+ requiresConnection('web','webServer','activeDirService')
+ requiresConnection('web','activeDirService','webServer')
+ requiresConnection('internet','attackerClient','webServer')

#Utility
+ utility('web',3)
+ utility('payments',5)
+ utility('internet',2)
