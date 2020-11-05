+ isA('frb1','userAccount')
+ isA('frb2','userAccount')
+ isA('frb3','userAccount')
+ isA('mc1','userAccount')
+ isA('mc2','userAccount')
+ isA('mc3','userAccount')
+ isA('bankA','userAccount')
+ isA('bankB','userAccount')
+ isA('bankC','userAccount')
#+ isA('firewall0','userAccount')
#I need this?
+ isA('frb1SU','superUserAccount')

#Compromise
+ compromised('mc1')
+ probCompromised('mc1',0.5)
+ compromised('mc2')
+ probCompromised('mc2',0.5)
+ compromised('mc3')
+ probCompromised('mc3',0.5)
#+ compromised('bankA')
#+ probCompromised('bankA',0.5)
#+ compromised('frb1')
#+ probCompromised('frb1',0.5)
#+ probCompromised('frb1',1.0)



#Utility
#+ utility('clearingAB',10)
#+ utility('clearingAC',30)
#+ utility('clearingBC',60)
+ utility('clearingAB',60)
+ utility('clearingAC',30)
+ utility('clearingBC',10)

#I need this?
+ residesOn('frb1','frb1SU')

+ requires('clearingAB','bankA')
+ requires('clearingAB','bankB')
+ requires('clearingAC','bankA')
+ requires('clearingAC','bankC')
+ requires('clearingBC','bankB')
+ requires('clearingBC','bankC')

+ requiresConnection('clearingAB','bankA','bankB')
+ requiresConnection('clearingAC','bankA','bankC')
+ requiresConnection('clearingBC','bankB','bankC')

+ networkConnectsTo('bankA','mc1')
+ networkConnectsTo('bankA','mc2')
+ networkConnectsTo('bankB','mc1')
+ networkConnectsTo('bankB','mc3')
+ networkConnectsTo('bankC','mc3')
+ networkConnectsTo('mc1','frb2')
+ networkConnectsTo('mc2','frb1')
+ networkConnectsTo('mc3','frb3')
+ networkConnectsTo('frb1','frb2')
+ networkConnectsTo('frb1','frb3')
+ networkConnectsTo('frb2','frb3')

#+ requires('firewall','fw0')
#+ requires('firewall','fw1')
#+ utility('firewall',0)

+ requires('zero','frb1')
+ requires('zero','frb2')
+ requires('zero','frb3')
+ requires('zero','mc1')
+ requires('zero','mc2')
+ requires('zero','mc3')
+ utility('zero',0)
