+ isA('frb1','userAccount')
+ isA('frb2','userAccount')
+ isA('frb3','userAccount')
+ isA('mc1','userAccount')
+ isA('mc2','userAccount')
+ isA('mc3','userAccount')
+ isA('bankA','userAccount')
+ isA('bankB','userAccount')
+ isA('bankC','userAccount')
#I need this?
+ isA('frb1SU','superUserAccount')

+ compromised('mc1')
+ probCompromised('mc1',0.2)
+ compromised('mc2')
+ probCompromised('mc1',0.1)

#I need this?
+ residesOn('frb1','frb1SU')

+ requires('clearingAB','bankA')
+ requires('clearingAB','bankB')
+ requires('clearingAC','bankA')
+ requires('clearingAC','bankC')
+ requires('clearingBC','bankB')
+ requires('clearingBC','bankC')

+ requiresConnection('bankA','bankB','clearingAB')
+ requiresConnection('bankA','bankC','clearingAC')
+ requiresConnection('bankB','bankC','clearingBC')

+ networkConnectsTo('bankA','mc1')
+ networkConnectsTo('bankA','mc2')
+ networkConnectsTo('bankB','mc1')
+ networkConnectsTo('bankB','mc3')
+ networkConnectsTo('bankC','mc3')
+ networkConnectsTo('mc1','frb2')
+ networkConnectsTo('mc2','frb1')
+ networkConnectsTo('mc3','frb3')
+ networkConnectsTo('bankA','mc1')
+ networkConnectsTo('frb1','frb2')
+ networkConnectsTo('frb1','frb3')
+ networkConnectsTo('frb2','frb3')

#+ requires('firewall','fw0')
#+ requires('firewall','fw1')

#Utility
+ utility('clearingAB',10)
+ utility('clearingAC',30)
+ utility('clearingBC',60)

+ utility('firewall',0)
