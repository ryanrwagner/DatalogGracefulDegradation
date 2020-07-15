+ isA('attacker','userAccount')
+ isA('fw1','userAccount')
+ isA('fw2','userAccount')
+ isA('fw3','userAccount')
+ isA('fw4','userAccount')
+ isA('secretService')

+ isType('fw1','fwTypeA')
+ isType('fw2','fwTypeA')
+ isType('fw3','fwTypeB')
+ isType('fw4','fwTypeB')

+ isA('attackerSU','superUserAccount')
+ isA('fw1SU','superUserAccount')
+ isA('fw2SU','superUserAccount')
+ isA('fw3SU','superUserAccount')
+ isA('fw4SU','superUserAccount')
+ isA('secretSU')

+ residesOn('attacker','attackerSU')
+ residesOn('fw1','fw1SU')
+ residesOn('fw2','fw2SU')
+ residesOn('fw3','fw3SU')
+ residesOn('fw4','fw4SU')
+ residesOn('secretService','secretSU')

+ compromised('attacker')

#+ requires()

+ requiresConnection('internet','attacker','secretService')

#+ networkConnectsTo()

+ utility('internet',10)
