+ isA('controller1','userAccount')
+ isA('supervisoryController1','userAccount')
+ isA('fw1','userAccount')
+ isA('fw2','userAccount')
+ isA('fw3','userAccount')
+ isA('icsHistorian','userAccount')
+ isA('icsDB','userAccount')
+ isA('corporateLaptop','userAccount')
+ isA('attacker','userAccount')

#+ isA('controller1SU','superUserAccount')
#+ isA('supervisoryController1SU','superUserAccount')
#+ isA('fw1SU','superUserAccount')
#+ isA('fw2SU','superUserAccount')
#+ isA('fw3SU','superUserAccount')
#+ isA('icsHistorianSU','superUserAccount')
#+ isA('icsDBSU','superUserAccount')
#+ isA('corporateLaptopSU','superUserAccount')
#+ isA('attackerSU','superUserAccount')

#+ residesOn('controller1','controller1SU')
#+ residesOn('supervisoryController1','supervisoryController1SU')
#+ residesOn('fw1','fw1SU')
#+ residesOn('fw2','fw2SU')
#+ residesOn('fw3','fw3SU')
#+ residesOn('icsHistorian','icsHistorianSU')
#+ residesOn('icsDB','icsDBSU')
#+ residesOn('corporateLaptop','corporateLaptopSU')
+ residesOn('attacker','attackerSU')

+ compromised('attacker',1.0,True,True,True)

+ requires('control','controller1')
+ requires('control','supervisoryController1')
+ requires('icsManagement','icsHistorian')
+ requires('icsManagement','icsDB')
+ requires('corporateLAN','corporateLaptop')

+ requires('fw1','firewall')
+ requires('fw2','firewall')
+ requires('fw3','firewall')


+ requiresConnection('control','supervisoryController1','controller1')
+ requiresConnection('icsManagement','icsDB','icsHistorian')
+ requiresConnection('icsManagement','icsHistorian','supervisoryController1')
+ requiresConnection('icsManagement','icsHistorian','controller1')
+ requiresConnection('icsManagement','supervisoryController1','icsDB')
+ requiresConnection('corporateLAN','corporateLaptop','icsDB')
# The corporateLAN must be connected to the internet
+ requiresConnection('corporateLAN','attacker','corporateLaptop')

+ networkConnectsTo('attacker','corporateLaptop')

#+ utility('control',10)
#+ utility('icsManagement',5)
#+ utility('corporateLAN',1)
+ utility('control',50)
+ utility('icsManagement',25)
+ utility('corporateLAN',5)
+ utility('firewall',0)


#Best Utility: 9.0
#Best Tactics Options: ["[['assert', 'networkConnectsTo', 'supervisoryController1', 'controller1']]", "[['assert', 'networkConnectsTo', 'corporateLaptop', 'icsDB'], ['assert', 'networkConnectsTo', 'supervisoryController1', 'controller1']]"]
# + networkConnectsTo('corporateLaptop','icsDB')
# + networkConnectsTo('icsDB','icsHistorian')
# + networkConnectsTo('icsHistorian','supervisoryController1')
# + networkConnectsTo('supervisoryController1','controller1')
# + networkConnectsTo('icsHistorian','controller1')
# + networkConnectsTo('supervisoryController1','icsDB')


#Inserting a firewall here increases utility
#+ networkConnectsTo('corporateLaptop','icsDB')
+ networkConnectsTo('corporateLaptop','fw1')
+ networkConnectsTo('fw1','icsDB')

+ networkConnectsTo('icsDB','icsHistorian')
#Adding an unnecessary firewall doesn't do anything to help utility
#+ networkConnectsTo('icsDB','fw2')
#+ networkConnectsTo('fw2','icsHistorian')

+ networkConnectsTo('icsHistorian','supervisoryController1')
+ networkConnectsTo('supervisoryController1','controller1')
+ networkConnectsTo('icsHistorian','controller1')
+ networkConnectsTo('supervisoryController1','icsDB')

#BUG: This still just has strata based on distance from attacker. But in reality, we subdivide further. The idea is that if an attacker gets into one DMZ, for example, she can't easily move to the other DMZ. How do I represent that here? It seems like looking at the attack paths is the way to do this. Or may this is already represented in the current math using the fact that risk is a PDF? I still think I'll need to refine to take individual paths into consideration. It's like Schroedinger's cat...all the paths are possible until we observe / the attacker chooses a path.
