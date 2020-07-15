+ isA('internet','userAccount')
+ isA('scs','userAccount')
+ isA('tepper','userAccount')
+ isA('fw0','userAccount')
+ isA('fw1','userAccount')
#+ isA('fw2','userAccount')

#Connections are directional and between services
# connectsTo(SourceService,TargetService)


#BUG Change back below
+ compromised('internet')
#Good below
+ probCompromised('internet',0.99)
#+ probCompromised('internet',1.0)
#+ probCompromised('internet',0.50)
#Test just for fun
+ compromised('tepper')
#Good below
probCompromised('tepper',0.20)
#+ probCompromised('tepper',1.0)
#+ probCompromised('tepper',0.50)
# For pyDatalog to be happy
+ residesOn('internet','internetSU')

+ requires('computerScienceSimulations','scs')
+ requires('businessConferencing','tepper')
+ requires('businessCaseStudies','tepper')
+ requires('universityEmail','scs')
+ requires('universityEmail','tepper')

+ requires('firewall','fw0')
+ requires('firewall','fw1')
+ requires('nothing','internet')
#+ requires('firewall','fw2')


+ requiresConnection('computerScienceJournals','scs','internet')
+ requiresConnection('businessConferencing','tepper','internet')
+ requiresConnection('universityEmail','scs','tepper')
#new
+ requiresConnection('universityEmail','tepper','internet')
+ requiresConnection('universityEmail','scs','internet')


+ networkConnectsTo('internet','scs')
+ networkConnectsTo('scs','tepper')

#U=72.0
# + networkConnectsTo('internet','fw0')
# + networkConnectsTo('fw0','fw1')
# + networkConnectsTo('fw1','tepper')
# + networkConnectsTo('tepper','scs')

#U=64
#+ networkConnectsTo('internet','fw0')
#+ networkConnectsTo('fw0','fw1')
#+ networkConnectsTo('fw1','scs')
#+ networkConnectsTo('scs','tepper')

#U=80
# + networkConnectsTo('internet','fw0')
# + networkConnectsTo('fw0','fw1')
# + networkConnectsTo('tepper','internet')
# + networkConnectsTo('scs','tepper')

#U=76
# + networkConnectsTo('internet','fw0')
# + networkConnectsTo('fw0','fw1')
# + networkConnectsTo('fw1','tepper')
# + networkConnectsTo('tepper','scs')


#U=71.0
# + networkConnectsTo('internet','fw0')
# + networkConnectsTo('fw0','fw1')
# + networkConnectsTo('fw1','scs')

#U=96.0
# + networkConnectsTo('internet','fw0')
# + networkConnectsTo('fw0','fw1')
# + networkConnectsTo('fw1','tepper')
# + networkConnectsTo('fw1','fw2')
# + networkConnectsTo('fw2','scs')

# + networkConnectsTo('internet','fw0')
# + networkConnectsTo('fw0','scs')
# + networkConnectsTo('fw0','tepper')

#+ networkConnectsTo('scs','tepper')


#Utility
+ utility('universityEmail',20)
+ utility('computerScienceJournals',20)
+ utility('computerScienceSimulations',40)
+ utility('businessCaseStudies',15)
+ utility('businessConferencing',5)

+ utility('firewall',0)
+ utility('nothing',0)

#For two firewall test
#+ isType('fw','firewallType')
#+ isType('fw2','firewallType')
#+ isA('fw2','userAccount')
#+ isA('fwSU2','superUserAccount')
#+ residesOn('fw2','fwSU2')
# requires('firewall2','fw2')
