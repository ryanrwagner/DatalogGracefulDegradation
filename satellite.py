+isA('comms','userAccount')
+isA('navigation','userAccount')
+isA('propulsion','userAccount')
+isA('sciencePayload1','userAccount')
+isA('sciencePayload2','userAccount')
+isA('flightComputer','userAccount')
+isA('groundControl','userAccount')
+isA('guard1','userAccount')
#+isA('guard2','userAccount')


+requiresConnection('satellite','groundControl','comms')
+requiresConnection('command','comms','flightComputer')
+requiresConnection('betterOrbit','comms','flightComputer')
+requiresConnection('betterOrbit','flightComputer','navigation')
+requiresConnection('betterOrbit','flightComputer','propulsion')
+requiresConnection('orbit','flightComputer','navigation')
+requiresConnection('orbit','flightComputer','propulsion')
+requiresConnection('science1','comms','sciencePayload1')
+requiresConnection('science2','comms','sciencePayload2')

+requires('satellite','groundControl')
+requires('satellite','comms')
+requires('command','comms')
+requires('command','flightComputer')
+requires('betterOrbit','comms')
+requires('betterOrbit','flightComputer')
+requires('betterOrbit','navigation')
+requires('betterOrbit','propulsion')
+requires('orbit','flightComputer')
+requires('orbit','navigation')
+requires('orbit','propulsion')
+requires('science1','sciencePayload1')
+requires('science2','sciencePayload2')

+requires('guard','guard1')

#Hierarchy
+requires('science1','command')
+requires('science2','command')
+requires('betterOrbit','command')
+requires('command','satellite')

+utility('science1',50)
+utility('science2',50)
+utility('betterOrbit',5)
+utility('orbit',0)
+utility('command',0)
+utility('satellite',0)
+utility('guard',0)

+compromised('groundControl')
+probCompromised('groundControl',0.1)
+compromised('sciencePayload1')
+probCompromised('sciencePayload1',0.4)
+compromised('sciencePayload2')
+probCompromised('sciencePayload2',0.4)

#Assume a flat, bus architecture
#100.55
# +networkConnectsTo('groundControl','comms')
# +networkConnectsTo('comms','flightComputer')
# +networkConnectsTo('comms','navigation')
# +networkConnectsTo('comms','propulsion')
# +networkConnectsTo('comms','sciencePayload1')
# +networkConnectsTo('comms','sciencePayload2')


#More hierarchy and a guard
#101.55
# +networkConnectsTo('groundControl','comms')
# +networkConnectsTo('comms','guard1')
# +networkConnectsTo('guard1','flightComputer')
# +networkConnectsTo('flightComputer','navigation')
# +networkConnectsTo('flightComputer','propulsion')
# +networkConnectsTo('guard1','sciencePayload1')
# +networkConnectsTo('guard1','sciencePayload2')

+isA('guard2','userAccount')
+isA('guard3','userAccount')
+networkConnectsTo('groundControl','comms')
+networkConnectsTo('comms','guard1')
+networkConnectsTo('guard1','flightComputer')
+networkConnectsTo('flightComputer','navigation')
+networkConnectsTo('flightComputer','propulsion')
+networkConnectsTo('guard1','guard2')
+networkConnectsTo('guard2','sciencePayload1')
+networkConnectsTo('guard1','guard3')
+networkConnectsTo('guard3','sciencePayload2')



# For pyDatalog to be happy
+ residesOn('internet','internetSU')
