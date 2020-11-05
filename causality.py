transformerFails(X,P2) <= compromised(X,P) & isType(X,'transformer')
transformerFails(X,P2) <= relayFails(Y,P)
shortTermPowerOutage(P2) <= generatorFails(X,P)
longTermPowerOutage(P2) <= transformerFails(X,P)


#Causal style for 
#Full backup

#Alternate backup (PACE)

#No backup

#Ands / Ors

#Step degradation / Partial backup

#Test A
