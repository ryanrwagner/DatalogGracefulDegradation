transformerFails(X) <= compromised(X) & isType(X,'transformer')
transformerFails(X) <= relayFails(Y)
shortTermPowerOutage() <= generatorFails(X)
longTermPowerOutage() <= transformerFails(X)

