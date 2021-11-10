pyDatalog.create_terms('loss','event')

#OR
event("lossOfMitigations") <= event("relayMonitorProblem")
event("lossOfMitigations") <= event("uncooperativeGenerationCapacity")

event("unstableCurrent") <= event("relayControlProblem")

#AND
event("transformerDestruction") <= event("lossOfMitigations") & event("unstableCurrent")

#"XOR"
event("relayClosures") <= event("unstableCurrent") & ~event("lossOfMitigations")
event("relayOpenings") <= event("unstableCurrent") & ~event("lossOfMitigations")

loss("longTermTransmissionOutage") <= event("transformerDestruction")

loss("shorTermTransmissionOutage") <= event("relayClosures")

event("lowVoltage") <= event("relayOpenings")
loss("shortTermBrownOut") <= event("lowVoltage")



