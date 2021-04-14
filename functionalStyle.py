#function is compromised/questionable if service is required and compromised/questionable
#requiresSecurityAttribute('transmissionMgmt','integrity','trMgmtCommandData','engineerWorkstation','1.0')
functionCompromised(FunctionA,U) <= requires(FunctionA,ServiceA) & compromised(ServiceA) & utility(FunctionA,U)
functionCompromisedWithAttributes(FunctionA,U,Confidentiality,Integrity,Availability) <= requiresSecurityAttribute(FunctionA,DatumA,ServiceA,PercentDegradation) #Can I do product here like sum? compromisedWithAttributes(ServiceA,Confidentiality,Integrity,Availability)
#function is compromised/questionable if two connected services are both required and can't reach each other
#functionCompromised(FunctionA,C) <= requires(FunctionA,ServiceA) & compromised(ServiceA) & utility(FunctionA,C)
#I don't know that the below statement works
functionUncompromised(FunctionA,U) <= ~(functionCompromised(FunctionA,U))

#questionable(TargetService) means in allAttackerPaths(SourceService,TargetService,P,E,TotalC) where SourceService is any compromised service, P is anything, E is anything, and TotalC is a chosen risk metric
functionDownOrCompromised(FunctionA,U) <= functionCompromised(FunctionA,U)
functionDownOrCompromised(FunctionA,U) <= functionDown(FunctionA,U)
#Transitive Down or Compromised
functionDownOrCompromised(FunctionA,U) <= utility(FunctionA,U) & requires(FunctionA,FunctionB) & functionDownOrCompromised(FunctionB,U2)
functionDownOrCompromised(FunctionA,UAdjustment) <= implements(ServiceA,FunctionA,UAdjustment) & compromised(ServiceA)
#requiresSecurityAttribute('transmissionMgmt','integrity','trMgmtCommandData','hmi','1.0')
#+ implementsF('opcF','opc',0)
#NOTE: Is the below needed? What to do with the UAdjustment?
#functionCompromised(FunctionA,U) <= utility(FunctionA,U) & implements(FunctionA,ServiceA,UAdjustment) & compromised(ServiceA)
#functionCompromisedWithAttributes(FunctionA,U) <=

#functionDownOrCompromised(FunctionA,U) <=  ((COK == False) or (IOK == False) or (AOK == False)) & consumesDataWithAttributes(FunctionA,DatumA,COK,IOK,AOK)

#TODO This is very coarse. It negates the entire utility when it should just multiply
functionDownOrCompromised(FunctionA,U) <= consumesDataWithAttributesNoAlternative(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) & utility(FunctionA,U)

#requiresDataWithAttributes(FunctionA,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact)
#requires connection with attributes that's not provided

#Transitive Requires
#Function A requires Function C if (Function A requires Function B) and (Function B requires Function C)
requiresFunction(FunctionA,FunctionC) <= requiresFunction(FunctionA,FunctionB) & requiresFunction(FunctionB,FunctionC)
#NOTE: Do we need a data-need hierarchy, too?
#TODO: Requires OR for functions, requires AND for functions, with utility decreases

#requiresSecurityAttribute('transmissionMgmt','integrity','trMgmtCommandData','engineerWorkstation','1.0')
#For backward compatibility
requires(FunctionA,ServiceA) <= consumesData(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact)
#NOTE: This needs to be extended to allow for if two services produce the same Data
#TODO: This should probably be deleted...it doesn't make sense any more with the data flow focus
requires(FunctionA,ServiceB) <= producesData(ServiceB,Data) & consumesDataWithAttributes(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) #requiresDataWithAttributes(FunctionA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact)

#implements means a function is implemented by a component
#This connects the dynamic perspective to the functional perspective
#The U here is an adjustment to the utility
#A function is implemented if the function is implemented by a component and the component is not compromised
#A function can only be implemented by a single component, though a component can implement many functions
#implementedF(FunctionA,U) <= implements(FunctionA,ServiceA,U) & ~compromised(ServiceA)

#+ consumesData('transmissionF','transmissionC2',False,0,True,1.0,False,0)
#Services/Components produce and consume
#Functions require and provide
#+ consumesData('transmissionF','opc','statusModbusData',False,0,True,1,True,0.5)
#consumesDataWithAttributes(FunctionA,ServiceA,Data,COK,IOK,AOK) <= consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & producesData(ServiceB,Data) & transitiveConnectsWithAttributes(ServiceA,ServiceB,CProvided,IProvided,AProvided) & (COK == ((not CRequired) or (CRequired and CProvided))) & (IOK == ((not IRequired) or (IRequired and IProvided))) & (AOK == ((not ARequired) or (ARequired and AProvided)))

#TODO Come back to this in a second
#NOTE Paths are built from the consumer of the data flow backwards, so
#if there is directionality of the connections, this could be an issue
#Good one is below
#consumesDataWithAttributes(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) <= consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & producesData(ServiceB,Data) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P) & (COK==CRequired) & (IOK==CProvided) & (CRequired==False) & (AOK=='rule1True')

#consumesDataWithAttributes(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) <= consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & producesData(ServiceB,Data) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P) & (COK==CRequired) & (IOK==CProvided) & (CRequired==True) & (CProvided==True) & (AOK=='rule2True')

#consumesDataWithAttributes(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) <= consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & producesData(ServiceB,Data) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P) & (COK==CRequired) & (IOK==CProvided) & (CRequired==True) & (CProvided==False) & (AOK=='rule3False')

#consumesDataOnlyGoodPath(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) <= consumesDataWithAttributes(FunctionA,ServiceA,Data,True,CImpact,True,IImpact,True,AImpact,P) & ~consumesDataWithAttributes(FunctionA,ServiceA,Data,True,CImpact,True,IImpact,True,AImpact,P2) & (P2!=P1)

consumesDataWithAttributesNoAlternative(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) <= consumesDataWithAttributeProblems(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) & ~consumesDataWithAttributes(FunctionA,ServiceA,Data,True,CImpact,True,IImpact,True,AImpact,P2)

noIdealConsumption(FunctionA,ServiceA,Data,True,CImpact,True,IImpact,True,AImpact,P2) <= ~consumesDataWithAttributes(FunctionA,ServiceA,Data,True,CImpact,True,IImpact,True,AImpact,P2)

consumesDataWithAttributeProblems(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) <= consumesDataWithAttributes(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) & (COK==False)
consumesDataWithAttributeProblems(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) <= consumesDataWithAttributes(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) & (IOK==False)
consumesDataWithAttributeProblems(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) <= consumesDataWithAttributes(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) & (AOK==False)


consumesDataWithAttributes(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) <= consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & producesData(ServiceB,Data) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P) & consumesDataWithC(FunctionA,ServiceA,ServiceB,CRequired,CProvided,P,COK) & consumesDataWithI(FunctionA,ServiceA,ServiceB,IRequired,IProvided,P,IOK) & consumesDataWithA(FunctionA,ServiceA,ServiceB,ARequired,AProvided,P,AOK)



#This function consumes some data on this service. The boolean is whether or not the service is consumed with confidentiality in tact
consumesDataWithC(FunctionA,ServiceA,ServiceB,CRequired,CProvided,P,True) <= (CRequired==True) & (CProvided==True) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)

consumesDataWithC(FunctionA,ServiceA,ServiceB,CRequired,CProvided,P,True) <= (CRequired==False) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)

consumesDataWithC(FunctionA,ServiceA,ServiceB,CRequired,CProvided,P,False) <= (CRequired==True) & (CProvided==False) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)

consumesDataWithI(FunctionA,ServiceA,ServiceB,IRequired,IProvided,P,True) <= (IRequired==True) & (IProvided==True) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)

consumesDataWithI(FunctionA,ServiceA,ServiceB,IRequired,IProvided,P,True) <= (IRequired==False) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)

consumesDataWithI(FunctionA,ServiceA,ServiceB,IRequired,IProvided,P,False) <= (IRequired==True) & (IProvided==False) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)

consumesDataWithA(FunctionA,ServiceA,ServiceB,ARequired,AProvided,P,True) <= (ARequired==True) & (AProvided==True) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)

consumesDataWithA(FunctionA,ServiceA,ServiceB,ARequired,AProvided,P,True) <= (ARequired==False) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)

consumesDataWithA(FunctionA,ServiceA,ServiceB,ARequired,AProvided,P,False) <= (ARequired==True) & (AProvided==False) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)

#BUG the multiplication needs to be modified by the OK true and falses
consumeseDataWithModifiedUtilityUnderAttack(FunctionA,ServiceA,Data,UMod,DFP,AP) <= consumesDataWithAttributesUnderAttack(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,DFP,AP) & (UMod==(CImpact * Impact * AImpact))

#AP is the attack path and DFP is the DataFlowPath
consumesDataWithAttributesUnderAttack(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,DFP,AP) <= consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & producesData(ServiceB,Data) & transitiveConnectsWithAttributesOnPathUnderAttack(ServiceA,ServiceB,CProvided,IProvided,AProvided,DFP,AP) & consumesDataWithCUnderAttack(FunctionA,ServiceA,ServiceB,CRequired,CProvided,DFP,AP,COK) & consumesDataWithIUnderAttack(FunctionA,ServiceA,ServiceB,IRequired,IProvided,DFP,AP,IOK) & consumesDataWithAUnderAttack(FunctionA,ServiceA,ServiceB,ARequired,AProvided,DFP,AP,AOK)

#This function consumes some data on this service. The boolean is whether or not the service is consumed with confidentiality in tact
consumesDataWithCUnderAttack(FunctionA,ServiceA,ServiceB,CRequired,CProvided,DFP,AP,True) <= (CRequired==True) & (CProvided==True) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & producesData(ServiceB,Data) & transitiveConnectsWithAttributesOnPathUnderAttack(ServiceA,ServiceB,CProvided,IProvided,AProvided,DFP,AP) #No service along the data flow path has a confidentiality issue in the attack path

consumesDataWithC(FunctionA,ServiceA,ServiceB,CRequired,CProvided,P,True) <= (CRequired==False) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)

consumesDataWithC(FunctionA,ServiceA,ServiceB,CRequired,CProvided,P,False) <= (CRequired==True) & (CProvided==False) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)

consumesDataWithI(FunctionA,ServiceA,ServiceB,IRequired,IProvided,P,True) <= (IRequired==True) & (IProvided==True) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)

consumesDataWithI(FunctionA,ServiceA,ServiceB,IRequired,IProvided,P,True) <= (IRequired==False) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)

consumesDataWithI(FunctionA,ServiceA,ServiceB,IRequired,IProvided,P,False) <= (IRequired==True) & (IProvided==False) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)

consumesDataWithA(FunctionA,ServiceA,ServiceB,ARequired,AProvided,P,True) <= (ARequired==True) & (AProvided==True) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)

consumesDataWithA(FunctionA,ServiceA,ServiceB,ARequired,AProvided,P,True) <= (ARequired==False) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)

consumesDataWithA(FunctionA,ServiceA,ServiceB,ARequired,AProvided,P,False) <= (ARequired==True) & (AProvided==False) & consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P)

#Changed this to comment it
#transitiveConnectsWithAttributesOnPathUnderAttack(ServiceA,ServiceB,CProvided,IProvided,AProvided,DFP,AP)

#BUG
#consumesDataWithAttributes(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) <= consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & producesData(ServiceB,Data) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P) & (COK==CRequired) & (IOK==CProvided) & (CRequired==False) & (AOK==providesIfRequired(CRequired,CProvided))




#consumesDataWithAttributes(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) <= consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & producesData(ServiceB,Data) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P) & (((CRequired==False) and (COK==True)) or ((CRequired==True) and (CProvided==True) and (COK==True)) or ((CRequired==True) and (CProvided==False) and (COK==False))) & (((IRequired==False) and (IOK==True)) or ((IRequired==True) and (IProvided==True) and (IOK==True)) or ((IRequired==True) and (IProvided==False) and (IOK==False))) & (((ARequired==False) and (AOK==True)) or ((ARequired==True) and (AProvided==True) and (AOK==True)) or ((ARequired==True) and (AProvided==False) and (AOK==False)))





 #(((CRequired==False) & (COK==True)) or ((CRequired==True) and (CProvided==True) and (COK==True)) or (COK==False)) & (((IRequired==False) & (IOK==True)) or ((IRequired==True) and (IProvided==True) and (IOK==True)) or (IOK==False)) & (((ARequired==False) & (AOK==True)) or ((ARequired==True) and (AProvided==True) and (AOK==True)) or (AOK==False)) & (CImpact==0) & (IImpact==0) & (AImpact==0)


#consumesDataWithAttributes(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) <= consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & producesData(ServiceB,Data) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P) & (((CRequired==False) & (COK==True)) or ((CRequired==True) and (CProvided==True) and (COK==True)) or (COK==False)) & (((IRequired==False) & (IOK==True)) or ((IRequired==True) and (IProvided==True) and (IOK==True)) or (IOK==False)) & (((ARequired==False) & (AOK==True)) or ((ARequired==True) and (AProvided==True) and (AOK==True)) or (AOK==False))

#consumesDataWithAttributes(FunctionA,ServiceA,Data,COK,CImpact,IOK,IImpact,AOK,AImpact,P) <= consumesData(FunctionA,ServiceA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact) & producesData(ServiceB,Data) & transitiveConnectsWithAttributesOnPath(ServiceA,ServiceB,CProvided,IProvided,AProvided,P) & (COK==((not CRequired) or (CRequired and CProvided))) & (IOK==((not IRequired) or (IRequired and IProvided))) & (AOK==((not ARequired) or (ARequired and AProvided)))



#& (COK== (CRequired)) & (IOK==IRequired) & (AOK==ARequired)

#& (COK == ((not CRequired) or (CRequired and CProvided))) & (IOK == ((not IRequired) or (IRequired and IProvided))) & (AOK == ((not ARequired) or (ARequired and AProvided)))

# requiresDataWithAttributes(FunctionA,Data,CRequired,CImpact,IRequired,IImpact,ARequired,AImpact)
#NOTE: There needs to be a way to connect Data, for example ModBus and REST status so that one instance of an end to end connection connects the same instances

# Requires  Produces    ConsumesOK (only if (required and provided) or not required)
# T         T           T
# T         F           F
# F         T           T
# F         F           T
#
