First, do the following:

pip install pyDatalog

# SourceService connects to TargetService.
# Booleans or values 0-1.0 for if confidentiality, integrity, and availability are provided on the connection
+ connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided)

# Note: Should this be isType? If not, then there should be a ChildType and ParentType or something like that
+ isSubType(TargetService,TargetType)

# Deprecate this
+ isVulnerable(TargetType,VulnType,C,CImpact,IImpact,AImpact)

# A hypothetical exploit of VulnType for TargetType has cost C to create
# and has an impact on confidentiality, integrity, and availability
# The impacts are multiplied against the CProvided, IProvided, AProvided
# so a CImpact of 0 results in a complete loss of confidentiality
+ isVulnerable(TargetType,VulnType,C,CImpact,IImpact,AImpact)

# The producer doesn't necessarily know the use case for the data it produces
# For example, weather forecasts could be used to determine whether or not to bring an umbrella (low imapct) or whether or not it's safe to fly a helicopter (high impact)
# The SourceService here is a producer of the data type Data. There can be multiple producers of Data.
+ producesData(SourceService,Data)
# The consumer knows how it's using the data it consumes. The TargetService component is a consumer of Data on behalf of FuncName. It's agnostic to which component produces the Data. 
# TODO Next: There should be the ability here to have multiple consumers. How do I do that?
# The consumer has weighted (in terms of impact to function utility) requirements for confidentiality, integrity, and availability.
# These weights of CImpact, IImpact, and AImpact should add to 1.0!
# An impact of 0 for any of the parameters below means that it is not required. For example, data may be public, so confidentiality is not a concern.
+ consumesData(FuncName,TargetServiceSet,Data,CImpact,IImpact,AImpact)
# The following two lines define that FunctName requires Data for AND(OR(TargetService1,TargetService2),OR(TargetService3,TargetService4)). That is, either 1 or 2, AND either 3 or 4.
+ consumesData(FuncName,[TargetService1,TargetService2],Data,CImpact,IImpact,AImpact)
+ consumesData(FuncName,[TargetService3,TargetService4],Data,CImpact,IImpact,AImpact)

