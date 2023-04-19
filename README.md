First, do the following:

pip install pyDatalog

# SourceService connects to TargetService.
# Booleans or values 0-1.0 for if confidentiality, integrity, and availability are provided on the connection
+ connectsTo(SourceService,TargetService,CProvided,IProvided,AProvided)

# Note: Should this be isType? If not, then there should be a ChildType and ParentType or something like that
+ isSubType(TargetService,TargetType)

# Note: isType shouldn't use the same name for the instance and the type or it will mess up credential evaluation, when we treat use the instance name as the type name so we can specifically apply a credential as a vulnerability in an instance.

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
+ consumesData(FuncName,ConsumesSet,Data,CImpact,IImpact,AImpact)
# The following two lines define that FunctName requires Data for AND(OR(TargetService1,TargetService2),OR(TargetService3,TargetService4)). That is, either 1 or 2, AND either 3 or 4.
+ consumesData(FuncName,[TargetService1,TargetService2],Data,CImpact,IImpact,AImpact)
+ consumesData(FuncName,[TargetService3,TargetService4],Data,CImpact,IImpact,AImpact)

# Note that each component MUST have a credential fact associated with it, or it will not be included in attack path evaluation. This is to eliminate branching on attack path generation depending on whether or not a component has a credential. The goal is to reduce state space explosion.
+ hasCredentials(SourceService,CredentialSet)

# Branches are needed to explain why backups are important

# Explain the optimization by memoizing the leaves and the branches to ensure all scenarios are topologically distinct

# Note that there is C,I,A for connectsTo (connectors) and for exploits that act on components

# When we multiply for cumulative C,I,A (in creating transitive paths) and when we add (in creating sum effects over C, I, A) -- each C,I,A can tank the whole utility, but if one is not required (0), then it shouldn't be multiplied, because that would make everything 0. And (1-0) creates the wrong effect, too, if one wants to multiply.

# Only one exploit can be used on a given component each scenario

# U - (CRequired)*(1-CProvided)*U 
# 1 - (CRequired)*(1-CProvided)
# CRequired (% of total U) | CProvided (% of total C) | CImpact (Multiple Effect on Utility)    |   1-CProvided | Product
#       1                           1                           1                                   0               0
#       1                           0.5                         0.5                                 0.5             0.5
#       1                           0                           0                                   1               1
#       0.5                         1                           1                                   0               0
#       0                           1                           1                                   0               0
#       0                           0                           1                                   1               0
#       0.5                         0.5                         0.75                                0.5             0.25


# compromised represents an attacker having full C,I,A impacts