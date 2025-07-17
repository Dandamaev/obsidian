---
Date: 2024-09-17
Link for presentetion: https://docs.google.com/presentation/d/1uxYgo0zAIf_Gu_M5Ua1j-DrTRG3sXva4fa9412AIRPI/edit#slide=id.ged5cd7653c_0_2
---
### Modeling basic
**Modeling** - is process of developing models.
**Model** - a simplified representation of reality based on a theory to answer to the ызшсшашс questions (with known precision). 
**Design** - 
Conceptual models

#### Metamodel:
##### MOF - Meta-Object Framework
- level 0: object of real world (people, time, table)
- level 1: classes of objects ("table" class with an instance of table) representing real world "UML2"
- level 2: metamodel (classes, instances, relations)
- level 3: metametamodel (classes)**
This is 4 levels of metamodel 
To note MBSE, DSL (xTest, text, some tools from IDEA).
We are interested mostly L1 and L2
Type (in programming) - kind of label and rules of handing that could be applied to objects with same label
- integer (math operations ...)
- Tickets ⇾ class Ticket - type
1. Parametrization 
		1 + 3 ⇾ a + b, a b - integer
2. Specification {smth}
##### ADT
1. Name 
2. Set of operation :
	- pre-conditions
	- past-conditions
3. Assets/ass /axioms
Stack (ADT)
- new (s) ⇾ S
- push (s, a) ⇾ S
- pool (s) ⇾ As

Class - implement of any ADT
- method of operation
- internal state (attribute)
TYPE ⇾ ADT ⇾ Class

*** 
### UML2 metamodel
May contain features:
- Structured (attributes)
- Behavior 
{put pic}
Class in UML - is a kind of Classifier suited for describing software / problem domain, in a class we would have:
- operations instead of features;
- attributes;
- properties;
- hat receptions
- behavior ⇾ methods.

Classifier:
- Class;
- interface;
- Datatype;
- Actors and use cases;
- Associations.

Relations:
- dependency A - - - - - > B;
- Generalization A ⇾ B;
- Association;
- Interface realization A -------|> B.
Association: 
{put pic}

Example:
![[Pasted image 20240917192340.png]]

Aggregation: <>
Composition: <<>>
Qualifier: {tag}

Class Schedule
	events Dictionary \[Tag, List {Event}]

Primitive Type:
- integer;
- string;
- real;
- boolean;
- {Unlimited Natural/integer} will be in TG channel

\+ public
\- private`
\# protected
\~ package

***
### ER-models
Chen notation
Crowfoot notation
We have:
- Entity;
- We
Example:
![[Pasted image 20240917194359.png]]
