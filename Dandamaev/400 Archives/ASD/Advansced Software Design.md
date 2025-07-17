---
Преподаватель: |-
  Хританков Антон Сергеевич 
  Якушева Софья Михайловна
Сайт: https://objectoriented.ru/asd
Git: https://github.com/fanglores/Advanced-Software-Design
---
# 1st_Module
#### List of weekly tasks
- Module 1
	1. Study the domain and define project scope
	2. Apply JTBD to detail the usage context and basic scenarios
	3. Follow DDD to develop a static domain model
	4. Devise the dynamic model using UML
	5. Complete the analysis model (final task module 1)
- Module 2
	1. Develop the software architecture by domain decomposition
	2. Design the user interfaces and APIs
	3. Develop the distributed data model for NoSQL or RDBMS
	4. Complete prototyping and detailed design
	5. Complete the design model (final task module 2)

***
#### Tasks
```dataview
table without id 
    file.link as "Tasks",  
    Deadline as "Deadline"  
from "Study/ASD/Tasks"  
where Deadline
sort file.name asc

```

```button
name New Task
type command
action Templater: Create New Note From Template

```

#### Notes
```dataview
table without id 
    file.link as "Notes",  
    Date as "Date"  
from "Study/ASD/Notes"  
sort Date asc

```

```button
name New Note
type command
action Templater: Create New Note From Template

```

На видео начинать со слов "I'm Name Last Name ..."
Просмотреть шаблон эссе. 

Topic for essay: **"The role of aggregates in domain-driven design"**

Calss diagram 

STORY MAP должна быть читаемой - можно на два слайда

Behavior diagrams for each member behavior activity of doing what? Link Activity with class Candidate (Cooperation) Object flows are not present should be added

Say about roles members | repository structure

***

### Use case Diagram

@startuml
left to right direction

actor SecuritySpecialist as SS
actor DevOpsEngineer as DE
actor Developer as Dev
actor APIConsumer as AC

rectangle System {
  usecase "Request Routing" as RR
  usecase "Load Balancing" as LB
  usecase "Audit and Logging" as AL
  usecase "SSO and Authorization" as SSO
  usecase "Request Validation" as RV
  usecase "Response Caching" as RC
  usecase "Modular Deployment of Models" as MD
  usecase "Containerization" as CN
  usecase "Service Deployment" as SD
  usecase "Model Auto-Documentation" as AD
}

SS -down-> AL
SS -down-> SSO

DE -down-> LB
DE -down-> RC
DE -down-> SD
DE -down-> MD
DE -down-> CN

Dev -down-> MD
Dev -down-> CN
Dev -down-> SD
Dev -down-> AD
Dev -down-> RV

AC -down-> RR
AC -down-> RV
AC -down-> RC
AC -down-> AD

@enduml
***

# 2nd_Module

## Tasks:
- [Task_8](Task_8.md)
- [Task 9](<Task9_1.md>)
- [[Mistakes in tasks]];
- 

## Notes
- [12 NOV 2024](<12 Nov 2024.md>);
- [19 NOV 2024](<19 NOV 2024.md>);
- [26 NOV 2024](<26 Nov 2024.md>);
- [Mini Hack](<mini hack.md>);
- [03 DEC 2024](<03 DEC 2024.md>);
- [[Authentication]];
- [[12 NOV  2024]];
- [[17 DEC 2024]];
- 

## Other
- Замечания к прошлому essay: Lack of personal opinion. Short list of sources, mainly blogs and other sites.
- 
