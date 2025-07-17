```dataview
table without id 
    file.link as "Daily Tasks"
from "/Tasks/00 Weekly"  
where file.name != "Weekly Task"
sort Date desc

```
```button
name New Note
type command
action Templater: Create New Note From Template

```
