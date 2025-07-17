```dataview
table without id 
    file.link as "Notes",  
    Date as "Date"  
from "Notes"  
where file.name != "Notes"
sort Date desc

```
```button
name New Note
type command
action Templater: Create New Note From Template

```
