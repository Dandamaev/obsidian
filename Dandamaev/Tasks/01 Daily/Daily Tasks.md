```dataview
TABLE without id
file.link AS "Daily Tasks"
FROM "Tasks/01 Daily"
WHERE file.name != "Daily Tasks"
```

```button
name Daily Tasks
type note(Tasks/01 Daily/today) template
action daily-taks-template
color blue
```

```button 
name New Task 
type command 
action Templater: Create new note from template
color blue
```
