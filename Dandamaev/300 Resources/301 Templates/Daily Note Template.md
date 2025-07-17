<< [[<% fileDate = moment(tp.file.title, 'DD.MM.YYYY dddd').subtract(1, 'days').format('DD.MM.YYYY dddd') %>|Yesterday]] | [[<% moment(tp.file.title, 'DD.MM.YYYY dddd').add(1, 'days').format('DD.MM.YYYY dddd') %>|Tomorrow]] >>


## Tasks Due Today
```tasks
not done
due <% tp.file.title %>
hide due date
```
## Overdue Tasks
```tasks
not done
due before <% tp.file.title %>
hide due date
```
## Completed Tasks
```tasks
done <% tp.file.title %>
```
