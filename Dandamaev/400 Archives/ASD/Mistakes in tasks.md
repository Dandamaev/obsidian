## Task 9
1) ucs diag incorr notation -> no meaning  
2) ddd: stereotypes incorr, svc cant have state,  
3) design: API Gw cant be root (no state), system does not have any state  
4) uml cls diag - attr:Type, not "Type attr", attrs dupl assoc  
5) check event diag maps to class diag/uc diag

### 1. UCS
1. **Упрощение и группировка use cases:**  
    Многие use cases избыточны и могут быть объединены. Например, **"Generate OpenAPI Specification"** и **"Provide API Documentation"** можно объединить в один use case, связанный с генерацией и предоставлением документации.
    
2. **Удаление или переименование некорректных use cases:**
    
    - **"Enwrap model" (uc19)** — неясное название. Предлагаю заменить на более понятное, например, **"Package Model"**.
    - **"Forward Request to K8s Service" (uc2)** — может быть заменено на более общее **"Route Request"**.
3. **Корректные связи между use cases:**  
    Использование **`<<includes>>`** и **`<<extends>>`** должно отражать реальные зависимости между действиями. Убедитесь, что **`<<includes>>`** применяется для обязательных шагов, а **`<<extends>>`** для условных или дополнительных действий.
    
4. **Четкое разделение ответственности между актёрами:**  
    Разделите use cases по зонам ответственности актёров, чтобы избежать путаницы.
    
5. **Убрать бессмысленные зависимости и связи:**  
    Некоторые связи могут быть избыточными или логически не обоснованными. Например, связь между **"Check Authorization Token" (uc10)** и **"Token Valid"**/**"Token Invalid"** можно упростить.


***
## Task 9.1
comp diag: no ports, some connections without interfaces, 9 aggregates and 5 components, table misses a lot of UC 
ddd mistakes (two roots), class diagram missed counts and assoc names
***
## Task 10
check use cases are still representative for the project

