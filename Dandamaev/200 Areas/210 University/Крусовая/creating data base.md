Admins:
```sql
CREATE TABLE admins (
    id SERIAL PRIMARY KEY,
    login TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

Projects:
```sql
CREATE TABLE projects (
id SERIAL PRIMARY KEY,
name varchar(255) NOT NULL,
description varchar(255) NOT NULL,
owner_id integer references admins(id) NOT NULL
)
```

Users:
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    login TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```
