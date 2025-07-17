# ADR-001: Choice of Monolithic Architecture for MVP

## Context and Problem Statement
It is necessary to develop the MVP of the Atlas authentication service within the limited academic timeframe (course project) with the possibility of future expansion for a master's thesis.

## Decision Drivers (не достаточно четко)
* Tight development deadlines (3 months)
* Limited resources (2 developers)
* Requirement for quick product launch
* Future scalability plans (>2000)

## Considered Options
1. Monolithic architecture (FastAPI + React) уже готовый почему именно оно.
2. Microservices architecture
3. Hybrid approach (monolith with a dedicated authentication service)

## Decision Outcome
Chosen option: "Monolithic architecture", because:
- Allows implementing MVP 3 times faster
- Minimizes deployment complexity
- Matches current load (<500 users)
- Documented plan for transitioning to microservices in the future

### Consequences
* Good: Accelerated development of core features
* Good: Simplified testing and debugging
* Bad: Potential difficulties with scaling
* Bad: Need for future refactoring

### Confirmation
- MVP successfully launched on time
- Load testing confirmed adequate performance
- Roadmap includes transition to microservices in Q2 2024

## Pros and Cons of the Options

### Monolithic Architecture
* Good: Simple development
* Good: Single codebase
* Bad: Scaling limitations

### Microservices Architecture
* Good: Horizontal scaling
* Bad: High entry threshold
* Bad: Complex orchestration

---
# ADR-002: Choice of PostgreSQL as the main DBMS

## Context and Problem Statement
A reliable storage solution is required for:
- User credentials
- OAuth provider settings
- Audit logs

## Decision Drivers
* Support for ACID transactions
* Ability to store structured and semi-structured data
* Integration with FastAPI
* Availability in Russian cloud providers

## Considered Options
1. PostgreSQL 14+
2. MongoDB 6.0+
3. Yandex Database (YDB)

## Decision Outcome
Chosen option: "PostgreSQL 14+", because:
- Full support for SQLAlchemy
- JSONB for OAuth settings
- Built-in replication
- Compatibility with cloud solutions

### Consequences
* Good: Reliable user data storage
* Good: Support for complex queries
* Bad: Requires optimization for high loads

### Confirmation
- Successful testing with 1000 RPS
- Integration with Alembic for migrations

## Pros and Cons of the Options

### PostgreSQL 14+
* Good: Mature ecosystem
* Good: JSONB + relational queries
* Bad: Sharding complexity

### MongoDB 6.0+
* Good: Flexible schema
* Bad: Limited transactions
* Bad: No JOIN operations

---
# ADR-003: Use of iframe + postMessage for embedding forms

## Context and Problem Statement
A secure method is needed to integrate authentication forms into third-party applications without CORS restrictions.

## Decision Drivers
* Security of data transmission
* Ease of integration for clients
* Support for modern browsers
* Isolation of styles and scripts

## Considered Options
1. Iframe + postMessage
2. OAuth Proxy
3. Web Components + Custom Elements

## Decision Outcome
Chosen option: "Iframe + postMessage", because:
- Standard approach supported by all browsers
- Complete isolation of form code
- Flexibility in communication via postMessage

### Consequences
* Good: Easy implementation
* Good: Support for older browsers
* Bad: Need for strict origin checking

### Confirmation
- Successful integration with 3 test applications
- Penetration testing revealed no vulnerabilities

## Pros and Cons of the Options

### Iframe + postMessage
* Good: Context isolation
* Good: Support for IE11+
* Bad: Security limitations

### OAuth Proxy
* Good: Better security
* Bad: Complex setup
---
1. Conceptual modelling. 
    
    1. Description of a infological model construction process with justification of entities and relationships allocation. 
        
        1. Entity-relationship diagram (ERD) with comments. 
            
    2. User journeys. 
        
2. Logical data modelling. 
    
    1. Description of the process of transition to a datalogical (relational) model with emphasis on the representation of "many to many" relationships and inheritance. 
        
        1. Table-reference diagram (TRD) with comments.  
            
            1. Note: you may combine logical diagram of the relational model it with the database scheme, but primary keys, foreign keys, constraints, etc. should be necessarily reflected). 
                
3. Logical process modelling 
    
    1. Main scenarios. 
        
        1. Note: you may use BPMN. 
            
    2. Partial dataflow diagram (any kind). 
        
        1. Note: you may use classical DFD in simplest form or BPMN data objects. 
            
4. Physical data modelling. 
    
    1. DB schema diagram (data types and reference integrity characteristics must be reflected).  
        
        1. Note: it is desirable to draw the diagram adequately to facilitate its visual perception.  
            
    2. Additional mechanisms for ensuring data integrity. 
        
        1. Note: minimum 2 examples of integrity constraints. 
            
    3. DDL code of the DB.