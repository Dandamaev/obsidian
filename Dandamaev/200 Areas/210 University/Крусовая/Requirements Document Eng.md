Okay, here is the Requirements Document for Atlas translated into English, based on the Version 0.2 structure and content you provided. Sections still requiring information are marked accordingly.

---

**Requirements Document for Atlas**

**Version 0.2 (Draft based on updated data)**

**Prepared by:** [Your Name/Team] *(Please specify authors)*
**Based on data provided by:** [Username], [Date of update]

**Keywords:** authentication, authorization, OAuth2.0, API integration, user management, web application security, SaaS, iframe, postMessage, FastAPI, React, PostgreSQL, Docker.

---

**(Preliminary) Table of Contents**

1.  **Goal of the project**
2.  **Brief description of the subject area**
3.  **Feasibility study and main decisions**
    3.1. Goals, tasks, and constraints
    3.2. Preliminary architecture
    3.3. Technology stack
        3.3.1. Interoperability
        3.3.2. Scalability
    3.4. Prototyping methodology
    3.5. XXXOps (DevOps, SecOps)
4.  **Software Requirement Specification (SRS)**
5.  **Conceptual modeling**
    5.1. Description of the infological model construction process
        5.1.1. Entity-relationship diagram (ERD) with comments (PlantUML)
    5.2. User journeys
6.  **Logical data modeling**
    6.1. Description of the process of transition to a datalogical (relational) model
        6.1.1. Table-reference diagram (TRD) with comments
7.  **Logical process modeling**
    7.1. Main scenarios (BPMN)
    7.2. Partial dataflow diagram (DFD or similar)
8.  **Physical data modeling**
    8.1. DB schema diagram (with data types and referential integrity)
    8.2. Additional mechanisms for ensuring data integrity
    8.3. DDL code of the DB
9.  **Application construction**
    9.1. Business logic of the test application
    9.2. Technical description of the test application
    9.3. UI solutions
    9.4. Examples of data editing in the DB
    9.5. Queries and reports (including SQL)
    9.6. Usability testing artifacts
10. **The results of functional testing**
11. **The results of usability testing**
12. **Conclusion**
13. **Appendices (e.g., References)**

---

**1. Goal of the project**

Development of the **Atlas** cloud service, providing developers with a platform for simplified integration, configuration, and management of authentication and authorization systems in their web applications. The service aims to reduce the complexity and development time associated with implementing login, registration, OAuth2.0 support (including Russian providers), and user management features.

**2. Brief description of the subject area**

The project belongs to the domain of Identity and Access Management (IAM), Authentication as a Service (AaaS), and Developer Tools. The subject area includes:
*   Authentication mechanisms (password-based, via OAuth2.0/OpenID Connect).
*   OAuth2.0 and OpenID Connect protocols.
*   User session management (JWT).
*   Role-Based Access Control (RBAC).
*   Web application security (password hashing, CORS, HTTPS).
*   Interface embedding (iframe, postMessage).

**3. Feasibility study and main decisions**

**3.1. Goals, tasks, and constraints**

*   **Goals:**
    *   Create a scalable and secure Atlas service.
    *   Simplify the authentication integration process for developers.
    *   Ensure support for popular OAuth2.0 providers, including Russian ones (Yandex.ID).
    *   Provide a user-friendly interface for managing users and projects.
    *   Occupy a niche in the Russian market for IAM solutions targeting small and medium-sized projects.
*   **Tasks:**
    *   Develop the backend REST API (FastAPI).
    *   Develop the frontend web interface (React) for embeddable forms and the admin panel.
    *   Implement a secure embedding mechanism using iframe and postMessage.
    *   Integrate OAuth2.0 providers (Google, Yandex).
    *   Implement a user and role management system.
    *   Set up the deployment infrastructure (Docker).
    *   Conduct testing (functional, usability, load).
*   **Constraints:**
    *   The project is being developed within an academic framework (course project, master's thesis).
    *   The initial version (prototype) supports only 2 OAuth providers (Google, Yandex).
    *   No functionality to add multiple administrators (owners of Atlas projects) to a single project.
    *   Limited hardware resources for prototype deployment.
    *   Dependency on the availability and terms of third-party OAuth provider APIs.

**3.2. Preliminary architecture**

*   **Components:**
    *   **Backend:** Monolithic (at this stage, with plans to transition to a microservice architecture in the future) application using FastAPI, responsible for the REST API, authentication logic, database interaction, and OAuth provider communication.
    *   **Frontend:** Application using React JS, providing:
        *   An admin panel for Atlas administrators (project owners).
        *   An interface to retrieve necessary data for embedding forms (e.g., Project ID).
    *   **Database:** PostgreSQL relational DBMS for storing data of Atlas administrators (`admins`), their projects (`projects`), and end-users (`users`) registered via Atlas for a specific project.
*   **Interaction:**
    *   The frontend (admin panel) interacts with the backend via REST API.
    *   Integration of embeddable Atlas forms into third-party applications is done via `<iframe>` with data exchange using `postMessage`.
*   **Deployment:** Containerization using Docker and Docker Compose. Request proxying via Nginx.

    *   **[Information Needed]:** *Is there a more detailed architecture diagram (e.g., showing main backend modules, interaction with external systems)?*

**3.3. Technology stack**

*   **Backend:** Python, FastAPI, PostgreSQL, SQLAlchemy (with Alembic for migrations), Pydantic, python-jose (for JWT), Bcrypt.
*   **Frontend:** JavaScript, React JS, Redux (Redux Toolkit), Axios, Ant Design, React Router.
*   **Infrastructure:** Docker, Docker Compose, Nginx.
*   **Testing:** Pytest (for backend), a separate web application (React) for manual and potentially automated E2E testing of embeddable forms.

    **3.3.1. Interoperability**
    *   Ensured through a standardized REST API (FastAPI automatically generates OpenAPI/Swagger documentation).
    *   Use of standard OAuth2.0/OpenID Connect protocols.
    *   The `iframe` + `postMessage` embedding mechanism is a web standard.

    **3.3.2. Scalability**
    *   Horizontal scaling of backend services is possible due to containerization (Docker) and the asynchronous nature of FastAPI.
    *   Nginx can be used for load balancing.
    *   PostgreSQL supports replication for read scaling.

**3.4. Prototyping methodology**

*   The project started as an MVP (Minimum Viable Product) within a course project framework.
*   Core functions were implemented: Atlas admin registration/login (including OAuth), project creation/management, basic role system for end-users, embeddable forms for end-users (login/registration via email and OAuth).
*   Further development is planned as part of a master's thesis, involving architectural redesign (possibly microservices) and functional expansion.

    *   **[Information Needed]:** *What specific development methodology was used (Agile, Scrum, Waterfall)? How were requirements and feedback gathered during the MVP phase?*

**3.5. XXXOps (DevOps, SecOps)**

*   **DevOps:**
    *   Docker and Docker Compose are used to create a reproducible development environment and simplify deployment.
    *   CI/CD (e.g., GitHub Actions) is planned for automating builds, testing, and deployment.
*   **SecOps:**
    *   Password hashing (Bcrypt).
    *   JWT protection (short access token lifespan, use of refresh tokens, storing JWT and OAuth secrets in environment variables).
    *   CORS configuration for the API.
    *   Use of HTTPS (via Nginx).
    *   Input data validation at the API level (Pydantic).
    *   Rate Limiting implemented for authentication endpoints.

    *   **[Information Needed]:** *Are logging and monitoring systems configured? Is there a specific CI/CD plan? Have security audits or static/dynamic code scanning been performed?*

**4. Software Requirement Specification (SRS)**

*   **Functional Requirements:**
    *   `REQ-F-1` (High): The system shall allow an Atlas administrator (hereinafter "Admin") to register using an email and password.
    *   `REQ-F-2` (High): The system shall allow an Admin to authenticate using email/password or via OAuth2.0 (Google, Yandex).
    *   `REQ-F-3` (High): The Admin shall be able to create, view, edit, and delete their projects.
    *   `REQ-F-4` (High): The Admin shall be able to configure project settings (name, description, redirect URL, OAuth settings).
    *   `REQ-F-5` (High): The system shall provide a unique ID for each project for use when embedding forms.
    *   `REQ-F-6` (High): The system shall provide the ability to embed login and registration forms for end-users (hereinafter "User") into third-party applications via iframe.
    *   `REQ-F-7` (High): The embedded forms shall allow a User to register/authenticate via email/password or OAuth2.0 (if enabled for the project).
    *   `REQ-F-8` (High): The system shall ensure secure data exchange (tokens, user data) between the iframe and the parent application via `postMessage`.
    *   `REQ-F-9` (Medium): The Admin shall be able to view the list of Users registered within their project.
    *   `REQ-F-10` (Medium): The Admin shall be able to change a User's role within their project (e.g., 'user', 'admin').
    *   `REQ-F-11` (Medium): The Admin shall be able to block/unblock a User within their project.
    *   `REQ-F-12` (High): The web interface (Admin panel and embedded forms) shall display error notifications (e.g., API unavailability, validation errors, OAuth issues).
    *   `REQ-F-13` (Medium): The Admin shall be able to enable/disable OAuth for a project and select active providers (Google, Yandex).
*   **Non-functional Requirements:**
    *   `REQ-NF-1` (High): API response time for authentication operations (login, registration, OAuth callback) shall not exceed 500 ms under average load (~50 concurrent requests).
    *   `REQ-NF-2` (High): The interface of the Admin panel and embedded forms shall be intuitive (adhering to standard web application patterns) and not require extensive training.
    *   `REQ-NF-3` (Medium): The system shall display and function correctly in the latest versions of Google Chrome, Mozilla Firefox, and Apple Safari browsers.
    *   `REQ-NF-4` (High): Service availability (uptime) for the prototype shall be at least 99%.
    *   `REQ-NF-5` (Medium): The system (prototype) shall be designed to support up to 500 active Users (total across all projects) without significant performance degradation (>1 sec per request).
    *   `REQ-NF-6` (High): Secure authentication and data transmission methods shall be used (HTTPS, signed JWTs, secure cookie flags if used, postMessage origin check, Bcrypt password hashing).
    *   `REQ-NF-7` (Medium): The codebase shall be modular (separation into routers, services, models in FastAPI; components, pages, services in React) and contain comments for key or complex code sections.

    *   **[Information Needed]:** *Confirmation and possibly refinement of requirement wordings and priorities are needed. Are there requirements for localization or accessibility?*

**5. Conceptual modeling**

**5.1. Description of the infological model construction process**

The infological model was developed based on the analysis of the main use cases for the Atlas service. Key entities were identified:
*   **Admins (Atlas Administrators):** Subjects who register in Atlas, create, and manage projects. They have `login`, `email`, `password` (hashed, nullable for OAuth), OAuth provider data (`oauth_provider`, `oauth_user_id`), timestamps (`created_at`, `updated_at`, `last_login`).
*   **Projects:** Entities created by Administrators. Each project represents an authentication configuration for one third-party application. They have a unique `id` (UUID), `name`, `description`, `url` (for redirects), `owner_id` (reference to Admins), OAuth settings (`oauth_enabled`, `oauth_providers` in JSON), timestamps.
*   **Users (End Users):** Subjects who register or log into a third-party application *via* Atlas forms associated with a specific project. They have `login`, `email`, `password` (hashed, null for OAuth), `project_id` (reference to Projects), `role` (string, e.g., 'user', 'admin' - role *within the project*), `status` (Enum: 'active', 'blocked'), OAuth data, timestamps.

Relationships between entities:
*   One `Admin` can own many `Projects` (one-to-many).
*   One `Project` belongs to one `Admin` (many-to-one).
*   One `Project` can have many `Users` (one-to-many).
*   One `User` belongs to one `Project` (many-to-one).

This model was implemented using the SQLAlchemy ORM, the code for which was provided.

    **5.1.1. Entity-relationship diagram (ERD) with comments (PlantUML)**

```plantuml
@startuml ERD for Atlas

!define ENTITY class
!define ATTRIBUTE_PK *
!define ATTRIBUTE_FK -
!define ATTRIBUTE_NN --
!define RELATIONSHIP(left, op, right, name) left op right : name

ENTITY AdminsBase {
  ATTRIBUTE_PK id : int
  ATTRIBUTE_NN login : String <<unique>>
  ATTRIBUTE_NN email : String <<unique>>
  password : String <<nullable>>
  ATTRIBUTE_NN created_at : timestamp
  ATTRIBUTE_NN updated_at : timestamp
  oauth_provider : OAuthProviderEnum <<nullable>>
  oauth_user_id : String <<nullable>>
  last_login : timestamp <<nullable>>
  __tablename__ = "admins"
  .. Relations ..
  ' One Admin has many Projects
}

ENTITY ProjectsBase {
  ATTRIBUTE_PK id : String(36) / UUID <<default>>
  ATTRIBUTE_NN name : String(255)
  ATTRIBUTE_NN description : String(255)
  ATTRIBUTE_FK ATTRIBUTE_NN owner_id : int <<FK>>
  url : String <<nullable>>
  ATTRIBUTE_NN oauth_enabled : Boolean <<default: false>>
  oauth_providers : JSON <<nullable>>
  ATTRIBUTE_NN created_at : timestamp
  ATTRIBUTE_NN updated_at : timestamp
  __tablename__ = "projects"
  .. Relations ..
  ' One Project belongs to one Admin
  ' One Project has many Users
}

ENTITY UsersBase {
  ATTRIBUTE_PK id : int
  ATTRIBUTE_NN login : String <<unique>>
  ATTRIBUTE_NN email : String <<unique>>
  password : String <<nullable>>
  ATTRIBUTE_FK ATTRIBUTE_NN project_id : String(36) / UUID <<FK>>
  ATTRIBUTE_NN role : String <<default: "user">>
  ATTRIBUTE_NN status : UserStatusEnum <<default: "active">>
  ATTRIBUTE_NN created_at : timestamp
  ATTRIBUTE_NN updated_at : timestamp
  oauth_provider : OAuthProviderEnum <<nullable>>
  oauth_user_id : String <<nullable>>
  last_login : timestamp <<nullable>>
  __tablename__ = "users"
  .. Relations ..
  ' One User belongs to one Project
}

' Relationships
RELATIONSHIP(AdminsBase, "1", "0..*", ProjectsBase, owns) : owner_id -> id
RELATIONSHIP(ProjectsBase, "1", "0..*", UsersBase, has)   : project_id -> id

enum UserStatusEnum {
 ACTIVE
 BLOCKED
}

enum OAuthProviderEnum {
 google
 yandex
 ' Add other providers if needed
}

UsersBase::status --> UserStatusEnum
AdminsBase::oauth_provider --> OAuthProviderEnum
UsersBase::oauth_provider --> OAuthProviderEnum

@enduml
```

**5.2. User journeys**

*   **Role Distinction:**
    *   **Admin:** User of the Atlas service who configures authentication for their external applications.
    *   **User:** End-user of an external application who uses Atlas forms to log in or register.
*   **Example Scenarios:**
    *   **Scenario 1 (Admin): Registration and Project Creation**
        1.  Admin navigates to the Atlas website.
        2.  Chooses the option to log in/register via Google or Yandex.
        3.  Authenticates with the provider.
        4.  Is redirected back to Atlas, where their account is created.
        5.  Admin goes to the "Projects" section and clicks "Create Project".
        6.  Enters Name, Description, and the Redirect URL for their application (where to redirect Users after successful login).
        7.  Configures OAuth options (enables OAuth, selects Google/Yandex).
        8.  Saves the project.
        9.  Copies the generated project UUID for integration into their application.
    *   **Scenario 2 (User): Registration in a third-party app via Atlas (iframe)**
        1.  User visits the website of an application that has integrated Atlas.
        2.  Clicks the "Register" button.
        3.  The page displays an iframe with the Atlas registration form.
        4.  User enters email, password, and password confirmation.
        5.  Clicks "Register".
        6.  Atlas (within the iframe) sends data to its backend, creates the User associated with the project_id, and sends a `postMessage` to the parent window indicating success (`ATLAS_REGISTER_SUCCESS` with User data).
        7.  The third-party application receives the message, potentially saves the User data locally, and redirects the User to the application's main page (or the URL specified by the Admin).
    *   **Scenario 3 (User): Login to a third-party app via Atlas (OAuth)**
        1.  User visits the website of an application that has integrated Atlas.
        2.  Clicks "Login".
        3.  Inside the Atlas iframe, clicks the "Login with Google" button.
        4.  A Google authentication window opens.
        5.  User logs into Google.
        6.  Google redirects back to Atlas (within the iframe).
        7.  Atlas verifies the user, generates JWT tokens, and sends a `postMessage` to the parent window indicating success (`ATLAS_AUTH_SUCCESS` with tokens).
        8.  The third-party application receives the message, saves the tokens (e.g., in localStorage), and redirects the User to the application's main page.
    *   **Scenario 4 (Admin): Blocking a User**
        1.  Admin logs into the Atlas admin panel.
        2.  Selects the relevant project.
        3.  Navigates to the "Users" tab.
        4.  Finds the target User in the list.
        5.  Clicks the "Block" button next to the User.
        6.  The system changes the User's status to 'blocked'.
        7.  The blocked User can no longer log in via Atlas for this project.

    *   **[Information Needed]:** *Confirmation and possibly more detail for scenarios are required. Are User Stories in the format "As a <role>, I want <action>, so that <goal>" needed?*

**6. Logical data modeling**

**6.1. Description of the process of transition to a datalogical (relational) model**

    *   **[Information Needed]:** *The transition from ERD to the relational model was direct due to the use of an ORM (SQLAlchemy). Each entity became a table. Attributes became columns with corresponding data types. One-to-many relationships were implemented via foreign keys (FK) in the tables on the "many" side (Projects.owner_id -> Admins.id, Users.project_id -> Projects.id). Many-to-many relationships are absent in the current model. The model likely conforms to 3NF, as there are no obvious transitive dependencies and all non-key attributes depend on the primary key. Formal confirmation of the normalization level is needed.*

    **6.1.1. Table-reference diagram (TRD) with comments**
    *   **[Information Needed]:** *Provide a TRD diagram visualizing the `admins`, `projects`, `users` tables, their columns, data types, PKs, and FKs. Tools like dbdiagram.io or similar can be used.*

**7. Logical process modeling**

**7.1. Main scenarios (BPMN)**

    *   **[Information Needed]:** *Provide diagrams for key scenarios (e.g., Scenario 1 and Scenario 3 from section 5.2) using BPMN 2.0 notation. Diagrams should show the sequence of actions, decision points, performers (User, Atlas System, External Provider).*

**7.2. Partial dataflow diagram (DFD or similar)**

    *   **[Information Needed]:** *Provide a Data Flow Diagram (e.g., Level 0 showing Atlas interacting with Admin, User, OAuth Provider, and Third-Party App) or a Level 1 DFD for the OAuth authentication process. The diagram should illustrate main processes, data stores, external entities, and data flows.*

**8. Physical data modeling**

**8.1. DB schema diagram (with data types and referential integrity)**

    *   **[Information Needed]:** *Provide a physical PostgreSQL schema diagram, generated from the ORM or DDL. It must show exact table names, column names, data types (VARCHAR, TIMESTAMP WITH TIME ZONE, INTEGER, BOOLEAN, JSON, ENUM), NOT NULL constraints, PKs, FKs.*

**8.2. Additional mechanisms for ensuring data integrity**

Based on the provided SQLAlchemy code:
*   **`UNIQUE` Constraints:**
    *   `admins.login`
    *   `admins.email`
    *   `users.login`
    *   `users.email`
*   **`NOT NULL` Constraints:** On all fields where `nullable=False`, including crucial identifiers, timestamps, and status fields.
*   **`FOREIGN KEY` Constraints:**
    *   `projects.owner_id` references `admins.id`
    *   `users.project_id` references `projects.id`
*   **`ENUM` Constraints (via SQLAlchemyEnum):**
    *   `admins.oauth_provider`, `users.oauth_provider` (use `OAuthProvider`)
    *   `users.status` (uses `UserStatus`)
*   **Default Values (`default`, `server_default`):** For `projects.id` (UUID), `projects.oauth_enabled` (False), `users.role` ("user"), `users.status` (UserStatus.ACTIVE), `created_at`, `updated_at` (func.now()).
*   **Automatic Updates (`onupdate`):** For `updated_at` fields (func.now()).

**8.3. DDL code of the DB**

    *   **[Information Needed]:** *Provide the complete DDL (Data Definition Language) script for PostgreSQL, which can be generated using Alembic or directly from SQLAlchemy metadata.*

**9. Application construction**

**9.1. Business logic of the test application**

*   The test application simulates a developer's website (e.g., a TODO list or blog) that integrates Atlas for user authentication.
*   **Implemented Scenarios:**
     * Display login and registration pages containing Atlas component.
    * Passing `projectId` to the iframe.
    * Listening for `message` events from Atlas iframe (`ATLAS_AUTH_SUCCESS`, `ATLAS_REGISTER_SUCCESS`, `ATLAS_IFRAME_HEIGHT`).
    * When receiving `ATLAS_AUTH_SUCCESS`: store JWT tokens (access, refresh) in `localStorage`.
    * When `ATLAS_REGISTER_SUCCESS` is received: call its backend API to create a local user record.
    * Managing logged in/unlogged out status based on token availability.
    * Redirecting user to secure pages after successful login (token availability in `localStorage`).
    * Logout implementation (removing tokens from `localStorage`).
    * Using access token for requests to its secure API.

**9.2. Technical description of the test application**

* **Technologies:** React JS + Python(FastAPI) + PostgreSQL + Docker + Nginx.
* ** Key integration component:** `AuthIframe`.
* **Example of working application:** [https://todo.appweb.space/](https://todo.appweb.space/)

**9.3. UI solutions**

*   **Atlas (Admin Panel and Embedded Forms):** Uses the Ant Design UI library for most interface elements (buttons, forms, tables, modals, etc.).
*   **Test Application:** Also uses the Ant Design UI library for its interface elements.

    *   **[Information Needed]:** *Provide screenshots of key Atlas admin panel screens (project list, project details with user list, OAuth settings) and the test application (login/registration page with Atlas iframe, protected page after login).*

**9.4. Examples of data editing in the DB**

*   **Example 1: Admin changing a User's role via API**
    *   Admin selects a user in the project list in the UI panel and chooses a new role ('user' or 'admin').
    *   UI sends a PUT request to `/projects/{project_id}/users/{user_id}/role` with body `{"new_role": "admin"}`.
    *   Backend (FastAPI code provided) verifies Admin permissions, finds the user, and updates the `role` field in the `users` table. SQL (generated by SQLAlchemy): `UPDATE users SET role = 'admin' WHERE id = :user_id AND project_id = :project_id;`
*   **Example 2: Admin creating a Project via API**
    *   Admin clicks "Create Project" in the UI, fills the form (name, description, URL, OAuth settings).
    *   UI sends a POST request to `/projects/` with project data.
    *   Backend (FastAPI code provided) creates a new record in the `projects` table. SQL (generated by SQLAlchemy): `INSERT INTO projects (...) VALUES (...) RETURNING id;`
*   **Example 3: Admin updating a Project via API** (Similar to creation, uses PUT `/projects/{project_id}` and SQL `UPDATE projects SET ... WHERE id = :project_id;`)
*   **Example 4: Admin deleting a Project via API** (Uses DELETE `/projects/{project_id}` and SQL `DELETE FROM projects WHERE id = :project_id;`)
*   **Example 5: Updating User data after OAuth login**
    *   After a successful callback from the OAuth provider, the Atlas backend finds or creates the user in the `users` table and updates the `last_login` field, and potentially `oauth_user_id` / `oauth_provider` if it's the first login via this provider. SQL (generated by SQLAlchemy): `UPDATE users SET last_login = NOW(), oauth_user_id = :oauth_user_id WHERE email = :email AND project_id = :project_id;`

    *   **[Information Needed]:** *Provide screenshots of the corresponding UI forms from the Atlas admin panel.*

**9.5. Queries and reports (including SQL)**

*   **Example 1: Fetching Admin's Projects (with user count)**
    *   Endpoint: `GET /projects/` (code provided).
    *   SQL (generated by SQLAlchemy, approximate structure):
        ```sql
        SELECT
            p.id, p.name, p.description, p.owner_id, p.url, p.oauth_enabled,
            count(u.id) AS user_count
        FROM projects p
        LEFT OUTER JOIN users u ON CAST(u.project_id AS VARCHAR) = CAST(p.id AS VARCHAR) -- Adjust cast based on actual DB types
        WHERE p.owner_id = :current_admin_id
        GROUP BY p.id;
        ```
*   **Example 2: Fetching Project Details (including user list)**
    *   Endpoint: `GET /projects/{project_id}` (code provided).
    *   SQL (two queries, approximate structure):
        ```sql
        -- Query 1: Get project details
        SELECT p.id, ..., count(u.id) AS user_count
        FROM projects p LEFT OUTER JOIN users u ON CAST(u.project_id AS VARCHAR) = CAST(p.id AS VARCHAR)
        WHERE CAST(p.id AS VARCHAR) = :project_id AND p.owner_id = :current_admin_id
        GROUP BY p.id;
        -- Query 2: Get project users
        SELECT u.id, u.login, u.email, u.role, u.status, u.oauth_provider
        FROM users u
        WHERE CAST(u.project_id AS VARCHAR) = :project_id;
        ```
*   **Reports:** Specific reports (e.g., graphs, statistics) are not implemented at this stage.

    *   **[Information Needed]:** *Are there other important queries? Are reports planned?*

**9.6. Usability testing artifacts**

*   Mentioned that assessment was conducted based on Nielsen's principles.

    *   **[Information Needed]:** *Provide specific artifacts: results of the evaluation against Nielsen's heuristics (e.g., a table with ratings and comments per heuristic), description of the testing methodology (who conducted it, on whom, what scenarios were tested), summary of feedback received from testers, description of UI/UX changes made based on the results.*

**10. The results of functional testing**

*   Manual API testing was performed using the Swagger UI.
*   Manual E2E testing was conducted using the separate test web application (`https://todo.appweb.space/`) to verify scenarios involving form embedding, registration, and login (email/password and OAuth).
*   (Presumably) Pytest was used for backend unit tests.

    *   **[Information Needed]:** *Provide a summary of results: number of test cases executed (manual API, manual E2E, automated Pytest unit tests), pass rate percentage, number and severity of defects found and fixed, code coverage reports (if measured).*

**11. The results of usability testing**

    *   **[Information Needed]:** *See section 9.6. Provide formalized usability testing results.*

**12. Conclusion**

The Atlas project has been successfully implemented as an MVP demonstrating key functionality. The system provides embedded forms of authentication with support for both traditional login by email and password and OAuth authorization via popular providers, including Google and Yandex. At the same time, an administrative panel is implemented that allows you to manage projects and exercise basic control over users. The chosen technology stack, including FastAPI for the backend, React for the frontend, PostgreSQL as a DBMS and Docker for containerization, proved its effectiveness for creating a modern, productive and scalable web service.

The project is especially relevant for the Russian market, where there is a steady demand for solutions with integration of local OAuth providers and minimal infrastructure requirements. Functional testing through the test application confirmed the correct operation of all key integration scenarios. Within the framework of testing, special attention was paid to verification of interaction between embedded forms and parent applications through secure data exchange using postMessage.

Further development of the project in the context of the master thesis will focus on several strategic directions. A deep refactoring of the code base is planned, with a possible transition to a microservice architecture to improve the scalability and maintainability of the system. Functional expansion will include adding support for new OAuth providers, implementation of more flexible access control systems (RBAC/ABAC), the ability to assign multiple administrators to a project, implementation of two-factor authentication and tools for customizing the appearance of forms.

Special attention will be paid to security issues: regular security audits, implementation of additional security mechanisms and constant monitoring of vulnerabilities are planned. To ensure stable operation of the growing number of users, performance optimization and improvement of system fault tolerance are planned. In parallel, a comprehensive system of automated testing will be developed, including unit, integration and end-to-end tests, which will help maintain high code quality while actively developing new features.

**13. Appendices (e.g., References)**

*   **Test Application:** [https://todo.appweb.space/](https://todo.appweb.space/)
*   **[Information Needed]:** *Add links to:*
    *   *GitHub repository (if public or will be made public).*
    *   *Swagger/OpenAPI API documentation.*
    *   *Key libraries used (Ant Design, FastAPI, SQLAlchemy, etc.).*
    *   *Sources of statistical data or research (if used to justify relevance).*

---

Please review the translated document and provide the missing information to make it as complete and accurate as possible.