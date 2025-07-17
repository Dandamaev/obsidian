
1. The **Logical Data Model** slide presents the **AuthenticationProvider** class, which maintains RBAC rules and a cache of **SSOTokens**, containing a `token` and `login_time`. The provider offers methods to authenticate and validate tokens.

2. The **API Usage** slide outlines the `/auth/login` endpoint, which handles SSO (Single Sign-On) authentication and RBAC (Role-Based Access Control) validation.
   
3. The **Physical Schema** slide shows the **Users** table with fields for `id`, timestamps, and login details, linked via a 1-to-many relationship to the **Sessions** table, which tracks session tokens and expiration times.

need for sso 
used for further interactions
  

1. The project involves an Authenticator system with a logical data model that includes an AuthenticationProvider with methods for Authenticate and ValidateToken.
    
2. The SSOToken entity holds the token and login_time for single sign-on (SSO) functionality.
    
3. The API usage for authentication involves a POST request to /auth/login to perform SSO authentication.
    
4. The physical schema details two entities: Users and Sessions, with a one-to-many relationship between them.
    
5. The Users table includes fields for id, username, password_hash, and timestamps for creation and last login.
    
6. The Sessions table tracks session_token, expires_at, and created_at times, linked to users via user_id.

