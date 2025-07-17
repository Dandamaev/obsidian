
| Use case                       | Cooperation name         | Used roles                        | Candidate classes       |
| ------------------------------ | ------------------------ | --------------------------------- | ----------------------- |
| Send Request                   | Request routing          | DevOps Engineer, System Architect | Request Router          |
| Forward Request to K8s Service | Service distribution     | DevOps Engineer, System Architect | Load Balancer           |
| Load Balancing                 | Traffic balancing        | DevOps Engineer                   | Load Balancer           |
| Collect Logs                   | Log management           | DevOps Engineer, System Architect | System Logger           |
| Authenticate                   | Authentication process   | System Architect                  | Authentication Provider |
| Cache Response                 | Response caching         | DevOps Engineer                   | Response Cacher         |
| Deploy Model                   | Service deployment       | Developer, DevOps Engineer        | Service Deployer        |
| Publish Model                  | Model publication        | Developer, DevOps Engineer        | Model Containerizer     |
| OpenAPI Schema Generation      | Documentation automation | Developer                         | OpenAPI Generator       |

| **Use Case**                  | **Cooperation Name**    | **Used Roles**                         | **Candidate Classes**           |
|-------------------------------|-------------------------|----------------------------------------|---------------------------------|
| Send Request                  | Forward to Kubernetes   | API Consumer, Request Router           | Request Router                  |
| Forward Request to K8s Service | Route Request           | API Consumer, Load Balancer            | Load Balancer                   |
| Load Balancing                | Distribute Load         | API Consumer, Load Balancer            | Load Balancer                   |
| Authenticate                  | Validate Authentication | API Consumer, Authentication Provider  | Authentication Provider         |
| Cache Response                | Store Response          | API Consumer, Response Cacher          | Response Cacher                 |
| Collect Logs                  | Log System Events       | Security Specialist, System Logger     | System Logger                   |
| Deploy Model                  | Deploy Service          | ML Engineer, Service Deployer          | Service Deployer                |
| Publish Model                 | Containerize Model      | ML Engineer, Model Containerizer       | Model Containerizer             |
| OpenAPI Schema Generation      | Generate API Definition | API Consumer, OpenAPI Generator        | OpenAPI Generator               |
