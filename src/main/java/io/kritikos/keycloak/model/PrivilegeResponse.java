package io.kritikos.keycloak.model;

import java.util.List;

/**
 * Response model returned by the external privilege API.
 * <p>
 * Expected JSON shape:
 *
 * <pre>
 * {
 *   "userId":   "user-uuid",
 *   "clientId": "my-app",
 *   "privileges": [
 *     { "name": "read:reports",  "description": "Can read reports" },
 *     { "name": "write:orders",  "description": "Can create orders" }
 *   ]
 * }
 * </pre>
 */
public class PrivilegeResponse {

  private String userId;
  private String clientId;
  private List<Privilege> privileges;

  public String getUserId() {
    return userId;
  }

  public void setUserId(String userId) {
    this.userId = userId;
  }

  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public List<Privilege> getPrivileges() {
    return privileges;
  }

  public void setPrivileges(List<Privilege> privileges) {
    this.privileges = privileges;
  }
}
