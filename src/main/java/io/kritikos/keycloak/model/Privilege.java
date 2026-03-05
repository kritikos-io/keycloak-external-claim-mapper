package io.kritikos.keycloak.model;

/**
 * A single application privilege entry.
 */
public class Privilege {

  private String name;
  private String description;

  public Privilege() {
  }

  public Privilege(String name, String description) {
    this.name = name;
    this.description = description;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  @Override
  public String toString() {
    return name;
  }
}
