package tech.simter.security;

/**
 * System Security
 *
 * @author RJ 2017-04-25
 */
public interface SecurityService {
  /**
   * The key that store roles in context
   */
  String CONTEXT_KEY_ROLES = "roles";

  /**
   * Determine whether the context has a specified role
   *
   * @param role the role's identify
   * @return true if has the role, otherwise return false
   */
  boolean hasRole(String role);

  /**
   * Determine whether the context has any specified roles
   *
   * @param roles the role's identifies
   * @return true if has any one role, otherwise return false
   */
  boolean hasAnyRole(String... roles);

  /**
   * Determine whether the context has all the specified roles
   *
   * @param roles the role's identifies
   * @return true if has all roles, otherwise return false
   */
  boolean hasAllRole(String... roles);

  /**
   * Verify whether the context has a specified role
   *
   * @param role the role's identify
   * @throws SecurityException if the context has not the specified role
   */
  void verifyHasRole(String role) throws SecurityException;

  /**
   * Verify whether the context has any specified roles
   *
   * @param roles the role's identifies
   * @throws SecurityException if the context has not any specified role
   */
  void verifyHasAnyRole(String... roles) throws SecurityException;

  /**
   * Verify whether the context has all the specified roles
   *
   * @param roles the role's identifies
   * @throws SecurityException if the context has not all the specified roles
   */
  void verifyHasAllRole(String... roles) throws SecurityException;
}
