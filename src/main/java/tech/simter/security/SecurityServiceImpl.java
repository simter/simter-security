package tech.simter.security;

import tech.simter.Context;

import javax.inject.Named;
import javax.inject.Singleton;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * System Security Implementation by Context
 *
 * @author RJ 2017-04-25
 */
@Named
@Singleton
public class SecurityServiceImpl implements SecurityService {
  public boolean hasRole(String role) {
    Set<String> contextRoles = getContextRoles();
    return contextRoles != null && contextRoles.contains(role);
  }

  public boolean hasAnyRole(String... roles) {
    Set<String> contextRoles = getContextRoles();
    if (contextRoles == null || roles == null) return false;
    for (String role : roles) {
      if (contextRoles.contains(role)) return true;
    }
    return false;
  }

  public boolean hasAllRole(String... roles) {
    Set<String> contextRoles = getContextRoles();
    if (contextRoles == null || roles == null) return false;
    return contextRoles.containsAll(Stream.of(roles).collect(Collectors.toSet()));
  }

  public void verifyHasRole(String role) throws SecurityException {
    Set<String> contextRoles = getContextRoles();
    if (contextRoles == null || !contextRoles.contains(role)) throw new SecurityException();
  }

  public void verifyHasAnyRole(String... roles) throws SecurityException {
    Set<String> contextRoles = getContextRoles();
    if (contextRoles == null || roles == null) throw new SecurityException();
    for (String role : roles) {
      if (contextRoles.contains(role)) return;
    }
    throw new SecurityException();
  }

  public void verifyHasAllRole(String... roles) throws SecurityException {
    Set<String> contextRoles = getContextRoles();
    if (contextRoles == null || roles == null) throw new SecurityException();
    if (!contextRoles.containsAll(Stream.of(roles).collect(Collectors.toSet())))
      throw new SecurityException();
  }

  private Set<String> getContextRoles() {
    String roles = Context.get(CONTEXT_KEY_ROLES);
    return roles == null ? null : Stream.of(roles.split(",")).collect(Collectors.toSet());
  }
}