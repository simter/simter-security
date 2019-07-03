package tech.simter.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.simter.Context;

import static org.junit.jupiter.api.Assertions.*;

class SecurityServiceImplTest {
  private SecurityServiceImpl service = new SecurityServiceImpl();

  @BeforeEach
  void setUp() {
    Context.clear();
  }

  @Test
  void hasRole() {
    assertFalse(service.hasRole("ADMIN"));
    Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN");
    assertTrue(service.hasRole("ADMIN"));
  }

  @Test
  void verifyHasRole() {
    Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN");
    service.verifyHasRole("ADMIN");
  }

  @Test
  void verifyHasRoleFailed() {
    assertThrows(SecurityException.class, () -> service.verifyHasRole("ADMIN"));
  }

  @Test
  void hasAnyRole() {
    assertFalse(service.hasAnyRole("ADMIN", "TEST"));
    Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN,TEST");
    assertFalse(service.hasAnyRole("NOT-EXISTS"));
    assertTrue(service.hasAnyRole("ADMIN"));
    assertTrue(service.hasAnyRole("TEST"));
    assertTrue(service.hasAnyRole("ADMIN", "TEST"));
    assertTrue(service.hasAnyRole("TEST", "NOT-EXISTS"));
  }

  @Test
  void verifyHasAnyRole() {
    Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN,TEST");
    service.verifyHasAnyRole("ADMIN");
    service.verifyHasAnyRole("TEST");
    service.verifyHasAnyRole("ADMIN", "TEST");
    service.verifyHasAnyRole("TEST", "NOT-EXISTS");
  }

  @Test
  void verifyHasAnyRoleFailed() {
    assertThrows(SecurityException.class, () -> {
      Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN");
      service.verifyHasAnyRole("NOT-EXISTS");
    });
  }

  @Test
  void hasAllRole() {
    assertFalse(service.hasAllRole("ADMIN"));
    assertFalse(service.hasAllRole("ADMIN", "TEST"));
    Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN,TEST");
    assertFalse(service.hasAllRole("NOT-EXISTS"));
    assertFalse(service.hasAllRole("TEST", "NOT-EXISTS"));
    assertTrue(service.hasAllRole("ADMIN"));
    assertTrue(service.hasAllRole("TEST"));
    assertTrue(service.hasAllRole("ADMIN", "TEST"));
  }

  @Test
  void VerifyHasAllRole() {
    Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN,TEST");
    service.verifyHasAllRole("ADMIN");
    service.verifyHasAllRole("TEST");
    service.verifyHasAllRole("ADMIN", "TEST");
  }

  @Test
  void verifyHasAllRoleFailed1() {
    assertThrows(SecurityException.class, () -> {
      Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN");
      service.verifyHasAllRole("NOT-EXISTS");
    });
  }

  @Test
  void verifyHasAllRoleFailed2() {
    assertThrows(SecurityException.class, () -> {
      Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN,TEST");
      service.verifyHasAllRole("ADMIN", "NOT-EXISTS");
    });
  }
}