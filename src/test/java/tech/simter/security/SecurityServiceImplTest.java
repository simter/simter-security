package tech.simter.security;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;
import tech.simter.Context;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(MockitoJUnitRunner.StrictStubs.class)
public class SecurityServiceImplTest {
  private SecurityServiceImpl service = new SecurityServiceImpl();

  @Before
  public void setUp() throws Exception {
    Context.clear();
  }

  @Test
  public void hasRole() throws Exception {
    assertThat(service.hasRole("ADMIN"), is(false));
    Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN");
    assertThat(service.hasRole("ADMIN"), is(true));
  }

  @Test
  public void verifyHasRole() throws Exception {
    Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN");
    service.verifyHasRole("ADMIN");
  }

  @Test(expected = SecurityException.class)
  public void verifyHasRoleFailed() throws Exception {
    service.verifyHasRole("ADMIN");
  }

  @Test
  public void hasAnyRole() throws Exception {
    assertThat(service.hasAnyRole("ADMIN", "TEST"), is(false));
    Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN,TEST");
    assertThat(service.hasAnyRole("NOT-EXISTS"), is(false));
    assertThat(service.hasAnyRole("ADMIN"), is(true));
    assertThat(service.hasAnyRole("TEST"), is(true));
    assertThat(service.hasAnyRole("ADMIN", "TEST"), is(true));
    assertThat(service.hasAnyRole("TEST", "NOT-EXISTS"), is(true));
  }

  @Test
  public void verifyHasAnyRole() throws Exception {
    Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN,TEST");
    service.verifyHasAnyRole("ADMIN");
    service.verifyHasAnyRole("TEST");
    service.verifyHasAnyRole("ADMIN", "TEST");
    service.verifyHasAnyRole("TEST", "NOT-EXISTS");
  }

  @Test(expected = SecurityException.class)
  public void verifyHasAnyRoleFailed() throws Exception {
    Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN");
    service.verifyHasAnyRole("NOT-EXISTS");
  }

  @Test
  public void hasAllRole() throws Exception {
    assertThat(service.hasAllRole("ADMIN"), is(false));
    assertThat(service.hasAllRole("ADMIN", "TEST"), is(false));
    Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN,TEST");
    assertThat(service.hasAllRole("NOT-EXISTS"), is(false));
    assertThat(service.hasAllRole("TEST", "NOT-EXISTS"), is(false));
    assertThat(service.hasAllRole("ADMIN"), is(true));
    assertThat(service.hasAllRole("TEST"), is(true));
    assertThat(service.hasAllRole("ADMIN", "TEST"), is(true));
  }

  @Test
  public void VerifyHasAllRole() throws Exception {
    Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN,TEST");
    service.verifyHasAllRole("ADMIN");
    service.verifyHasAllRole("TEST");
    service.verifyHasAllRole("ADMIN", "TEST");
  }

  @Test(expected = SecurityException.class)
  public void verifyHasAllRoleFailed1() throws Exception {
    Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN");
    service.verifyHasAllRole("NOT-EXISTS");
  }

  @Test(expected = SecurityException.class)
  public void verifyHasAllRoleFailed2() throws Exception {
    Context.set(SecurityService.CONTEXT_KEY_ROLES, "ADMIN,TEST");
    service.verifyHasAllRole("ADMIN", "NOT-EXISTS");
  }
}