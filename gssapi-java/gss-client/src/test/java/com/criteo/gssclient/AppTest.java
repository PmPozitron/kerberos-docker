package com.criteo.gssclient;

import static org.junit.Assert.assertTrue;

import org.apache.directory.ldap.client.api.Krb5LoginConfiguration;
import org.junit.Test;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.security.kerberos.client.ldap.KerberosLdapContextSource;

import javax.security.auth.login.Configuration;


public class AppTest {

  @Test
  public void testApp() {
    assertTrue(true);
  }

  @Test
  public void springLdapTemplateTestDrive() {

    LdapTemplate template = new LdapTemplate();
  }

  @Test
  public void createContextSource() {
    KerberosLdapContextSource contextSource = new KerberosLdapContextSource("ldap://desktop-9vij310:10389/dc=security,dc=example,dc=com");
    contextSource.setLoginConfig(createConfiguration());

    System.out.println(contextSource);

  }

  public Krb5LoginConfiguration createConfiguration() {
    Krb5LoginConfiguration result = new Krb5LoginConfiguration();

    return result;
  }


}