package com.criteo.gssclient;

import static org.junit.Assert.assertTrue;

import com.sun.security.auth.module.Krb5LoginModule;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.util.Strings;
import org.apache.directory.ldap.client.api.Krb5LoginConfiguration;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.SaslGssApiRequest;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.client.KrbConfigKey;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.security.authentication.jaas.memory.InMemoryConfiguration;
import org.springframework.security.kerberos.client.config.SunJaasKrb5LoginConfig;
import org.springframework.security.kerberos.client.ldap.KerberosLdapContextSource;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.RealmChoiceCallback;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;


public class AppTest {

    private static File ccache = Paths.get("D:/dbg/kerberos-docker-fork/gssapi-java/gss-client/config/ccache").toFile();

    static {
        if (!ccache.exists()) {
            try {
                ccache.createNewFile();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @BeforeClass
    public static void initProps() {
        /*
        -Dsun.security.krb5.debug=true
        -Djava.security.krb5.conf=D:/dbg/kerberos-docker-fork/gssapi-java/gss-client/config/krb5.conf
        -Djava.security.auth.login.config=D:/dbg/kerberos-docker-fork/gssapi-java/gss-client/config/consumer-jaas-krb5.conf
         */
//        System.setProperty("sun.security.krb5.debug", "true");
//        System.setProperty("java.security.auth.login.config", "D:/dbg/kerberos-docker-fork/gssapi-java/gss-client/config/consumer-jaas-krb5.conf");
        System.setProperty("java.security.krb5.conf", "D:/dbg/kerberos-docker-fork/gssapi-java/gss-client/config/krb5.conf");
    }

    @Test
    public void testApp() {
        assertTrue(true);
    }

    @Test
    public void apache() throws Exception {
//        GssLdapAction action = new GssLdapAction();
//        Jaas.loginAndAction("client", action);
//        System.out.println(test());

        SaslGssApiRequest saslGssApiRequest = new SaslGssApiRequest();
        Configuration configuration = Configuration.getConfiguration();
        saslGssApiRequest.setLoginModuleConfiguration(configuration);
        saslGssApiRequest.setLoginContextName("KerberosLdapContextSource");
        saslGssApiRequest.setMutualAuthentication(true);
        saslGssApiRequest.setRealmName("EXAMPLE.COM");
        saslGssApiRequest.setUsername("pmp");
        saslGssApiRequest.setCredentials("secret");
        saslGssApiRequest.setKdcHost("desktop-9vij310");
        saslGssApiRequest.setKdcPort(88);
        saslGssApiRequest.setKrb5ConfFilePath("D:/dbg/kerberos-docker-fork/gssapi-java/gss-client/config/krb5.conf");

        LdapNetworkConnection connection = new LdapNetworkConnection("desktop-9vij310", 10389, false);
//        connection.startTls();
        BindResponse br = connection.bind(saslGssApiRequest);
        System.out.println(br);

        EntryCursor cursor = connection.search("dc=security,dc=example,dc=com", "(objectclass=*)", SearchScope.SUBTREE);
        cursor.forEach(System.out::println);

        cursor.close();
        connection.unBind();
        connection.close();
    }

    @Test
    public void spring() throws Exception {
//        LdapContextSource contextSource = new LdapContextSource();
//        contextSource.setUrl("ldap://desktop-9vij310:10389");
//        contextSource.setBase("");
//        contextSource.afterPropertiesSet();

        KerberosLdapContextSource contextSource = new KerberosLdapContextSource("ldap://desktop-9vij310:10389");

//        Configuration configuration = Configuration.getConfiguration();
        Configuration configuration = createConfiguration("alice/admin", "");
        contextSource.setLoginConfig(configuration);

        contextSource.afterPropertiesSet();

        LdapTemplate ldapTemplate = new LdapTemplate(contextSource);
        ldapTemplate.search("dc=security,dc=example,dc=com", "objectclass=*", ctx -> {
            System.out.println(ctx);
        });
    }

    @Test
    public void thatTgtAndSgt_areObtained() throws KrbException, IOException {
        KrbConfig krb5Conf = new KrbConfig();
        krb5Conf.setString(KrbConfigKey.PERMITTED_ENCTYPES, "des3-cbc-sha1");
        krb5Conf.setString(KrbConfigKey.KDC_HOST, "desktop-9vij310");
        krb5Conf.setInt(KrbConfigKey.KDC_PORT, 88);
        krb5Conf.setBoolean(KrbConfigKey.KDC_ALLOW_TCP, true);
        krb5Conf.setBoolean(KrbConfigKey.KDC_ALLOW_UDP, true);
        krb5Conf.setString(KrbConfigKey.KDC_REALM, "EXAMPLE.COM");

//        krb5Conf.setString(KrbConfigKey.DEFAULT_REALM, "OTHER.COM");
        KrbClient client = new KrbClient(krb5Conf);
        client.init();

        TgtTicket tgt = client.requestTgt("alice/admin", "secret");
        SgtTicket sgt = client.requestSgt(tgt, "ldap/desktop-9vij310");
        client.storeTicket(tgt, ccache);
        client.storeTicket(sgt, ccache);

        System.out.printf("%s, %s, %s\n", tgt, sgt, Arrays.toString(Files.readAllBytes(ccache.toPath())));
    }

    public static Configuration createConfiguration(String principal, String pass) {
        Map<String, Object> options = new HashMap<>();
//        options.put("useKeyTab", String.valueOf(false));
        options.put("principal", principal);
//        options.put("password", pass.toCharArray());
        options.put("refreshKrb5Config", String.valueOf(true));
        options.put("debug", String.valueOf(true));
//        options.put("doNotPrompt", String.valueOf(true));
//        options.put("tryFirstPass", String.valueOf(true));
//        options.put("useFirstPass", String.valueOf(true));
//        options.put("callbackHandler", new CustomCallBackHandler());
        options.put("useTicketCache", String.valueOf(true));
        options.put("ticketCache", ccache.getAbsolutePath());

        AppConfigurationEntry[] entries = new AppConfigurationEntry[] {
                new AppConfigurationEntry(Krb5LoginModule.class.getName(), AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options)
        };

        return new InMemoryConfiguration(entries);
    }

    public static SunJaasKrb5LoginConfig createKrb5Config() throws Exception {
        SunJaasKrb5LoginConfig config = new SunJaasKrb5LoginConfig();
//        Configuration.Parameters params = config.getParameters();
        config.setDebug(true);
        config.setUseTicketCache(true);
        config.setIsInitiator(true);
        config.setServicePrincipal("pmp@EXAMPLE.COM");
        config.afterPropertiesSet();

        return config;
    }
}
class CustomCallBackHandler implements CallbackHandler {
    String name = "pmp@EXAMPLE.COM";
    String pass = "secret";
    String realm = "EXAMPLE.COM";
    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        for (Callback cb : callbacks) {
            if (cb instanceof NameCallback) {
                NameCallback ncb = (NameCallback) cb;
                ncb.setName(name);
            } else if (cb instanceof PasswordCallback) {
                PasswordCallback pcb = (PasswordCallback) cb;
                pcb.setPassword(Strings.utf8ToString(pass.getBytes()).toCharArray());
            } else if (cb instanceof RealmCallback) {
                RealmCallback rcb = (RealmCallback) cb;

                if (realm != null) {
                    rcb.setText(realm);
                } else {
                    rcb.setText(rcb.getDefaultText());
                }
            } else if (cb instanceof RealmChoiceCallback) {
                RealmChoiceCallback rccb = (RealmChoiceCallback) cb;

                boolean foundRealmName = false;

                String[] realmNames = rccb.getChoices();
                for (int i = 0; i < realmNames.length; i++) {
                    String realmName = realmNames[i];
                    if (realmName.equals(realm)) {
                        foundRealmName = true;
                        rccb.setSelectedIndex(i);
                        break;
                    }
                }

                if (!foundRealmName) {
                    throw new IOException(I18n.err(I18n.ERR_04171_CANNOT_PARSE_MATCHED_DN, realm, Arrays.stream(realmNames).collect(Collectors.joining(", "))));
                }
            }
        }

    }
}