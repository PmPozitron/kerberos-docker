package com.criteo.gssclient;

import com.google.common.base.MoreObjects;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.util.Strings;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.SaslGssApiRequest;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.Krb5Conf;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.client.KrbConfigKey;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.security.kerberos.client.config.SunJaasKrb5LoginConfig;
import org.springframework.security.kerberos.client.ldap.KerberosLdapContextSource;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class LdapClient {

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

    public static void main(String[] args) throws Exception {
//        apache();
        spring();
//        thatTgtAndSgt_areObtained();
    }

    /*
    D:/dbg/kerberos-docker-fork/gssapi-java/gss-client/src/main/java/com/criteo/gssclient/krb5-local.conf
     */
    private static void apache() throws Exception {
        //        GssLdapAction action = new GssLdapAction();
//        Jaas.loginAndAction("client", action);

//        System.out.println(test());

        SaslGssApiRequest saslGssApiRequest = new SaslGssApiRequest();
        Configuration configuration = Configuration.getConfiguration();
        saslGssApiRequest.setLoginModuleConfiguration(configuration);
        saslGssApiRequest.setLoginContextName("client");
        saslGssApiRequest.setMutualAuthentication(true);
        saslGssApiRequest.setRealmName("EXAMPLE.COM");
        saslGssApiRequest.setUsername("pmp");
        saslGssApiRequest.setCredentials("secret");
        saslGssApiRequest.setKdcHost("desktop-9vij310");
        saslGssApiRequest.setKdcPort(88);
        saslGssApiRequest.setKrb5ConfFilePath("D:/dbg/kerberos-docker-fork/gssapi-java/gss-client/config/krb5.conf");
        LdapConnectionConfig config = new LdapConnectionConfig();


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

    private static void spring() throws Exception {
//        LdapContextSource contextSource = new LdapContextSource();
//        contextSource.setUrl("ldap://desktop-9vij310:10389");
//        contextSource.setBase("");
//        contextSource.afterPropertiesSet();

        KerberosLdapContextSource contextSource = new KerberosLdapContextSource("ldap://desktop-9vij310:10389");
        SunJaasKrb5LoginConfig config = new SunJaasKrb5LoginConfig();
//        Configuration.Parameters params = config.getParameters();
        config.setDebug(true);
        config.setUseTicketCache(true);
        config.setIsInitiator(true);
        config.setServicePrincipal("pmp@EXAMPLE.COM");
        config.afterPropertiesSet();

//        Configuration configuration = Configuration.getConfiguration();
//        ((ConfigFile)configuration).refresh();
        contextSource.setLoginConfig(Configuration.getConfiguration());

        contextSource.afterPropertiesSet();

        LdapTemplate ldapTemplate = new LdapTemplate(contextSource);
        ldapTemplate.search("dc=security,dc=example,dc=com", "objectclass=*", ctx -> {
            System.out.println(ctx);
        });
    }

    private static void thatTgtAndSgt_areObtained() throws KrbException, IOException {
        KrbConfig krb5Conf = new KrbConfig();
        krb5Conf.setString(KrbConfigKey.PERMITTED_ENCTYPES, "des3-cbc-sha1");
        KrbClient client = new KrbClient(krb5Conf);
        client.init();

        TgtTicket tgt = client.requestTgt("pmp", "secret");
        SgtTicket sgt = client.requestSgt(tgt, "ldap/desktop-9vij310");
        client.storeTicket(tgt, ccache);
        client.storeTicket(sgt, ccache);

        System.out.printf("%s, %s, %s\n", tgt, sgt, Arrays.toString(Files.readAllBytes(ccache.toPath())));

    }


    private static List test() throws NamingException {
        Hashtable env = new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://desktop-9vij310:10389/dc=example,dc=com");
        env.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");
        env.put(Context.SECURITY_PRINCIPAL, "pmp@EXAMPLE.COM");

        // Create initial context
        DirContext ctx = new InitialDirContext();
        // Read supportedSASLMechanisms from root DSE
        Attributes attrs = ctx.getAttributes("ldap://desktop-9vij310:10389", new String[]{"supportedSASLMechanisms"});
        System.out.println(attrs);

        ctx = new InitialDirContext(env);
        List<String> list = new LinkedList<>();
        NamingEnumeration results;
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        results = ctx.search("", "(objectclass=person)", controls);
        // results = ctx.search("", "(objectclass=organizationalUnit)", controls);

        while (results.hasMore()) {
            SearchResult searchResult = (SearchResult) results.next();
            Attributes attributes = searchResult.getAttributes();
            Attribute attr = attributes.get("cn");
            String cn = attr.get().toString();
            list.add(cn);
        }
        System.out.println(list);
        return list;

    }
}

class CustomLoginConfiguration extends Configuration {

    /**
     * The list with configuration entries.
     */
    private static AppConfigurationEntry[] configList = new AppConfigurationEntry[1];


    /**
     * Creates a new instance of Krb5LoginConfiguration.
     */
    public CustomLoginConfiguration() {
        String loginModule = "com.sun.security.auth.module.Krb5LoginModule";

        HashMap<String, Object> options = new HashMap<>();
        // TODO: this only works for Sun JVM
        options.put("debug", "true");
        options.put("refreshKrb5Config", "true");
        options.put("principal", "pmp@EXAMPLE.COM");
        options.put("password", "secret".toCharArray());
//        options.put( "useKeyTab", "true" );
//        options.put( "keyTab", "D:/dbg/kerberos-docker-fork/gssapi-java/gss-client/config/pmp.keytab" );
        options.put("storeKey", "false");
//        options.put("callbackHandler", new CustomCallBackHandler());

//        options.put("krb5ConfFilePath", "D:/dbg/kerberos-docker-fork/gssapi-java/gss-client/config/krb5.conf");

        AppConfigurationEntry.LoginModuleControlFlag flag = AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;
        configList[0] = new AppConfigurationEntry(loginModule, flag, options);
    }


    /**
     * Interface method requiring us to return all the LoginModules we know about.
     *
     * @param applicationName the application name
     * @return the configuration entry
     */
    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String applicationName) {
        // We will ignore the applicationName, since we want all apps to use Kerberos V5
        return configList;
    }


    /**
     * Interface method for reloading the configuration.  We don't need this.
     */
    @Override
    public void refresh() {
        // Right now this is a load once scheme and we will not implement the refresh method
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .toString();
    }
}
