package com.criteo.gssclient;

import com.criteo.gssutils.Jaas;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.SaslGssApiRequest;

import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.PrivilegedActionException;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;

public class LdapClient {

    public static void main(String[] args) throws NamingException, PrivilegedActionException, LoginException, LdapException, IOException {
//        GssLdapAction action = new GssLdapAction();
//        Jaas.loginAndAction("client", action);

//        System.out.println(test());

        SaslGssApiRequest saslGssApiRequest = new SaslGssApiRequest();
        saslGssApiRequest.setLoginModuleConfiguration(Configuration.getConfiguration());
        saslGssApiRequest.setLoginContextName( "client");
//        saslGssApiRequest.setMutualAuthentication( true );
        saslGssApiRequest.setRealmName("EXAMPLE.COM");
//        saslGssApiRequest.setUsername("pmp");
//        saslGssApiRequest.setCredentials("secret");
        saslGssApiRequest.setKdcHost("desktop-9vij310");
        saslGssApiRequest.setKdcPort(88);
        saslGssApiRequest.setKrb5ConfFilePath("D:/dbg/kerberos-docker-fork/gssapi-java/gss-client/config/krb5.conf");
        LdapConnectionConfig config = new LdapConnectionConfig();


        LdapNetworkConnection ldapNetworkConnection = new LdapNetworkConnection("desktop-9vij310", 10389, false);

        BindResponse br = ldapNetworkConnection.bind( saslGssApiRequest );
        System.out.println(br);

        EntryCursor cursor = ldapNetworkConnection.search( "ou=system", "(objectclass=*)", SearchScope.ONELEVEL );

        try
        {
            for ( Entry entry : cursor )
            {
                assert( entry != null );
                System.out.println( entry );
            }
        }
        finally
        {
            cursor.close();
        }

        ldapNetworkConnection.unBind();
        ldapNetworkConnection.close();


    }

    private static List test() throws NamingException {
        Hashtable env = new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:1389/dc=example,dc=org");
        env.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");

        // Create initial context
        DirContext ctx = new InitialDirContext();
        // Read supportedSASLMechanisms from root DSE
        Attributes attrs = ctx.getAttributes("ldap://localhost:10389", new String[]{"supportedSASLMechanisms"});
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
