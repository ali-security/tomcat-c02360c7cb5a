/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.realm;

import java.security.Principal;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.LifecycleException;
import org.apache.juli.logging.LogFactory;

public class TestJDBCRealm {

    protected static class TesterJDBCRealm extends JDBCRealm {
        public TesterJDBCRealm() {
            setDriverName(TesterRealmDatabase.TesterDriver.class.getName());
            setConnectionURL("jdbc:tester");
        }
        @Override
        protected void initInternal() throws LifecycleException {
            // Avoid heavy lifecycle and JMX, however container log is needed
            containerLog = LogFactory.getLog(TestJDBCRealm.class);
            // Needed for CLIENT-CERT authentication
            x509UsernameRetriever = new X509SubjectDnRetriever();
        }
    }

    private TesterJDBCRealm realm;

    @After
    public void tearDown() throws Exception {
        if (realm != null) {
            realm.stop();
        }
        TesterRealmDatabase.setDriverDatabase(null);
    }

    private TesterRealmDatabase createDatabase() {
        TesterRealmDatabase database = new TesterRealmDatabase();
        database.addUser("tomcat", "password");
        database.addUser("random", "password");
        database.addUser("CN=tomcat", "password");
        database.addUserRole("tomcat", "admin");
        database.addUserRole("tomcat", "foo");
        TesterRealmDatabase.setDriverDatabase(database);
        return database;
    }

    private void createRealm(boolean roleStore) throws Exception {
        realm = new TesterJDBCRealm();
        realm.setUserTable("users");
        realm.setUserNameCol("user_name");
        realm.setUserCredCol("user_pass");
        if (roleStore) {
            realm.setUserRoleTable("user_roles");
            realm.setRoleNameCol("role_name");
        }
    }

    @Test
    public void testRealm() throws Exception {
        createDatabase();
        createRealm(true);
        realm.start();

        Assert.assertNull(realm.authenticate("tomcat", "bar"));
        Assert.assertNull(realm.authenticate("blabla", "bar"));

        Principal p = realm.authenticate("tomcat", "password");
        Assert.assertTrue(p instanceof GenericPrincipal);
        GenericPrincipal gp = (GenericPrincipal) p;
        Assert.assertTrue(gp.hasRole("foo"));
        Assert.assertTrue(gp.hasRole("admin"));
        Assert.assertFalse(gp.hasRole("manager"));

        p = realm.getPrincipal("tomcat");
        Assert.assertTrue(p instanceof GenericPrincipal);
        gp = (GenericPrincipal) p;
        Assert.assertEquals("password", gp.getPassword());
        Assert.assertTrue(gp.hasRole("foo"));
        Assert.assertTrue(gp.hasRole("admin"));
        Assert.assertFalse(gp.hasRole("manager"));

        // A user that does not exist must not be found
        Assert.assertNull(realm.getPrincipal("blabla"));

        p = realm.getPrincipal("random");
        Assert.assertTrue(p instanceof GenericPrincipal);
        gp = (GenericPrincipal) p;
        Assert.assertEquals(0, gp.getRoles().length);
    }

    @Test
    public void testUnknownUserNotAuthenticated() throws Exception {
        createDatabase();
        createRealm(true);
        realm.start();

        // Authentication mechanisms where the credentials are validated
        // outside of the Realm (CLIENT-CERT, SPNEGO, ...) only ask the Realm
        // for the Principal. A user that does not exist must not be
        // authenticated.
        Assert.assertNull(realm.authenticate("blabla"));
        Assert.assertNull(realm.authenticate(TestDataSourceRealm.createCertificateChain("CN=blabla")));
        Assert.assertNull(realm.authenticate(TestDataSourceRealm.createGssName("blabla@EXAMPLE.COM"), null));

        // Users that do exist are still found
        Principal p = realm.authenticate("tomcat");
        Assert.assertTrue(p instanceof GenericPrincipal);
        Assert.assertTrue(((GenericPrincipal) p).hasRole("admin"));

        p = realm.authenticate(TestDataSourceRealm.createCertificateChain("CN=tomcat"));
        Assert.assertTrue(p instanceof GenericPrincipal);
        Assert.assertEquals("CN=tomcat", p.getName());

        p = realm.authenticate(TestDataSourceRealm.createGssName("tomcat@EXAMPLE.COM"), null);
        Assert.assertTrue(p instanceof GenericPrincipal);
        Assert.assertEquals("tomcat", p.getName());
        Assert.assertTrue(((GenericPrincipal) p).hasRole("foo"));
    }

    @Test
    public void testRoleLookupFailure() throws Exception {
        TesterRealmDatabase database = createDatabase();
        createRealm(true);
        realm.start();

        database.setFailRoleQueries(true);

        // A failed role lookup must fail authentication rather than return a
        // Principal without roles
        Assert.assertNull(realm.getRoles("tomcat"));
        Assert.assertNull(realm.authenticate("tomcat", "password"));
        Assert.assertNull(realm.getPrincipal("tomcat"));
        Assert.assertNull(realm.authenticate("tomcat"));
        Assert.assertNull(realm.authenticate(TestDataSourceRealm.createGssName("tomcat@EXAMPLE.COM"), null));

        database.setFailRoleQueries(false);

        Assert.assertNotNull(realm.authenticate("tomcat", "password"));
        Assert.assertNotNull(realm.getPrincipal("tomcat"));
    }

    @Test
    public void testAuthOnlyWithoutRoleStore() throws Exception {
        createDatabase();
        createRealm(false);
        realm.setAllRolesMode("authOnly");
        realm.start();

        Assert.assertNull(realm.authenticate("tomcat", "bar"));

        Principal p = realm.authenticate("tomcat", "password");
        Assert.assertTrue(p instanceof GenericPrincipal);
        Assert.assertEquals(0, ((GenericPrincipal) p).getRoles().length);

        p = realm.getPrincipal("tomcat");
        Assert.assertTrue(p instanceof GenericPrincipal);
        Assert.assertEquals(0, ((GenericPrincipal) p).getRoles().length);

        Assert.assertNull(realm.getPrincipal("blabla"));
    }

    @Test
    public void testStrictWithoutRoleStore() throws Exception {
        createDatabase();
        createRealm(false);
        realm.start();

        // Default strict mode with no role store. Authentication of a valid
        // user must succeed with an empty role list rather than fail.
        Assert.assertNull(realm.authenticate("tomcat", "bar"));

        Principal p = realm.authenticate("tomcat", "password");
        Assert.assertTrue(p instanceof GenericPrincipal);
        Assert.assertEquals(0, ((GenericPrincipal) p).getRoles().length);

        p = realm.getPrincipal("tomcat");
        Assert.assertTrue(p instanceof GenericPrincipal);
        Assert.assertEquals(0, ((GenericPrincipal) p).getRoles().length);

        Assert.assertNull(realm.getPrincipal("blabla"));
    }

    @Test
    public void testDatabaseUnavailable() throws Exception {
        // No database is registered with the driver so every attempt to
        // connect fails
        createRealm(true);
        realm.start();

        // No Principal may be returned if the database cannot be reached
        Assert.assertNull(realm.authenticate("tomcat", "password"));
        Assert.assertNull(realm.getPrincipal("tomcat"));
        Assert.assertNull(realm.authenticate("tomcat"));
        Assert.assertNull(realm.authenticate(TestDataSourceRealm.createCertificateChain("CN=tomcat")));
        Assert.assertNull(realm.authenticate(TestDataSourceRealm.createGssName("tomcat@EXAMPLE.COM"), null));
    }
}
