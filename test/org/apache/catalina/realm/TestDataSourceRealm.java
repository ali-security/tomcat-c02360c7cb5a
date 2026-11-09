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

import java.lang.reflect.Proxy;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.startup.LoggingBaseTest;
import org.apache.tomcat.util.compat.JreCompat;
import org.easymock.EasyMock;
import org.ietf.jgss.GSSName;

public class TestDataSourceRealm extends LoggingBaseTest {

    public static final String SIMPLE_SCHEMA =
            "create table users (\n"
            + "  user_name         varchar(15) not null primary key,\n"
            + "  user_pass         varchar(15) not null\n"
            + ");\n"
            + "create table user_roles (\n"
            + "  user_name         varchar(15) not null,\n"
            + "  role_name         varchar(15) not null,\n"
            + "  primary key (user_name, role_name)\n"
            + ");";
    public static final String USERS_INSERT = "INSERT INTO users(user_name, user_pass) VALUES(?, ?)";
    public static final String ROLES_INSERT = "INSERT INTO user_roles(user_name, role_name) VALUES(?, ?)";

    protected class DerbyDataSourceRealm extends DataSourceRealm {
        protected final String name;
        protected Connection connection = null;
        protected volatile boolean available = true;
        public DerbyDataSourceRealm(String name) {
            this.name = "/" + name;
        }
        @Override
        protected Connection open() {
            // Simulate a DataSource that cannot provide a connection
            if (!available) {
                return null;
            }
            // Replace DataSource use and JNDI access with direct Derby
            // connection
            if (connection == null) {
                try {
                    Class.forName("org.apache.derby.jdbc.EmbeddedDriver");
                    connection = DriverManager.getConnection("jdbc:derby:" + getTemporaryDirectory().getAbsolutePath()
                            + name + ";create=true");
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            }
            return connection;
        }
        @Override
        protected void close(Connection dbConnection) {
            // Only one connection so don't close it here
        }
        @Override
        public void initInternal() throws LifecycleException {
            // Avoid heavy lifecycle and JMX, however container log is needed
            containerLog = log;
            // Needed for CLIENT-CERT authentication
            x509UsernameRetriever = new X509SubjectDnRetriever();
        }
        @Override
        public void stopInternal() throws LifecycleException {
            super.stopInternal();
            if (connection != null) {
                super.close(connection);
            }
        }
    }

    private DerbyDataSourceRealm db;

    @Test
    public void testRealm() throws Exception {

        Assume.assumeTrue(JreCompat.isJre16Available());

        db = new DerbyDataSourceRealm("dsRealm");
        db.setUserTable("users");
        db.setUserNameCol("user_name");
        db.setUserCredCol("user_pass");
        db.setUserRoleTable("user_roles");
        db.setRoleNameCol("role_name");

        // First create the users and roles tables
        Connection connection = db.open();
        for (String sql: SIMPLE_SCHEMA.split(";")) {
            try (Statement statement = connection.createStatement()) {
                statement.execute(sql);
            }
        }

        try (PreparedStatement stmt = connection.prepareStatement(USERS_INSERT)) {
            stmt.setString(1, "tomcat");
            stmt.setString(2, "password");
            stmt.executeUpdate();
            stmt.setString(1, "random");
            stmt.setString(2, "password");
            stmt.executeUpdate();
        }
        try (PreparedStatement stmt = connection.prepareStatement(ROLES_INSERT)) {
            stmt.setString(1, "tomcat");
            stmt.setString(2, "admin");
            stmt.executeUpdate();
            stmt.setString(1, "tomcat");
            stmt.setString(2, "foo");
            stmt.executeUpdate();
        }

        db.start();

        Principal p = db.authenticate("tomcat", "bar");
        Assert.assertNull(p);

        p = db.authenticate("blabla", "bar");
        Assert.assertNull(p);

        p = db.authenticate("tomcat", "password");
        Assert.assertTrue(p instanceof GenericPrincipal);
        GenericPrincipal gp = (GenericPrincipal) p;
        Assert.assertTrue(gp.hasRole("foo"));
        Assert.assertTrue(gp.hasRole("admin"));
        Assert.assertFalse(gp.hasRole("manager"));

        p = db.getPrincipal("tomcat");
        Assert.assertTrue(p instanceof GenericPrincipal);
        gp = (GenericPrincipal) p;
        Assert.assertTrue(gp.hasRole("foo"));
        Assert.assertTrue(gp.hasRole("admin"));
        Assert.assertFalse(gp.hasRole("manager"));

        String pass = db.getPassword("tomcat");
        Assert.assertEquals("password", pass);

        List<String> roles = db.getRoles("tomcat");
        Assert.assertEquals(2, roles.size());

        // A user that does not exist in the database must not be found
        p = db.getPrincipal("blabla");
        Assert.assertNull(p);

        p = db.getPrincipal("random");
        Assert.assertTrue(p instanceof GenericPrincipal);
        gp = (GenericPrincipal) p;
        Assert.assertEquals(0, gp.getRoles().length);

        db.stop();

    }


    @Test
    public void testRealmWithoutRoleStore() throws Exception {

        Assume.assumeTrue(JreCompat.isJre16Available());

        db = createRealm("dsRealmNoRoles", false);

        db.start();

        // Default strict mode with no role store. Authentication of a valid
        // user must succeed with an empty role list rather than fail.
        Principal p = db.authenticate("tomcat", "bar");
        Assert.assertNull(p);

        p = db.authenticate("tomcat", "password");
        Assert.assertTrue(p instanceof GenericPrincipal);
        GenericPrincipal gp = (GenericPrincipal) p;
        Assert.assertEquals(0, gp.getRoles().length);

        p = db.getPrincipal("tomcat");
        Assert.assertTrue(p instanceof GenericPrincipal);
        gp = (GenericPrincipal) p;
        Assert.assertEquals(0, gp.getRoles().length);

        p = db.getPrincipal("blabla");
        Assert.assertNull(p);

        List<String> roles = db.getRoles("tomcat");
        Assert.assertNotNull(roles);
        Assert.assertEquals(0, roles.size());

        db.stop();
    }


    @Test
    public void testUnknownUserNotAuthenticated() throws Exception {

        Assume.assumeTrue(JreCompat.isJre16Available());

        db = createRealm("dsRealmUnknownUser", true);

        db.start();

        // Authentication mechanisms where the credentials are validated
        // outside of the Realm (CLIENT-CERT, SPNEGO, ...) only ask the Realm
        // for the Principal. A user that does not exist must not be
        // authenticated.
        Assert.assertNull(db.authenticate("blabla"));
        Assert.assertNull(db.authenticate(createCertificateChain("CN=blabla")));
        Assert.assertNull(db.authenticate(createGssName("blabla@EXAMPLE.COM"), null));

        // Users that do exist are still found
        Principal p = db.authenticate("tomcat");
        Assert.assertTrue(p instanceof GenericPrincipal);
        Assert.assertTrue(((GenericPrincipal) p).hasRole("admin"));

        p = db.authenticate(createCertificateChain("CN=tomcat"));
        Assert.assertTrue(p instanceof GenericPrincipal);
        Assert.assertEquals("CN=tomcat", p.getName());

        p = db.authenticate(createGssName("tomcat@EXAMPLE.COM"), null);
        Assert.assertTrue(p instanceof GenericPrincipal);
        Assert.assertEquals("tomcat", p.getName());
        Assert.assertTrue(((GenericPrincipal) p).hasRole("foo"));

        db.stop();
    }


    @Test
    public void testRoleLookupFailure() throws Exception {

        Assume.assumeTrue(JreCompat.isJre16Available());

        db = createRealm("dsRealmRoleFailure", true);

        db.start();

        Assert.assertNotNull(db.authenticate("tomcat", "password"));
        Assert.assertNotNull(db.getPrincipal("tomcat"));

        // Make the role lookup fail
        try (Statement statement = db.open().createStatement()) {
            statement.execute("drop table user_roles");
        }

        // A failed role lookup must fail authentication rather than return a
        // Principal without roles
        Assert.assertNull(db.getRoles("tomcat"));
        Assert.assertNull(db.authenticate("tomcat", "password"));
        Assert.assertNull(db.getPrincipal("tomcat"));
        Assert.assertNull(db.authenticate("tomcat"));
        Assert.assertNull(db.authenticate(createGssName("tomcat@EXAMPLE.COM"), null));

        db.stop();
    }


    @Test
    public void testDatabaseUnavailable() throws Exception {

        Assume.assumeTrue(JreCompat.isJre16Available());

        db = createRealm("dsRealmUnavailable", true);

        db.start();

        db.available = false;

        // No Principal may be returned if the database cannot be reached
        Assert.assertNull(db.authenticate("tomcat", "password"));
        Assert.assertNull(db.getPrincipal("tomcat"));
        Assert.assertNull(db.authenticate("tomcat"));
        Assert.assertNull(db.authenticate(createCertificateChain("CN=tomcat")));
        Assert.assertNull(db.authenticate(createGssName("tomcat@EXAMPLE.COM"), null));

        db.available = true;

        Assert.assertNotNull(db.authenticate("tomcat", "password"));
        Assert.assertNotNull(db.getPrincipal("tomcat"));

        db.stop();
    }


    private DerbyDataSourceRealm createRealm(String name, boolean roleStore) throws Exception {
        DerbyDataSourceRealm realm = new DerbyDataSourceRealm(name);
        realm.setUserTable("users");
        realm.setUserNameCol("user_name");
        realm.setUserCredCol("user_pass");
        if (roleStore) {
            realm.setUserRoleTable("user_roles");
            realm.setRoleNameCol("role_name");
        }

        // Create the users table and, if required, the roles table
        Connection connection = realm.open();
        for (String sql : SIMPLE_SCHEMA.split(";")) {
            if (!roleStore && sql.contains("user_roles")) {
                continue;
            }
            try (Statement statement = connection.createStatement()) {
                statement.execute(sql);
            }
        }

        try (PreparedStatement stmt = connection.prepareStatement(USERS_INSERT)) {
            stmt.setString(1, "tomcat");
            stmt.setString(2, "password");
            stmt.executeUpdate();
            stmt.setString(1, "random");
            stmt.setString(2, "password");
            stmt.executeUpdate();
            stmt.setString(1, "CN=tomcat");
            stmt.setString(2, "password");
            stmt.executeUpdate();
        }
        if (roleStore) {
            try (PreparedStatement stmt = connection.prepareStatement(ROLES_INSERT)) {
                stmt.setString(1, "tomcat");
                stmt.setString(2, "admin");
                stmt.executeUpdate();
                stmt.setString(1, "tomcat");
                stmt.setString(2, "foo");
                stmt.executeUpdate();
            }
        }
        return realm;
    }


    static X509Certificate[] createCertificateChain(String subject) {
        X509Certificate cert = EasyMock.createNiceMock(X509Certificate.class);
        EasyMock.expect(cert.getSubjectX500Principal()).andStubReturn(new X500Principal(subject));
        EasyMock.replay(cert);
        return new X509Certificate[] { cert };
    }


    static GSSName createGssName(final String name) {
        return (GSSName) Proxy.newProxyInstance(TestDataSourceRealm.class.getClassLoader(),
                new Class<?>[] { GSSName.class }, (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "toString":
                            return name;
                        case "hashCode":
                            return Integer.valueOf(System.identityHashCode(proxy));
                        case "equals":
                            return Boolean.valueOf(proxy == args[0]);
                        default:
                            throw new UnsupportedOperationException(method.getName());
                    }
                });
    }
}
