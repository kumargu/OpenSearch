package org.opensearch.secure_sm.policy;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.FilePermission;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.SocketPermission;
import java.security.CodeSource;
import java.security.Permission;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class PolicyFileTests {
    private static File tempPolicyFile;

    @BeforeClass
    public static void setUp() throws IOException {
        tempPolicyFile = File.createTempFile("test-policy", ".policy");
        try (PrintWriter writer = new PrintWriter(new FileWriter(tempPolicyFile))) {
            writer.println("grant {");
            writer.println("  permission java.io.FilePermission \"/tmp/testfile\", \"read\";");
            writer.println("};");
        }

        File f = new File("/tmp/testfile");
        if (!f.exists()) {
            assertTrue(f.createNewFile());
            f.deleteOnExit(); // Clean up after test run
        }
    }

    @AfterClass
    public static void tearDown() {
        if (tempPolicyFile != null && tempPolicyFile.exists()) {
            assertTrue(tempPolicyFile.delete());
        }
    }

    @Test
    public void testPolicyFileInitialization() throws MalformedURLException {
        PolicyFile policyFile = new PolicyFile(tempPolicyFile.toURI().toURL());
        assertNotNull(policyFile);
    }

    @Test
    public void testPermissionGranted() throws Exception {
        PolicyFile policyFile = new PolicyFile(tempPolicyFile.toURI().toURL());

        CodeSource cs = new CodeSource(tempPolicyFile.toURI().toURL(), (Certificate[]) null);
        ProtectionDomain pd = new ProtectionDomain(cs, null);
        Permission perm = new FilePermission("/tmp/testfile", "read");

        assertTrue(policyFile.implies(pd, perm));
    }

    @Test
    public void testPermissionNotGrantedForOtherFilePath() throws Exception {
        PolicyFile policyFile = new PolicyFile(tempPolicyFile.toURI().toURL());

        CodeSource cs = new CodeSource(tempPolicyFile.toURI().toURL(), (Certificate[]) null);
        ProtectionDomain pd = new ProtectionDomain(cs, null);
        Permission perm = new FilePermission("/usr/data", "read");

        assertFalse(policyFile.implies(pd, perm));
    }

    @Test
    public void testRefreshReloadsPolicy() throws IOException {
        PolicyFile policyFile = new PolicyFile(tempPolicyFile.toURI().toURL());

        // Update the policy file to grant permission to a different file
        try (PrintWriter writer = new PrintWriter(new FileWriter(tempPolicyFile))) {
            writer.println("grant {");
            writer.println("  permission java.io.FilePermission \"/home/data\", \"read,write\";");
            writer.println("};");
        }

        policyFile.refresh();
        CodeSource cs = new CodeSource(tempPolicyFile.toURI().toURL(), (Certificate[]) null);
        ProtectionDomain pd = new ProtectionDomain(cs, null);
        Permission perm = new FilePermission("/home/data", "read,write");

        assertTrue(policyFile.implies(pd, perm));
    }

    @Test
    public void testSkippedPermissionClassSuccess() throws Exception {
        File skipPermPolicyFile = File.createTempFile("skipperm-policy", ".policy");
        try (PrintWriter writer = new PrintWriter(new FileWriter(skipPermPolicyFile))) {
            writer.println("grant {");
            writer.println("  permission org.opensearch.SpecialPermission \"skip.this\", \"execute\";");
            writer.println("};");
        }

        PolicyFile policyFile = new PolicyFile(skipPermPolicyFile.toURI().toURL());

        CodeSource cs = new CodeSource(skipPermPolicyFile.toURI().toURL(), (Certificate[]) null);
        ProtectionDomain pd = new ProtectionDomain(cs, null);
        Permission fakePermission = new RuntimePermission("skip.this", "execute");

        // Not granted, but also not failing due to skipped class
        assertFalse(policyFile.implies(pd, fakePermission));

        assertTrue(skipPermPolicyFile.delete());
    }

    @Test
    public void testPermissionWithPropertyExpansionSyntax() throws Exception {
        File propPolicyFile = File.createTempFile("prop-policy", ".policy");
        try (PrintWriter writer = new PrintWriter(new FileWriter(propPolicyFile))) {
            writer.println("grant {");
            writer.println("  permission java.net.SocketPermission \"${{hostname}}:443\", \"connect\";");
            writer.println("};");
        }

        PolicyFile policyFile = new PolicyFile(propPolicyFile.toURI().toURL());

        CodeSource cs = new CodeSource(propPolicyFile.toURI().toURL(), (Certificate[]) null);
        ProtectionDomain pd = new ProtectionDomain(cs, null);

        Permission perm = new SocketPermission("example.com:443", "connect");

        // Property placeholder should not match real hostname
        assertFalse(policyFile.implies(pd, perm));

        assertTrue(propPolicyFile.delete());
    }
}
