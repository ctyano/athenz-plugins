package com.yahoo.athenz.common.server.cert.impl.vault;

import com.yahoo.athenz.common.server.cert.CertSigner;
import org.testng.annotations.Test;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class VaultCertSignerFactoryTest {

    @Test
    public void testCreate() {
        System.setProperty("athenz.zts.vault.base_uri", "https://vault.example.com:8200");
        System.setProperty("athenz.zts.vault.approle_role_id", "test-role-id");
        System.setProperty("athenz.zts.vault.approle_secret_id", "test-secret-id");

        VaultCertSignerFactory factory = new VaultCertSignerFactory();
        CertSigner signer = factory.create();
        assertNotNull(signer);
        assertTrue(signer instanceof VaultCertSigner);

        System.clearProperty("athenz.zts.vault.base_uri");
        System.clearProperty("athenz.zts.vault.approle_role_id");
        System.clearProperty("athenz.zts.vault.approle_secret_id");
    }
}
