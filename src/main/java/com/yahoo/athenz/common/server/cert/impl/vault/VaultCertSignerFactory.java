package com.yahoo.athenz.common.server.cert.impl.vault;

import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.common.server.cert.CertSignerFactory;

public class VaultCertSignerFactory implements CertSignerFactory {

    @Override
    public CertSigner create() {
        return new VaultCertSigner();
    }
}
