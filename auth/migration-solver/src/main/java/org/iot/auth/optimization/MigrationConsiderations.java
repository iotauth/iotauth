package org.iot.auth.optimization;

public class MigrationConsiderations {
    private final boolean migrationTrust;
    private final boolean authCapacity;

    public MigrationConsiderations(boolean migrationTrust, boolean authCapacity) {
        this.migrationTrust = migrationTrust;
        this.authCapacity = authCapacity;
    }

    public boolean isMigrationTrustConsidered() {
        return migrationTrust;
    }

    public boolean isAuthCapacityConsidered() {
        return authCapacity;
    }
}
