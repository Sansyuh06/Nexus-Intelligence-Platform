package com.demo;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * AppLogger — demo class that invokes LogManager.getLogger().
 */
public class AppLogger {

    private static final Logger logger = LogManager.getLogger(AppLogger.class);

    public void log(String message) {
        // Direct usage triggers JndiLookup.lookup() in vulnerable versions
        logger.info("Processing: " + message);
    }

    public static void main(String[] args) {
        AppLogger appLogger = new AppLogger();
        appLogger.log("Hello, world!");
    }
}
