var config = require('config');

const winston = require('winston');
require('winston-daily-rotate-file');
const path = require('path');
const Influx = require('influx');

// Get app version from package.json file
var appVersion = require('../package.json').version;

// Set up logger with timestamps and colors, and optional logging to disk file
const logTransports = [];

logTransports.push(
    new winston.transports.Console({
        name: 'console',
        level: config.get('ButlerAuth.logLevel'),
        format: winston.format.combine(
            winston.format.timestamp(),
            winston.format.colorize(),
            winston.format.simple(),
            winston.format.printf(info => `${info.timestamp} ${info.level}: ${info.message}`),
        ),
    }),
);

if (config.get('ButlerAuth.fileLogging')) {
    logTransports.push(
        new winston.transports.DailyRotateFile({
            dirname: path.join(__dirname, config.get('ButlerAuth.logDirectory')),
            filename: 'ButlerAuth.%DATE%.log',
            level: config.get('ButlerAuth.logLevel'),
            datePattern: 'YYYY-MM-DD',
            maxFiles: '30d',
        }),
    );
}

var logger = winston.createLogger({
    transports: logTransports,
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(info => `${info.timestamp} ${info.level}: ${info.message}`),
    ),
});

// Function to get current logging level
const getLoggingLevel = () => {
    return logTransports.find(transport => {
        return transport.name == 'console';
    }).level;
};

logger.info(`CONFIG: Influxdb enabled: ${config.get('ButlerAuth.uptimeMonitor.storeInInfluxdb.enable')}`);
logger.info(`CONFIG: Influxdb host IP: ${config.get('ButlerAuth.uptimeMonitor.storeInInfluxdb.hostIP')}`);
logger.info(`CONFIG: Influxdb host port: ${config.get('ButlerAuth.uptimeMonitor.storeInInfluxdb.hostPort')}`);
logger.info(`CONFIG: Influxdb db name: ${config.get('ButlerAuth.uptimeMonitor.storeInInfluxdb.dbName')}`);

// Set up Influxdb client
const influx = new Influx.InfluxDB({
    host: config.get('ButlerAuth.uptimeMonitor.storeInInfluxdb.hostIP'),
    port: `${
        config.has('ButlerAuth.uptimeMonitor.storeInInfluxdb.hostPort')
            ? config.get('ButlerAuth.uptimeMonitor.storeInInfluxdb.hostPort')
            : '8086'
    }`,
    database: config.get('ButlerAuth.uptimeMonitor.storeInInfluxdb.dbName'),
    username: `${
        config.get('ButlerAuth.uptimeMonitor.storeInInfluxdb.auth.enable')
            ? config.get('ButlerAuth.uptimeMonitor.storeInInfluxdb.auth.username')
            : ''
    }`,
    password: `${
        config.get('ButlerAuth.uptimeMonitor.storeInInfluxdb.auth.enable')
            ? config.get('ButlerAuth.uptimeMonitor.storeInInfluxdb.auth.password')
            : ''
    }`,
    schema: [
        {
            measurement: 'butlerauth_memory_usage',
            fields: {
                heap_used: Influx.FieldType.FLOAT,
                heap_total: Influx.FieldType.FLOAT,
                external: Influx.FieldType.FLOAT,
                process_memory: Influx.FieldType.FLOAT,
            },
            tags: ['butlerauth_instance'],
        },
    ],
});

function initInfluxDB() {
    const dbName = config.get('ButlerAuth.uptimeMonitor.storeInInfluxdb.dbName');
    const enableInfluxdb = config.get('ButlerAuth.uptimeMonitor.storeInInfluxdb.enable');

    if (enableInfluxdb) {
        influx
            .getDatabaseNames()
            .then(names => {
                if (!names.includes(dbName)) {
                    influx
                        .createDatabase(dbName)
                        .then(() => {
                            logger.info(`CONFIG: Created new InfluxDB database: ${dbName}`);

                            const newPolicy = config.get('ButlerAuth.uptimeMonitor.storeInInfluxdb.retentionPolicy');

                            // Create new default retention policy
                            influx
                                .createRetentionPolicy(newPolicy.name, {
                                    database: dbName,
                                    duration: newPolicy.duration,
                                    replication: 1,
                                    isDefault: true,
                                })
                                .then(() => {
                                    logger.info(`CONFIG: Created new InfluxDB retention policy: ${newPolicy.name}`);
                                })
                                .catch(err => {
                                    logger.error(
                                        `CONFIG: Error creating new InfluxDB retention policy "${newPolicy.name}"! ${err.stack}`,
                                    );
                                });
                        })
                        .catch(err => {
                            logger.error(`CONFIG: Error creating new InfluxDB database "${dbName}"! ${err.stack}`);
                        });
                } else {
                    logger.info(`CONFIG: Found InfluxDB database: ${dbName}`);
                }
            })
            .catch(err => {
                logger.error(`CONFIG: Error getting list of InfuxDB databases! ${err.stack}`);
            });
    }
}

module.exports = {
    config,
    logger,
    getLoggingLevel,
    appVersion,
    initInfluxDB,
    influx,
};
