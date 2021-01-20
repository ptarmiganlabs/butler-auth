/*eslint strict: ["error", "global"]*/
/*eslint no-invalid-this: "error"*/

'use strict';

const globals = require('./globals');
const _ = require('lodash');

function postButlerAuthMemoryUsageToInfluxdb(memory) {
    let datapoint = [
        {
            measurement: 'butlerauth_memory_usage',
            tags: {
                butlerauth_instance: memory.instanceTag,
            },
            fields: {
                heap_used: memory.heapUsed,
                heap_total: memory.heapTotal,
                external: memory.external,
                process_memory: memory.processMemory,
            },
        },
    ];
    const deepClonedDatapoint = _.cloneDeep(datapoint);

    globals.influx
        .writePoints(deepClonedDatapoint)

        .then(() => {
            globals.logger.silly(
                `MEMORY USAGE: Influxdb datapoint for Butler Auth memory usage: ${JSON.stringify(datapoint, null, 2)}`,
            );

            datapoint = null;
            globals.logger.verbose('MEMORY USAGE: Sent Butler Auth memory usage data to InfluxDB');
        })
        .catch(err => {
            globals.logger.error(`MEMORY USAGE: Error saving user session data to InfluxDB! ${err.stack}`);
        });
}

module.exports = {
    postButlerAuthMemoryUsageToInfluxdb,
};
