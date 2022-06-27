const AWS = require('aws-sdk');
// strange way to support CommonJS in node-fetch https://github.com/node-fetch/node-fetch#commonjs

const Logger = require('./src/logger');
const getSecretsAndParams = require('./src/getSecretsAndParams');
const getEnvironment = require('./src/getEnvironment');
const getCPEsFromDB = require('./src/getCPEsFromDB');
const submitTaniumJobs = require('./src/submitTaniumJobs');
const { AWS_DEFAULT_REGION } = require('./src/const');

// Handler
async function handler(event, context = {}) {
  const region = process.env.AWS_REGION || AWS_DEFAULT_REGION; // provided by Lambda environment
  Logger.init({
    region,
    streamName: context.logStreamName,
    groupName: context.logGroupName
  });
  const now = new Date();
  Logger.log('Function start at ' + now.toUTCString());
  const env = await getEnvironment({ region });
  const secretsAndParams = await getSecretsAndParams({ region });
  if (secretsAndParams.err) {
    Logger.error(
      'Error during fetching Secrets' + JSON.stringify(secretsAndParams.err)
    );
    return context.logStreamName;
  }
  const dynamodb = new AWS.DynamoDB({
    region,
    maxRetries: 3,
    sslEnabled: true
  });
  const CPEsFromDB = await getCPEsFromDB({ dynamodb });

  const scheduledJobs = await submitTaniumJobs({
    CPEsFromDB,
    env,
    secretsAndParams
  });
  Logger.flushLogs();
  return {
    logstream: context.logStreamName,
    startedOn: new Date().toUTCString(),
    done: true,
    scheduledJobs: Object.values(scheduledJobs || {})
  };
}

handler.handler = handler;
module.exports = handler;
exports.handler = handler;
