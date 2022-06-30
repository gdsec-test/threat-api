const Logger = require('./src/logger');
const getSecretsAndParams = require('./src/getSecretsAndParams');
const getEnvironment = require('./src/getEnvironment');
const getTaniumJobsResults = require('./src/getTaniumJobsResults');
const notifyCPEResultsViaSlackChannels = require('./src/notifyCPEResultsViaSlackChannels');
const extractCPEData = require('./src/extractCPEData');
const { AWS_DEFAULT_REGION } = require('./src/const');

// Handler
async function handler(event = {}, context = {}) {
  const { scheduledJobs } = event;
  if (!scheduledJobs) {
    Logger.error('Error, no scheduled jobs provided:' + JSON.stringify(event));
    return context.logStreamName;
  }
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
  const { stillNotReadyJobs, jobsResults } = await getTaniumJobsResults({
    scheduledJobs,
    env,
    secretsAndParams
  });
  let allJobsDone = stillNotReadyJobs && stillNotReadyJobs.length ? false : true; // if no more jobs to we stop working
  let { retryFetchResults = 0 } = event;
  if (!allJobsDone) {
    retryFetchResults++;
  }
  await notifyCPEResultsViaSlackChannels({
    CPEs: extractCPEData(jobsResults),
    params: secretsAndParams
  });
  const handlerResponse = {
    logstream: context.logStreamName,
    startedOn: new Date().toUTCString(),
    allJobsDone,
    scheduledJobs: stillNotReadyJobs,
    retryFetchResults
  };
  Logger.log('Function finished:' + JSON.stringify(handlerResponse));
  Logger.flushLogs();
  return handlerResponse;
}

handler.handler = handler;
module.exports = handler;
exports.handler = handler;
