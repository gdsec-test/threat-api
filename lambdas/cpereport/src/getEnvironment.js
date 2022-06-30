const AWS = require('aws-sdk');
const Logger = require('./logger');
const { ENV_CONFIG } = require('./const');
const SSM_ENV_PARAM = '/AdminParams/Team/Environment';

module.exports = async function getEnvironment({ region }) {
  const client = new AWS.SSM({
    region
  });
  return new Promise((resolve) => {
    client.getParameter({ Name: SSM_ENV_PARAM }, function (err, data) {
      if (err) {
        Logger.error(
          `Error fetching env param from ${SSM_ENV_PARAM} AWS SSM` +
            JSON.stringify(err)
        );
        resolve({ err });
      } else {
        Logger.log('Fetching environment from AWS Param Store is successfull');
        let result;
        try {
          const env = data.Parameter.Value;
          result = ENV_CONFIG[env];
        } catch (catchErr) {
          Logger.error(
            'Error fetching environment from AWS Param Store' +
              JSON.stringify(catchErr)
          );
        }
        resolve(result);
      }
    });
  });
};
