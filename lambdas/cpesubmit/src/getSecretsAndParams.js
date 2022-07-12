const AWS = require('aws-sdk');
const Logger = require('./logger');

module.exports = async function getSecretsAndParams({ region }) {
  const secretName = 'vulnerabilitywatch';
  const client = new AWS.SecretsManager({
    region
  });
  return new Promise((resolve) => {
    client.getSecretValue({ SecretId: secretName }, function (err, data) {
      if (err) {
        Logger.error('Error fetching secrets ' + JSON.stringify(err));
        resolve({ err });
      } else {
        Logger.log('Fetching secrets is successfull');
        let result;
        try {
          if ('SecretString' in data) {
            result = JSON.parse(data.SecretString);
          } else {
            let buff = new Buffer(data.SecretBinary, 'base64');
            result = buff.toString('ascii');
          }
        } catch (catchErr) {
          Logger.error('Error fetching secrets ' + JSON.stringify(catchErr));
        }
        resolve(result);
      }
    });
  });
};