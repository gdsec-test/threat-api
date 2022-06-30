const gdAuth = require('gd-auth-client');
const Logger = require('./logger');
const fetch = require('node-fetch');

const CPE_PER_JOB = 5;

module.exports = async function submitTaniumJobs({
  CPEsFromDB,
  env,
  secretsAndParams
}) {
  const { baseApiUrl, ssoUrl } = env;
  const { serviceAccountUser, serviceAccountPass } = secretsAndParams;
  const authToken = await gdAuth
    .getTokenFromCredentials(ssoUrl, serviceAccountUser, serviceAccountPass, {
      realm: 'jomax'
    })
    .catch((catchErr) => {
      Logger.error('Error authenticating in SSO ' + JSON.stringify(catchErr));
    });
  if (!authToken) {
    Logger.error('Error authenticating in SSO. See logs');
  } else {
    Logger.log('Authenticating in SSO successfull');
  }
  const cpeTaniumJobsLimit =
    parseInt(secretsAndParams.cpeTaniumJobsLimit) || 50;

  let cpes = CPEsFromDB.slice(0, cpeTaniumJobsLimit);
  const url = `${baseApiUrl}/v1/jobs`;

  const splitCpes = [];
  while (cpes.length) {
    splitCpes.push(cpes.splice(0, CPE_PER_JOB));
  }

  const params = {
    iocType: 'CPE',
    modules: ['tanium'],
    metadata: {}
  };
  const payload = {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      Authorization: `sso-jwt ${authToken}`
    }
  };
  const result = await Promise.all(
    splitCpes.map(async (smallerCpes) => {
      const jobParams = { ...params, iocs: smallerCpes };
      Logger.log('Submit Tanium Job:' + url + ' ' + JSON.stringify(jobParams));
      const resp = await fetch(url, {
        ...payload,
        body: JSON.stringify(jobParams)
      });
      return resp.json();
    })
  );
  return result.map(({ jobId }) => jobId);
};
