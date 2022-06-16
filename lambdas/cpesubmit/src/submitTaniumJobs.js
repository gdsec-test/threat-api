const gdAuth = require('gd-auth-client');
const Logger = require('./logger');
const fetch = require('node-fetch');

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
  }
  const cpeTaniumJobsLimit = parseInt(secretsAndParams.cpeTaniumJobsLimit) || 5;

  let cpes = CPEsFromDB.slice(0, cpeTaniumJobsLimit);
  const url = `${baseApiUrl}/v1/jobs`;
  const params = {
    iocType: 'CPE',
    iocs: cpes,
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
  payload.body = JSON.stringify(params);
  const resp = await fetch(url, payload);
  return await resp.json();
};
