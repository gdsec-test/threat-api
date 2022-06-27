const gdAuth = require('gd-auth-client');
const Logger = require('./logger');
const fetch = require('node-fetch');

module.exports = async function getTaniumJobsResults({
  scheduledJobs = [],
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
  const stillNotReadyJobs = [];
  const jobsResults = [];
  return await new Promise((resolve) => {
    const payload = {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Authorization: `sso-jwt ${authToken}`
      }
    };
    Promise.all(
      scheduledJobs.map((jobId) => {
        const url = `${baseApiUrl}/v1/jobs/${jobId}`;
        return fetch(url, payload);
      })
    )
      .then((responses = []) => {
        return Promise.all(
          responses.map((resp, i) => {
            if (resp.ok) {
              return resp.json();
            } else {
              const jobId = scheduledJobs[i];
              stillNotReadyJobs.push(jobId);
              return Promise.resolve({});
            }
          })
        );
      })
      .then((responses = []) => {
        responses.forEach((resp, i) => {
          if (resp.jobStatus === 'Completed') {
            jobsResults.push(resp);
          } else {
            const jobId = scheduledJobs[i];
            stillNotReadyJobs.push(jobId);
          }
        });
        resolve({ stillNotReadyJobs, jobsResults });
      });
  });
};
