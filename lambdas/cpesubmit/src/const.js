const TABLE_NAME = 'cve';
const AWS_DEFAULT_REGION = 'us-west-2';
const ENV_CONFIG = {
  'dev-private': {
    baseApiUrl: 'https://api-private.threat.int.dev-gdcorp.tools',
    ssoUrl: 'sso.dev-gdcorp.tools'
  },
  dev: {
    baseApiUrl: 'https://api.threat.int.dev-gdcorp.tools',
    ssoUrl: 'sso.dev-gdcorp.tools'
  },
  prod: {
    baseApiUrl: 'https://api.threat.int.gdcorp.tools',
    ssoUrl: 'sso.gdcorp.tools'
  }
};

module.exports = {
  TABLE_NAME,
  AWS_DEFAULT_REGION,
  ENV_CONFIG
};
