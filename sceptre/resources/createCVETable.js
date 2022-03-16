#!/usr/bin/env node

const createCVETableIfNotExist = require('../../lambdas/vulnerabilitywatch/src/createCVETableIfNotExist');
const Logger = require('../../lambdas/vulnerabilitywatch/src/logger');

async function createTable() {
  const region = process.env.AWS_REGION ||  process.env.AWS_DEFAULT_REGION || 'us-west-2';
  Logger.init({
    region
  });
  await createCVETableIfNotExist({ region });
  process.exit(0);
}

createTable();
