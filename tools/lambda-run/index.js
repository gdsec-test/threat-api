#!/usr/bin/env node
'use strict';

const {
  promises: { readdir }
} = require('fs');
const winston = require('winston');
const app = require('commander');
const inquirer = require('inquirer');
const { exec } = require('child_process');
const path = require('path');

const DIR_PREFIX = './';
const MODULES_DIR = `apis`;
const LAMBDA_ROOT_DIRS = [MODULES_DIR, 'lambdas'];
const RUNTIMES = [
  'go1.x',
  'nodejs12.x',
  'nodejs14.x',
  'python2.7',
  'python3.6',
  'python3.7',
  'python3.8'
];

const AWS_REGIONS = ['us-west-2', 'us-east-1', 'us-east-2', 'us-west-1'];

const askQuestions = async() => {
  const getDirectories = async (source) =>
    (await readdir(DIR_PREFIX + source, { withFileTypes: true }))
      .filter((dirent) => dirent.isDirectory())
      .map((dirent) => dirent.name);
  let lambdaList = await Promise.all(
    LAMBDA_ROOT_DIRS.map((root) => {
      return getDirectories(root).then((dirList) =>
        dirList.map((dir) => root + '/' + dir)
      );
    })
  );
  lambdaList = lambdaList.reduce((acc, item) => acc.concat(item), []);
  const questions = [
    {
      type: 'list',
      name: 'LAMBDA',
      message: 'What Lambda you want to debug?',
      choices: lambdaList
    },
    {
      type: 'list',
      name: 'RUNTIME',
      message: 'What runtime to use?',
      choices: RUNTIMES
    },
    {
      name: 'HANDLER',
      type: 'input',
      message:
        'Type main handler function name. Default: handler(Go), lambda.handler(Python) index.handler(NodeJS)'
    },
    {
      type: 'list',
      name: 'AWS_REGION',
      message: 'What AWS Region to use? Default is us-west-2',
      choices: AWS_REGIONS
    },
    {
      name: 'PORT',
      type: 'input',
      message:
        'What port to use to send requests to Lambda? Default is 9001:9001 (<host>:<container>)'
    }
  ];
  return inquirer.prompt(questions);
};

const desc = `Tool to run and debug AWS Lambdas locally. \
Please, set AWS creds (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) to be used by this tool before running \
Please, set following parameters to run properly`;

const run = () => {
  initLogger();
  app
    .version('1.0.0')
    .description(desc)
    //.option('-o', 'Custom option')
    .action(async (name, options, command) => {
      logInfo(desc);
      let { LAMBDA, RUNTIME, PORT, HANDLER, AWS_REGION } = await askQuestions();
      if (!PORT) {
        PORT = 9001;
      }
      if (!AWS_REGION) {
        AWS_REGION = 'us-west-2';
      }
      const volumePath = path.resolve(DIR_PREFIX + LAMBDA);
      let cmd = `docker run --rm \
      -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN -e AWS_REGION=${AWS_REGION}\
      -e DOCKER_LAMBDA_WATCH=1 -e DOCKER_LAMBDA_STAY_OPEN=1 \
      -p ${PORT}:${PORT} -e DOCKER_LAMBDA_API_PORT=${PORT} -e DOCKER_LAMBDA_RUNTIME_PORT=${PORT} \
      -i  \
      -v ${volumePath}:/var/task:ro,delegated `;
      cmd += ` lambci/lambda:${RUNTIME}`;
      if (!HANDLER) {
        if (RUNTIME.startsWith('go')) {
          cmd += ' handler ';
          cmd =
            `set -eu
            env GOPRIVATE=github.secureserver.net,github.com/gdcorp-* GOOS=linux GOARCH=amd64 go build -o ./${LAMBDA}/handler ./${LAMBDA}/...
            ` + cmd;
        } else if (RUNTIME.startsWith('nodejs')) {
          cmd += ' index.handler ';
        } else if (RUNTIME.startsWith('python')) {
          cmd += ' lambda.handler ';
        } else {
          cmd += ' handler ';
        }
      }
      suggestion({ LAMBDA, PORT });
      logInfo(`Assembled Docker command is:`);
      logInfo(cmd);
      runDocker(cmd);
    })
    .parse(process.argv);
};

function runDocker(cmd) {
  const childCmd = exec(cmd, (error, stdout, stderr) => {
    if (error) {
      logError(`${error.message}`);
      return;
    }
    if (stderr) {
      logError(`${stderr}`);
      return;
    }
    logInfo(`${stdout}`);
  });
  childCmd.stdout.pipe(process.stdout);
  childCmd.stderr.pipe(process.stderr);
  childCmd.on('close', (code) => {
    logInfo(`Lambda run exited with code ${code}`);
  });
}

function initLogger() {
  winston.addColors({
    error: 'red'
  });
  winston.add(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  );
}

function logInfo(message) {
  winston.log({ level: 'info', message: message.toString() });
}

function logError(message) {
  winston.log({ level: 'error', message: message.toString() });
}

function suggestion({ LAMBDA, PORT }) {
  const lambdaPath = LAMBDA.split('/');
  const functionName = lambdaPath[lambdaPath.length - 1];
  let suggestedPayload = '{"prop": "value"}';
  if (lambdaPath[0] === MODULES_DIR) {
    const job = {
      JobID: 'test',
      Submission: {
        Body: JSON.stringify({
          Modules: ['apivoid'],
          IOCs: ['google.com'],
          IOCType: 'DOMAIN'
        })
      }
    };
    suggestedPayload = {
      Records: [
        {
          Sns: {
            Message: JSON.stringify(job)
          }
        }
      ]
    };
  }
  const suggestedInvoke =
    `aws lambda invoke --endpoint http://localhost:${PORT} --no-sign-request ` +
    `--function-name ${functionName} --cli-binary-format raw-in-base64-out --payload '${JSON.stringify(
      suggestedPayload
    )}' /dev/stdout 2>/dev/null`;
  logInfo(`Use below command to call\\debug Lambda:\n${suggestedInvoke}`);
}

run();
