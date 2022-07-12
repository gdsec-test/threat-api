const winston = require('winston');
const WinstonCloudWatch = require('winston-cloudwatch');
const { AWS_DEFAULT_REGION } = require('./const');

const name = 'vulnerabilitywatch';
let _instance;

const Logger = {
  init: ({
    region = AWS_DEFAULT_REGION,
    streamName = name,
    groupName = '/aws/lambda/',
    doCloudWatch = true
  }) => {
    if (doCloudWatch) {
      const Logger = new WinstonCloudWatch({
        name: 'using-' + name,
        logGroupName: groupName,
        logStreamName: streamName,
        awsRegion: region
      });
      this.logGroupName = groupName;
      this.logStreamName = streamName;
      _instance = winston.add(Logger);
    }
    winston.addColors({
      error: 'red'
    });
    _instance = winston.add(
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.simple()
        )
      })
    );
  },
  flushLogs: () => {
    if (!_instance) {
      Logger.init();
    }
    const transport = _instance.transports.find(
      (t) => t.name === 'using-' + name
    );
    if (transport && transport[name]) {
      transport[name](function () {
        console.log('Flush logs');
      });
    }
  },
  log: (message = '') => {
    if (!_instance) {
      Logger.init();
    }
    winston.log({ level: 'info', message: message.toString() });
  },
  error: (message = '') => {
    if (!_instance) {
      Logger.init();
    }
    winston.log({ level: 'error', message: message.toString() });
  }
};

module.exports = Logger;