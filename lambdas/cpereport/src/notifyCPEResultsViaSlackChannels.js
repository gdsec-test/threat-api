const Logger = require('./logger');

const fetch = (...args) =>
  import('node-fetch').then(({ default: fetch }) => fetch(...args));

const BLOCKS_PER_MESSAGE = 25;
const MAX_TEXT_SIZE = 3000;
const clampIt = (str, size) => str.slice(0, size || MAX_TEXT_SIZE);

const getCPEFormattedRecord = ({ CPE = '', CIFound = [] }) => {
  let CPEData = `<https://www.google.com/search?q=${CPE}|${CPE}>`;
  CPEData = `\n:red-flag:${CPEData}\n:red-flag:`;
  return [
    {
      type: 'context',
      elements: [
        {
          type: 'mrkdwn',
          text: clampIt(
            `*CPEs*: ${CPEData}\n*Computers Found*: ${CIFound.join('\n')}`
          )
        }
      ]
    },
    {
      type: 'actions',
      elements: [
        {
          type: 'button',
          style: 'primary',
          action_id: 'create_incident_in_snow',
          text: {
            type: 'plain_text',
            text: clampIt(`Create Incident for CPE ${CPE}`, 70)
          },
          url: 'https://godaddy.service-now.com/nav_to.do?uri=%2Fincident.do%3Fsys_id%3D-1'
        }
      ]
    },
    {
      type: 'divider'
    }
  ];
};

function debounce(func, timeout = 1000) {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      func.apply(this).then(data => resolve(data)).catch(data => reject(data));;
    }, timeout);
  });
}

async function slack({ CPEs, creds: { botToken, channel } = {} }) {
  async function sendSlackMessage({ blocks, parentThread }) {
    let slackBody = {
      username: 'CPE Alert',
      channel: `${channel}`,
      blocks
    };
    if (parentThread) {
      Logger.log('Slack message has parent thread:' + parentThread);
      slackBody.thread_ts = parentThread;
    } else {
      Logger.log('Slack message has no parent thread');
    }
    return await fetch('https://slack.com/api/chat.postMessage', {
      method: 'post',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        Authorization: `Bearer ${botToken}`
      },
      body: JSON.stringify(slackBody)
    })
      .then((response) => {
        return response.json();
      })
      .then((data = {}) => {
        if (data.ok) {
          Logger.log('Alarm sent to Slack successfully:' + JSON.stringify(data));
        } else {
          Logger.log('Alarm sent to Slack with errors:' + JSON.stringify(data));
        }
        return data;
      })
      .catch((err = {}) => {
        Logger.log('Could not send alarm to Slack' + JSON.stringify(err));
      });
  }
  const CPEFormatted = CPEs.reduce((acc, cpeData) => {
    acc = [...acc, ...getCPEFormattedRecord(cpeData)];
    return acc;
  }, []);
  const slackResponse = await sendSlackMessage({
    blocks: [
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `Report for CPEs\n`
        }
      }
    ]
  });
  Logger.log('Response From Slack:' + JSON.stringify(slackResponse));
  const blocks = [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*CPEs and their Computer Instances*`
      }
    },
    {
      type: 'divider'
    },
    ...CPEFormatted
  ];

  const splitBlocks = [];
  while (blocks.length) {
    splitBlocks.push(blocks.splice(0, BLOCKS_PER_MESSAGE));
  }
  Logger.log('Start sending threaded Slack messages:' + JSON.stringify(splitBlocks));
  const result = await Promise.all(
    splitBlocks.map((smallerBlock) => {
        return debounce(() => sendSlackMessage({
          parentThread: slackResponse.ts,
          blocks: smallerBlock
        }));
      }
    )
  );
  return result;
}

const CHANNEL_PROVIDERS = {
  slack
};

async function notifyCPEResultsViaSlackChannels({ CPEs, params }) {
  const { configs = [] } = params;
  Logger.log('Calling Slack to send notification');
  return await Promise.all(
    configs.map(async (config) => {
      const {
        output: { type, creds }
      } = config;
      const channelHandler = CHANNEL_PROVIDERS[type];
      if (!channelHandler) {
        Logger.error(
          `Unable to send notifications via ${type} channel, cause no handler code supported`
        );
        return Promise.resolve();
      }
      return await channelHandler({
        CPEs,
        creds
      });
    })
  );
}

module.exports = notifyCPEResultsViaSlackChannels;