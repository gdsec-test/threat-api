const { TABLE_NAME } = require('./const');
const Logger = require('./logger');

const matchCPE = new RegExp(
  'cpe:2[.]3?:[\\/]?[aoh*\\-]:[a-z0-9\\-._]*:([a-z0-9\\-._]*):',
  'i'
);

module.exports = async function getCPEsFromDB({ dynamodb }) {
  const query = {
    TableName: TABLE_NAME,
    ProjectionExpression: 'cve_id,cpe'
  };
  let dbCPEs = [];
  const cpesSoftwareKeys = new Set();
  let LastEvaluatedKey, err;
  Logger.log('Start fetching existing CPEs from DynamoDB');
  try {
    do {
      const result = await new Promise((resolve) => {
        const currentQuery = LastEvaluatedKey
          ? { ...query, ExclusiveStartKey: LastEvaluatedKey }
          : query;
        dynamodb.scan(currentQuery, function (err, data) {
          if (err) {
            Logger.log(
              'Error happened during scanning for CPEs ' + JSON.stringify(err)
            );
            resolve({ err });
          } else {
            const { LastEvaluatedKey, Items = [], Count } = data;
            Logger.log(
              `Fetching existing CPEs ${Count} from DynamoDB is successfull`
            );
            resolve({ LastEvaluatedKey, Items, Count });
          }
        });
      });
      LastEvaluatedKey = result.LastEvaluatedKey;
      err = result.err;
      let currentCPEs = [];
      result.Items.forEach((item) => {
        let { cve_id: { S: ID } = {}, cpe: { L: CPEData = [] } = {} } = item;
        if (!CPEData.length) {
          return;
        }
        const cpeList = [];
        CPEData.forEach(({ S: item }) => {
          const findCPE = item.match(matchCPE);
          // we do not push CPEs twice , which refer same software
          if (findCPE && !cpesSoftwareKeys.has(findCPE[1])) {
            cpesSoftwareKeys.add(findCPE[1]);
            cpeList.push(item);
          }
        });
        currentCPEs = [...currentCPEs, ...cpeList];
      });

      dbCPEs = [...dbCPEs, ...currentCPEs];
    } while (LastEvaluatedKey && !err);
  } catch (err) {
    Logger.log('Error happened during fetching dbCPEs ' + JSON.stringify(err));
  }
  return new Promise((resolve) => resolve(dbCPEs));
};
