const Logger = require('./logger');
const Papa = require('papaparse');

module.exports = function extractCPEData(jobsResults = []) {
  let result = [];
  jobsResults.forEach((jobResult) => {
    const { responses: { tanium = [] } = {} } = jobResult;
    const respData = tanium.reduce((acc, item) => {
      const { Data = '', error } = item;
      if (!error) {
        const parsedData =
          Papa.parse(Data, {
            header: true,
            skipEmptyLines: true
          }).data || [];
        parsedData.forEach((data) => {
          let { CPE, Data } = data;
          if (Data) {
            Data = Data.trim();
            Data = Data.replace(/\[no results\]/gim, 'no_version');
            Data = Data.split(' ');
            const CIFound = [];
            for (let i = 0; i < Data.length; i += 3) {
              CIFound.push(Data[i]);
            }
            if (CIFound.length) {
              acc.push({ CPE, CIFound });
            }
          }
        });
      } else {
        Logger.error('Error in Tanium Job Results' + JSON.stringify(error));
      }
      return acc;
    }, []);
    result = result.concat(respData);
  });
  return result;
};
