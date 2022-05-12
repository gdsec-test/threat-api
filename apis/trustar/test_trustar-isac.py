import unittest
from unittest.mock import Mock, patch, MagicMock
import json
from typing import Any
import importlib
trustar = importlib.import_module('trustar-isac')

class Trustar(unittest.TestCase):
    def setup(self):
        # TODO: mock
        pass

    def testConvertTimestamp(self):
        input = 946684800000
        expected = '2000-01-01T00:00:00Z'
        result = trustar.convertTimestamp(input)
        self.assertEqual(result, expected)
    
    def testConvertIndicatorNoResults(self):
        result = trustar.convertIndicator(None, list())
        self.assertEqual(0, len(result))

    def testConvertIndicatorSuccess(self):
        ioc = '127.0.0.1'
        mocked_a_class = Mock()
        mocked_a_instance = mocked_a_class.return_value
        mocked_a_instance.to_dict.return_value = { ioc: None }
        result = trustar.convertIndicator(ioc, [mocked_a_instance])
        self.assertEqual(1, len(result))
        self.assertTrue(ioc in result[0])

    def testConvertToCsv(self):
        ioc = '127.0.0.1'
        iocs = {
            ioc: [{
                'firstSeen': 0,
                'lastSeen': 0,
                'sightings': None
            }]
        }
        result = trustar.convertToCsv(iocs, dict())
        header_row = 'ioc,firstSeen,lastSeen,sightings,correlations\n'
        self.assertTrue(result.startswith(header_row))
        self.assertTrue(f'\n{ioc},' in result)
        self.assertTrue(result.endswith('{}\n'))

    def testRetrieveCorrelatedIndicatorsNoReports(self):
        ioc = '127.0.0.1'
        ts = Mock()
        ts.get_correlated_reports = Mock(return_value=None)
        result_dict, result_msg = trustar.retrieveCorrelatedIndicators(ts, ioc)
        ts.get_correlated_reports.assert_called_once_with([ioc])
        expected_msg = 'Null returned when retrieving reports correlated with 127.0.0.1'
        self.assertEqual(expected_msg, result_msg)
        self.assertEqual(0, len(result_dict))

    def testRetrieveCorrelatedIndicatorsWithReports(self):
        ioc = '127.0.0.1'
        report_ids = [ 'A', 'B', 'C' ]
        correlations = list()
        for i in range(0, len(report_ids)):
            correlation = Mock()
            correlation.type = f'TESTTYPE{i}'
            correlation.value = f'TESTVALUE{i}'
            correlations.append([correlation])
        ts = Mock()
        def makeReport(id:str) -> Any:
            report = Mock()
            report.id = id
            return report
        ts.get_correlated_reports = Mock(return_value=[makeReport(id) for id in report_ids])
        ts.get_indicators_for_report = Mock()
        ts.get_indicators_for_report.side_effect = correlations
        result_dict, result_msg = trustar.retrieveCorrelatedIndicators(ts, ioc)
        ts.get_correlated_reports.assert_called_once_with([ioc])
        ts.get_indicators_for_report.assert_called_with(report_ids[-1])
        self.assertIsNone(result_msg)
        self.assertEqual(len(report_ids), len(result_dict))
    
    def testProcessNoModules(self):
        job_request = {
            'jobId': 'TESTJOB',
            'submission': { 'body': '{}' },
            'modules': list()
        }
        result = trustar.process(job_request)
        self.assertEqual(0, len(result))
    
    @patch('trustar-isac.configureTrustar')
    @patch('trustar-isac.lookupIp')
    @patch('trustar-isac.retrieveCorrelatedIndicators')
    @patch('trustar-isac.convertToCsv', return_value='')
    def testProcessWithModules(self, convert_csv, retrieve_correlated_indicators, lookup_ip, configure_trustar):
        ioc = '127.0.0.1'
        ts = MagicMock()
        ts.search_indicators.return_value = { ioc: list() }
        ts.get_correlated_reports.return_value = None
        retrieve_correlated_indicators.return_value = ( None, '' )
        configure_trustar.return_value = ts
        job_id = 'TESTJOB'
        job_request = {
            'jobId': job_id,
            'submission': { 'body': json.dumps({
                'iocType': 'IP',
                'iocs': [ ioc ],
                'modules': [ 'trustar' ]
            })
            },
        }
        indicator = Mock()
        indicator.to_dict.return_value = { ioc: list() }
        lookup_ip.return_value = [ indicator ]
        result = trustar.process(job_request)
        self.assertEqual(3, len(result))
        self.assertEqual('trustar', result['module_name'])
        self.assertEqual(job_id, result['jobId'])
        self.assertTrue('response' in result)

if __name__ == '__main__':
    unittest.main()