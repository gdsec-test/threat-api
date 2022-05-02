import unittest
from unittest.mock import Mock, patch
import importlib
trustar = importlib.import_module('trustar-isac')

class Trustar(unittest.TestCase):
    def setup(self):
        # TODO: mock
        pass

    def testConvertTimestamp(self):
        input = 946702800
        expected = '2000-01-01T00:00:00Z'
        result = trustar.convertTimestamp(input)
        self.assertEqual(result, expected)
    
    def testConvertIndicator(self):
        mocked_a_class = Mock()
        mocked_a_instance = mocked_a_class.return_value
        mocked_a_instance.to_dict.return_value = dict()
        with patch():
        #input = (mock.)

if __name__ == '__main__':
    unittest.main()