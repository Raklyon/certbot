"""Tests for certbot.helpful_parser"""
import unittest

from certbot.cli import HelpfulArgumentParser




class TestScanningFlags(unittest.TestCase):
    '''Test the prescan_for_flag method of HelpfulArgumentParser'''
    def test_prescan_no_help_flag(self):
        helpful_parser = HelpfulArgumentParser(['run'], {},
                                               detect_defaults=False)
        detected_flag = helpful_parser.prescan_for_flag('--help',
                                                        ['all', 'certonly'])
        self.assertFalse(detected_flag)
        detected_flag = helpful_parser.prescan_for_flag('-h',
                                                        ['all, certonly'])
        self.assertFalse(detected_flag)

    def test_prescan_unvalid_topic(self):
        helpful_parser = HelpfulArgumentParser(['--help', 'all'], {},
                                               detect_defaults=False)
        detected_flag = helpful_parser.prescan_for_flag('--help',
                                                    ['potato'])
        self.assertIs(detected_flag, True)
        detected_flag = helpful_parser.prescan_for_flag('-h',
                                                    helpful_parser.help_topics)
        self.assertFalse(detected_flag)

    def test_prescan_valid_topic(self):
        helpful_parser = HelpfulArgumentParser(['-h', 'all'], {},
                                               detect_defaults=False)
        detected_flag = helpful_parser.prescan_for_flag('-h',
                                                    helpful_parser.help_topics)
        self.assertEqual(detected_flag, 'all')
        detected_flag = helpful_parser.prescan_for_flag('--help',
                                                    helpful_parser.help_topics)
        self.assertFalse(detected_flag)




if __name__ == '__main__':
    unittest.main() # pragma: no cover
