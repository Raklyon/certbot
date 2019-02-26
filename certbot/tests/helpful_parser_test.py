"""Tests for certbot.helpful_parser"""
import unittest

from certbot.cli import HelpfulArgumentParser




class TestScanningFlags(unittest.TestCase):
    '''Test the prescan_for_flag method of HelpfulArgumentParser'''
    def test_prescan_no_help_flag(self):
        helpful_parser = HelpfulArgumentParser(['run'], {})
        detected_flag = helpful_parser.prescan_for_flag('--help',
                                                        ['all', 'certonly'])
        self.assertFalse(detected_flag)
        detected_flag = helpful_parser.prescan_for_flag('-h',
                                                        ['all, certonly'])
        self.assertFalse(detected_flag)

    def test_prescan_unvalid_topic(self):
        helpful_parser = HelpfulArgumentParser(['--help', 'all'], {})
        detected_flag = helpful_parser.prescan_for_flag('--help',
                                                    ['potato'])
        self.assertIs(detected_flag, True)
        detected_flag = helpful_parser.prescan_for_flag('-h',
                                                    helpful_parser.help_topics)
        self.assertFalse(detected_flag)

    def test_prescan_valid_topic(self):
        helpful_parser = HelpfulArgumentParser(['-h', 'all'], {})
        detected_flag = helpful_parser.prescan_for_flag('-h',
                                                    helpful_parser.help_topics)
        self.assertEqual(detected_flag, 'all')
        detected_flag = helpful_parser.prescan_for_flag('--help',
                                                    helpful_parser.help_topics)
        self.assertFalse(detected_flag)

class TestDetermineVerbs(unittest.TestCase):
    '''Tests for determine_verb methods of HelpfulArgumentParser'''
    def test_determine_verb_wrong_verb(self):
        helpful_parser = HelpfulArgumentParser(['potato'], {})
        self.assertEqual(helpful_parser.verb, "run")
        self.assertEqual(helpful_parser.args, ["potato"])

    def test_determine_verb_help(self):
        helpful_parser = HelpfulArgumentParser(['--help', 'everything'], {})
        self.assertEqual(helpful_parser.verb, "help")
        self.assertEqual(helpful_parser.args, ["--help", "everything"])
        helpful_parser = HelpfulArgumentParser(['-d', 'some_domain', '--help',
                                               'all'], {})
        self.assertEqual(helpful_parser.verb, "help")
        self.assertEqual(helpful_parser.args, ['-d', 'some_domain', '--help',
                                               'all'])

    def test_determine_verb(self):
        helpful_parser = HelpfulArgumentParser(['certonly'], {})
        self.assertEqual(helpful_parser.verb, 'certonly')
        self.assertEqual(helpful_parser.args, [])

        helpful_parser = HelpfulArgumentParser(['auth'], {})
        self.assertEqual(helpful_parser.verb, 'certonly')
        self.assertEqual(helpful_parser.args, [])

        helpful_parser = HelpfulArgumentParser(['everything'], {})
        self.assertEqual(helpful_parser.verb, 'run')
        self.assertEqual(helpful_parser.args, [])



if __name__ == '__main__':
    unittest.main() # pragma: no cover
