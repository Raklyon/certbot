"""Tests for certbot.helpful_parser"""
import unittest

from certbot.cli import HelpfulArgumentParser




class TestScanningFlags(unittest.TestCase):
    '''Test the prescan_for_flag method of HelpfulArgumentParser'''
    def test_prescan_no_help_flag(self):
        arg_parser = HelpfulArgumentParser(['run'], {})
        detected_flag = arg_parser.prescan_for_flag('--help',
                                                        ['all', 'certonly'])
        self.assertFalse(detected_flag)
        detected_flag = arg_parser.prescan_for_flag('-h',
                                                        ['all, certonly'])
        self.assertFalse(detected_flag)

    def test_prescan_unvalid_topic(self):
        arg_parser = HelpfulArgumentParser(['--help', 'all'], {})
        detected_flag = arg_parser.prescan_for_flag('--help',
                                                    ['potato'])
        self.assertIs(detected_flag, True)
        detected_flag = arg_parser.prescan_for_flag('-h',
                                                    arg_parser.help_topics)
        self.assertFalse(detected_flag)

    def test_prescan_valid_topic(self):
        arg_parser = HelpfulArgumentParser(['-h', 'all'], {})
        detected_flag = arg_parser.prescan_for_flag('-h',
                                                    arg_parser.help_topics)
        self.assertEqual(detected_flag, 'all')
        detected_flag = arg_parser.prescan_for_flag('--help',
                                                    arg_parser.help_topics)
        self.assertFalse(detected_flag)

class TestDetermineVerbs(unittest.TestCase):
    '''Tests for determine_verb methods of HelpfulArgumentParser'''
    def test_determine_verb_wrong_verb(self):
        arg_parser = HelpfulArgumentParser(['potato'], {})
        self.assertEqual(arg_parser.verb, "run")
        self.assertEqual(arg_parser.args, ["potato"])

    def test_determine_verb_help(self):
        arg_parser = HelpfulArgumentParser(['--help', 'everything'], {})
        self.assertEqual(arg_parser.verb, "help")
        self.assertEqual(arg_parser.args, ["--help", "everything"])
        arg_parser = HelpfulArgumentParser(['-d', 'some_domain', '--help',
                                               'all'], {})
        self.assertEqual(arg_parser.verb, "help")
        self.assertEqual(arg_parser.args, ['-d', 'some_domain', '--help',
                                               'all'])

    def test_determine_verb(self):
        arg_parser = HelpfulArgumentParser(['certonly'], {})
        self.assertEqual(arg_parser.verb, 'certonly')
        self.assertEqual(arg_parser.args, [])

        arg_parser = HelpfulArgumentParser(['auth'], {})
        self.assertEqual(arg_parser.verb, 'certonly')
        self.assertEqual(arg_parser.args, [])

        arg_parser = HelpfulArgumentParser(['everything'], {})
        self.assertEqual(arg_parser.verb, 'run')
        self.assertEqual(arg_parser.args, [])

class TestAdd(unittest.TestCase):
    def test_add_trivial_argument(self):
        arg_parser = HelpfulArgumentParser(['run'], {})
        arg_parser.add(None, "--hello-world")
        parsed_args = arg_parser.parser.parse_args(['--hello-world',
                                                    'Hello World!'])
        self.assertIs(parsed_args.hello_world, 'Hello World!')
        self.assertFalse(hasattr(parsed_args, 'potato'))

    def test_add_expected_argument(self):
        arg_parser = HelpfulArgumentParser(['--help', 'run'], {})
        arg_parser.add(
                [None, "run", "certonly", "register"],
                "--eab-kid", dest="eab_kid",
                metavar="EAB_KID",
                help="Key Identifier for External Account Binding")
        parsed_args = arg_parser.parser.parse_args(["--eab-kid", None])
        self.assertIs(parsed_args.eab_kid, None)


if __name__ == '__main__':
    unittest.main() # pragma: no cover
