"""Certbot command line argument & config processing."""
# pylint: disable=too-many-lines
from __future__ import print_function
import argparse
import copy
import glob
import logging
import logging.handlers
import os
import sys

import six
import zope.component
import zope.interface

from zope.interface import interfaces as zope_interfaces

from acme import challenges
# pylint: disable=unused-import, no-name-in-module
from acme.magic_typing import Any, Dict, Optional
# pylint: enable=unused-import, no-name-in-module

import certbot

from certbot import constants
from certbot import crypto_util
from certbot import errors
from certbot import hooks
from certbot import interfaces
from certbot import util

from certbot.plugins import disco as plugins_disco
import certbot.plugins.enhancements as enhancements
import certbot.plugins.selection as plugin_selection

from certbot.cli.argument_parser import *
from certbot.cli.argument_parser import _add_all_groups
from certbot.cli.argument_parser import _DomainsAction
from certbot.cli.argument_parser import _Default

logger = logging.getLogger(__name__)

# Global, to save us from a lot of argument passing within the scope of this module
helpful_parser = None  # type: Optional[HelpfulArgumentParser]


# Maps a config option to a set of config options that may have modified it.
# This dictionary is used recursively, so if A modifies B and B modifies C,
# it is determined that C was modified by the user if A was modified.
VAR_MODIFIERS = {"account": set(("server",)),
                 "renew_hook": set(("deploy_hook",)),
                 "server": set(("dry_run", "staging",)),
                 "webroot_map": set(("webroot_path",))}


def report_config_interaction(modified, modifiers):
    """Registers config option interaction to be checked by set_by_cli.

    This function can be called by during the __init__ or
    add_parser_arguments methods of plugins to register interactions
    between config options.

    :param modified: config options that can be modified by modifiers
    :type modified: iterable or str (string_types)
    :param modifiers: config options that modify modified
    :type modifiers: iterable or str (string_types)

    """
    if isinstance(modified, six.string_types):
        modified = (modified,)
    if isinstance(modifiers, six.string_types):
        modifiers = (modifiers,)

    for var in modified:
        VAR_MODIFIERS.setdefault(var, set()).update(modifiers)


def set_by_cli(var):
    """
    Return True if a particular config variable has been set by the user
    (CLI or config file) including if the user explicitly set it to the
    default.  Returns False if the variable was assigned a default value.
    """
    detector = set_by_cli.detector  # type: ignore
    if detector is None and helpful_parser is not None:
        # Setup on first run: `detector` is a weird version of config in which
        # the default value of every attribute is wrangled to be boolean-false
        plugins = plugins_disco.PluginsRegistry.find_all()
        # reconstructed_args == sys.argv[1:], or whatever was passed to main()
        reconstructed_args = helpful_parser.args + [helpful_parser.verb]
        detector = set_by_cli.detector = prepare_and_parse_args(  # type: ignore
            plugins, reconstructed_args, detect_defaults=True)
        # propagate plugin requests: eg --standalone modifies config.authenticator
        detector.authenticator, detector.installer = (  # type: ignore
            plugin_selection.cli_plugin_requests(detector))

    if not isinstance(getattr(detector, var), _Default):
        logger.debug("Var %s=%s (set by user).", var, getattr(detector, var))
        return True

    for modifier in VAR_MODIFIERS.get(var, []):
        if set_by_cli(modifier):
            logger.debug("Var %s=%s (set by user).",
                var, VAR_MODIFIERS.get(var, []))
            return True

    return False

# static housekeeping var
# functions attributed are not supported by mypy
# https://github.com/python/mypy/issues/2087
set_by_cli.detector = None  # type: ignore


def has_default_value(option, value):
    """Does option have the default value?

    If the default value of option is not known, False is returned.

    :param str option: configuration variable being considered
    :param value: value of the configuration variable named option

    :returns: True if option has the default value, otherwise, False
    :rtype: bool

    """
    if helpful_parser is not None:
        return (option in helpful_parser.defaults and
                helpful_parser.defaults[option] == value)
    return False


def option_was_set(option, value):
    """Was option set by the user or does it differ from the default?

    :param str option: configuration variable being considered
    :param value: value of the configuration variable named option

    :returns: True if the option was set, otherwise, False
    :rtype: bool

    """
    return set_by_cli(option) or not has_default_value(option, value)


def argparse_type(variable):
    """Return our argparse type function for a config variable (default: str)"""
    # pylint: disable=protected-access
    if helpful_parser is not None:
        for action in helpful_parser.parser._actions:
            if action.type is not None and action.dest == variable:
                return action.type
    return str

def read_file(filename, mode="rb"):
    """Returns the given file's contents.

    :param str filename: path to file
    :param str mode: open mode (see `open`)

    :returns: absolute path of filename and its contents
    :rtype: tuple

    :raises argparse.ArgumentTypeError: File does not exist or is not readable.

    """
    try:
        filename = os.path.abspath(filename)
        with open(filename, mode) as the_file:
            contents = the_file.read()
        return filename, contents
    except IOError as exc:
        raise argparse.ArgumentTypeError(exc.strerror)

def config_help(name, hidden=False):
    """Extract the help message for an `.IConfig` attribute."""
    # pylint: disable=no-member
    if hidden:
        return argparse.SUPPRESS
    else:
        field = interfaces.IConfig.__getitem__(name) # type: zope.interface.interface.Attribute
        return field.__doc__



def prepare_and_parse_args(plugins, args, detect_defaults=False):  # pylint: disable=too-many-statements
    """Returns parsed command line arguments.

    :param .PluginsRegistry plugins: available plugins
    :param list args: command line arguments with the program name removed

    :returns: parsed command line arguments
    :rtype: argparse.Namespace

    """

    # pylint: disable=too-many-statements

    helpful = HelpfulArgumentParser(args, plugins, detect_defaults)
    _add_all_groups(helpful)

    # --help is automatically provided by argparse
    helpful.add(
        None, "-v", "--verbose", dest="verbose_count", action="count",
        default=flag_default("verbose_count"), help="This flag can be used "
        "multiple times to incrementally increase the verbosity of output, "
        "e.g. -vvv.")
    helpful.add(
        None, "-t", "--text", dest="text_mode", action="store_true",
        default=flag_default("text_mode"), help=argparse.SUPPRESS)
    helpful.add(
        None, "--max-log-backups", type=nonnegative_int,
        default=flag_default("max_log_backups"),
        help="Specifies the maximum number of backup logs that should "
             "be kept by Certbot's built in log rotation. Setting this "
             "flag to 0 disables log rotation entirely, causing "
             "Certbot to always append to the same log file.")
    helpful.add(
        [None, "automation", "run", "certonly", "enhance"],
        "-n", "--non-interactive", "--noninteractive",
        dest="noninteractive_mode", action="store_true",
        default=flag_default("noninteractive_mode"),
        help="Run without ever asking for user input. This may require "
              "additional command line flags; the client will try to explain "
              "which ones are required if it finds one missing")
    helpful.add(
        [None, "register", "run", "certonly", "enhance"],
        constants.FORCE_INTERACTIVE_FLAG, action="store_true",
        default=flag_default("force_interactive"),
        help="Force Certbot to be interactive even if it detects it's not "
             "being run in a terminal. This flag cannot be used with the "
             "renew subcommand.")
    helpful.add(
        [None, "run", "certonly", "certificates", "enhance"],
        "-d", "--domains", "--domain", dest="domains",
        metavar="DOMAIN", action=_DomainsAction,
        default=flag_default("domains"),
        help="Domain names to apply. For multiple domains you can use "
             "multiple -d flags or enter a comma separated list of domains "
             "as a parameter. The first domain provided will be the "
             "subject CN of the certificate, and all domains will be "
             "Subject Alternative Names on the certificate. "
             "The first domain will also be used in "
             "some software user interfaces and as the file paths for the "
             "certificate and related material unless otherwise "
             "specified or you already have a certificate with the same "
             "name. In the case of a name collision it will append a number "
             "like 0001 to the file path name. (default: Ask)")
    helpful.add(
        [None, "run", "certonly", "register"],
        "--eab-kid", dest="eab_kid",
        metavar="EAB_KID",
        help="Key Identifier for External Account Binding"
    )
    helpful.add(
        [None, "run", "certonly", "register"],
        "--eab-hmac-key", dest="eab_hmac_key",
        metavar="EAB_HMAC_KEY",
        help="HMAC key for External Account Binding"
    )
    helpful.add(
        [None, "run", "certonly", "manage", "delete", "certificates",
         "renew", "enhance"], "--cert-name", dest="certname",
        metavar="CERTNAME", default=flag_default("certname"),
        help="Certificate name to apply. This name is used by Certbot for housekeeping "
             "and in file paths; it doesn't affect the content of the certificate itself. "
             "To see certificate names, run 'certbot certificates'. "
             "When creating a new certificate, specifies the new certificate's name. "
             "(default: the first provided domain or the name of an existing "
             "certificate on your system for the same domains)")
    helpful.add(
        [None, "testing", "renew", "certonly"],
        "--dry-run", action="store_true", dest="dry_run",
        default=flag_default("dry_run"),
        help="Perform a test run of the client, obtaining test (invalid) certificates"
             " but not saving them to disk. This can currently only be used"
             " with the 'certonly' and 'renew' subcommands. \nNote: Although --dry-run"
             " tries to avoid making any persistent changes on a system, it "
             " is not completely side-effect free: if used with webserver authenticator plugins"
             " like apache and nginx, it makes and then reverts temporary config changes"
             " in order to obtain test certificates, and reloads webservers to deploy and then"
             " roll back those changes.  It also calls --pre-hook and --post-hook commands"
             " if they are defined because they may be necessary to accurately simulate"
             " renewal. --deploy-hook commands are not called.")
    helpful.add(
        ["register", "automation"], "--register-unsafely-without-email", action="store_true",
        default=flag_default("register_unsafely_without_email"),
        help="Specifying this flag enables registering an account with no "
             "email address. This is strongly discouraged, because in the "
             "event of key loss or account compromise you will irrevocably "
             "lose access to your account. You will also be unable to receive "
             "notice about impending expiration or revocation of your "
             "certificates. Updates to the Subscriber Agreement will still "
             "affect you, and will be effective 14 days after posting an "
             "update to the web site.")
    # TODO: When `certbot register --update-registration` is fully deprecated,
    # delete following helpful.add
    helpful.add(
        "register", "--update-registration", action="store_true",
        default=flag_default("update_registration"), dest="update_registration",
        help=argparse.SUPPRESS)
    helpful.add(
        ["register", "update_account", "unregister", "automation"], "-m", "--email",
        default=flag_default("email"),
        help=config_help("email"))
    helpful.add(["register", "update_account", "automation"], "--eff-email", action="store_true",
                default=flag_default("eff_email"), dest="eff_email",
                help="Share your e-mail address with EFF")
    helpful.add(["register", "update_account", "automation"], "--no-eff-email",
                action="store_false", default=flag_default("eff_email"), dest="eff_email",
                help="Don't share your e-mail address with EFF")
    helpful.add(
        ["automation", "certonly", "run"],
        "--keep-until-expiring", "--keep", "--reinstall",
        dest="reinstall", action="store_true", default=flag_default("reinstall"),
        help="If the requested certificate matches an existing certificate, always keep the "
             "existing one until it is due for renewal (for the "
             "'run' subcommand this means reinstall the existing certificate). (default: Ask)")
    helpful.add(
        "automation", "--expand", action="store_true", default=flag_default("expand"),
        help="If an existing certificate is a strict subset of the requested names, "
             "always expand and replace it with the additional names. (default: Ask)")
    helpful.add(
        "automation", "--version", action="version",
        version="%(prog)s {0}".format(certbot.__version__),
        help="show program's version number and exit")
    helpful.add(
        ["automation", "renew"],
        "--force-renewal", "--renew-by-default", dest="renew_by_default",
        action="store_true", default=flag_default("renew_by_default"),
        help="If a certificate "
             "already exists for the requested domains, renew it now, "
             "regardless of whether it is near expiry. (Often "
             "--keep-until-expiring is more appropriate). Also implies "
             "--expand.")
    helpful.add(
        "automation", "--renew-with-new-domains", dest="renew_with_new_domains",
        action="store_true", default=flag_default("renew_with_new_domains"),
        help="If a "
             "certificate already exists for the requested certificate name "
             "but does not match the requested domains, renew it now, "
             "regardless of whether it is near expiry.")
    helpful.add(
        "automation", "--reuse-key", dest="reuse_key",
        action="store_true", default=flag_default("reuse_key"),
        help="When renewing, use the same private key as the existing "
             "certificate.")

    helpful.add(
        ["automation", "renew", "certonly"],
        "--allow-subset-of-names", action="store_true",
        default=flag_default("allow_subset_of_names"),
        help="When performing domain validation, do not consider it a failure "
             "if authorizations can not be obtained for a strict subset of "
             "the requested domains. This may be useful for allowing renewals for "
             "multiple domains to succeed even if some domains no longer point "
             "at this system. This option cannot be used with --csr.")
    helpful.add(
        "automation", "--agree-tos", dest="tos", action="store_true",
        default=flag_default("tos"),
        help="Agree to the ACME Subscriber Agreement (default: Ask)")
    helpful.add(
        ["unregister", "automation"], "--account", metavar="ACCOUNT_ID",
        default=flag_default("account"),
        help="Account ID to use")
    helpful.add(
        "automation", "--duplicate", dest="duplicate", action="store_true",
        default=flag_default("duplicate"),
        help="Allow making a certificate lineage that duplicates an existing one "
             "(both can be renewed in parallel)")
    helpful.add(
        "automation", "--os-packages-only", action="store_true",
        default=flag_default("os_packages_only"),
        help="(certbot-auto only) install OS package dependencies and then stop")
    helpful.add(
        "automation", "--no-self-upgrade", action="store_true",
        default=flag_default("no_self_upgrade"),
        help="(certbot-auto only) prevent the certbot-auto script from"
             " upgrading itself to newer released versions (default: Upgrade"
             " automatically)")
    helpful.add(
        "automation", "--no-bootstrap", action="store_true",
        default=flag_default("no_bootstrap"),
        help="(certbot-auto only) prevent the certbot-auto script from"
             " installing OS-level dependencies (default: Prompt to install "
             " OS-wide dependencies, but exit if the user says 'No')")
    helpful.add(
        ["automation", "renew", "certonly", "run"],
        "-q", "--quiet", dest="quiet", action="store_true",
        default=flag_default("quiet"),
        help="Silence all output except errors. Useful for automation via cron."
             " Implies --non-interactive.")
    # overwrites server, handled in HelpfulArgumentParser.parse_args()
    helpful.add(["testing", "revoke", "run"], "--test-cert", "--staging",
        dest="staging", action="store_true", default=flag_default("staging"),
        help="Use the staging server to obtain or revoke test (invalid) certificates; equivalent"
             " to --server " + constants.STAGING_URI)
    helpful.add(
        "testing", "--debug", action="store_true", default=flag_default("debug"),
        help="Show tracebacks in case of errors, and allow certbot-auto "
             "execution on experimental platforms")
    helpful.add(
        [None, "certonly", "run"], "--debug-challenges", action="store_true",
        default=flag_default("debug_challenges"),
        help="After setting up challenges, wait for user input before "
             "submitting to CA")
    helpful.add(
        "testing", "--no-verify-ssl", action="store_true",
        help=config_help("no_verify_ssl"),
        default=flag_default("no_verify_ssl"))
    helpful.add(
        ["testing", "standalone", "apache", "nginx"], "--tls-sni-01-port", type=int,
        default=flag_default("tls_sni_01_port"),
        help=config_help("tls_sni_01_port"))
    helpful.add(
        ["testing", "standalone"], "--tls-sni-01-address",
        default=flag_default("tls_sni_01_address"),
        help=config_help("tls_sni_01_address"))
    helpful.add(
        ["testing", "standalone", "manual"], "--http-01-port", type=int,
        dest="http01_port",
        default=flag_default("http01_port"), help=config_help("http01_port"))
    helpful.add(
        ["testing", "standalone"], "--http-01-address",
        dest="http01_address",
        default=flag_default("http01_address"), help=config_help("http01_address"))
    helpful.add(
        "testing", "--break-my-certs", action="store_true",
        default=flag_default("break_my_certs"),
        help="Be willing to replace or renew valid certificates with invalid "
             "(testing/staging) certificates")
    helpful.add(
        "security", "--rsa-key-size", type=int, metavar="N",
        default=flag_default("rsa_key_size"), help=config_help("rsa_key_size"))
    helpful.add(
        "security", "--must-staple", action="store_true",
        dest="must_staple", default=flag_default("must_staple"),
        help=config_help("must_staple"))
    helpful.add(
        ["security", "enhance"],
        "--redirect", action="store_true", dest="redirect",
        default=flag_default("redirect"),
        help="Automatically redirect all HTTP traffic to HTTPS for the newly "
             "authenticated vhost. (default: Ask)")
    helpful.add(
        "security", "--no-redirect", action="store_false", dest="redirect",
        default=flag_default("redirect"),
        help="Do not automatically redirect all HTTP traffic to HTTPS for the newly "
             "authenticated vhost. (default: Ask)")
    helpful.add(
        ["security", "enhance"],
        "--hsts", action="store_true", dest="hsts", default=flag_default("hsts"),
        help="Add the Strict-Transport-Security header to every HTTP response."
             " Forcing browser to always use SSL for the domain."
             " Defends against SSL Stripping.")
    helpful.add(
        "security", "--no-hsts", action="store_false", dest="hsts",
        default=flag_default("hsts"), help=argparse.SUPPRESS)
    helpful.add(
        ["security", "enhance"],
        "--uir", action="store_true", dest="uir", default=flag_default("uir"),
        help='Add the "Content-Security-Policy: upgrade-insecure-requests"'
             ' header to every HTTP response. Forcing the browser to use'
             ' https:// for every http:// resource.')
    helpful.add(
        "security", "--no-uir", action="store_false", dest="uir", default=flag_default("uir"),
        help=argparse.SUPPRESS)
    helpful.add(
        "security", "--staple-ocsp", action="store_true", dest="staple",
        default=flag_default("staple"),
        help="Enables OCSP Stapling. A valid OCSP response is stapled to"
        " the certificate that the server offers during TLS.")
    helpful.add(
        "security", "--no-staple-ocsp", action="store_false", dest="staple",
        default=flag_default("staple"), help=argparse.SUPPRESS)
    helpful.add(
        "security", "--strict-permissions", action="store_true",
        default=flag_default("strict_permissions"),
        help="Require that all configuration files are owned by the current "
             "user; only needed if your config is somewhere unsafe like /tmp/")
    helpful.add(
        ["manual", "standalone", "certonly", "renew"],
        "--preferred-challenges", dest="pref_challs",
        action=_PrefChallAction, default=flag_default("pref_challs"),
        help='A sorted, comma delimited list of the preferred challenge to '
             'use during authorization with the most preferred challenge '
             'listed first (Eg, "dns" or "tls-sni-01,http,dns"). '
             'Not all plugins support all challenges. See '
             'https://certbot.eff.org/docs/using.html#plugins for details. '
             'ACME Challenges are versioned, but if you pick "http" rather '
             'than "http-01", Certbot will select the latest version '
             'automatically.')
    helpful.add(
        "renew", "--pre-hook",
        help="Command to be run in a shell before obtaining any certificates."
        " Intended primarily for renewal, where it can be used to temporarily"
        " shut down a webserver that might conflict with the standalone"
        " plugin. This will only be called if a certificate is actually to be"
        " obtained/renewed. When renewing several certificates that have"
        " identical pre-hooks, only the first will be executed.")
    helpful.add(
        "renew", "--post-hook",
        help="Command to be run in a shell after attempting to obtain/renew"
        " certificates. Can be used to deploy renewed certificates, or to"
        " restart any servers that were stopped by --pre-hook. This is only"
        " run if an attempt was made to obtain/renew a certificate. If"
        " multiple renewed certificates have identical post-hooks, only"
        " one will be run.")
    helpful.add("renew", "--renew-hook",
                action=_RenewHookAction, help=argparse.SUPPRESS)
    helpful.add(
        "renew", "--no-random-sleep-on-renew", action="store_false",
        default=flag_default("random_sleep_on_renew"), dest="random_sleep_on_renew",
        help=argparse.SUPPRESS)
    helpful.add(
        "renew", "--deploy-hook", action=_DeployHookAction,
        help='Command to be run in a shell once for each successfully'
        ' issued certificate. For this command, the shell variable'
        ' $RENEWED_LINEAGE will point to the config live subdirectory'
        ' (for example, "/etc/letsencrypt/live/example.com") containing'
        ' the new certificates and keys; the shell variable'
        ' $RENEWED_DOMAINS will contain a space-delimited list of'
        ' renewed certificate domains (for example, "example.com'
        ' www.example.com"')
    helpful.add(
        "renew", "--disable-hook-validation",
        action="store_false", dest="validate_hooks",
        default=flag_default("validate_hooks"),
        help="Ordinarily the commands specified for"
        " --pre-hook/--post-hook/--deploy-hook will be checked for"
        " validity, to see if the programs being run are in the $PATH,"
        " so that mistakes can be caught early, even when the hooks"
        " aren't being run just yet. The validation is rather"
        " simplistic and fails if you use more advanced shell"
        " constructs, so you can use this switch to disable it."
        " (default: False)")
    helpful.add(
        "renew", "--no-directory-hooks", action="store_false",
        default=flag_default("directory_hooks"), dest="directory_hooks",
        help="Disable running executables found in Certbot's hook directories"
        " during renewal. (default: False)")
    helpful.add(
        "renew", "--disable-renew-updates", action="store_true",
        default=flag_default("disable_renew_updates"), dest="disable_renew_updates",
        help="Disable automatic updates to your server configuration that"
        " would otherwise be done by the selected installer plugin, and triggered"
        " when the user executes \"certbot renew\", regardless of if the certificate"
        " is renewed. This setting does not apply to important TLS configuration"
        " updates.")
    helpful.add(
        "renew", "--no-autorenew", action="store_false",
        default=flag_default("autorenew"), dest="autorenew",
        help="Disable auto renewal of certificates.")

    helpful.add_deprecated_argument("--agree-dev-preview", 0)
    helpful.add_deprecated_argument("--dialog", 0)

    # Populate the command line parameters for new style enhancements
    enhancements.populate_cli(helpful.add)

    _create_subparsers(helpful)
    _paths_parser(helpful)
    # _plugins_parsing should be the last thing to act upon the main
    # parser (--help should display plugin-specific options last)
    _plugins_parsing(helpful, plugins)

    if not detect_defaults:
        global helpful_parser # pylint: disable=global-statement
        helpful_parser = helpful
    return helpful.parse_args()


def _create_subparsers(helpful):
    helpful.add("config_changes", "--num", type=int, default=flag_default("num"),
                help="How many past revisions you want to be displayed")

    from certbot.client import sample_user_agent # avoid import loops
    helpful.add(
        None, "--user-agent", default=flag_default("user_agent"),
        help='Set a custom user agent string for the client. User agent strings allow '
             'the CA to collect high level statistics about success rates by OS, '
             'plugin and use case, and to know when to deprecate support for past Python '
             "versions and flags. If you wish to hide this information from the Let's "
             'Encrypt server, set this to "". '
             '(default: {0}). The flags encoded in the user agent are: '
             '--duplicate, --force-renew, --allow-subset-of-names, -n, and '
             'whether any hooks are set.'.format(sample_user_agent()))
    helpful.add(
        None, "--user-agent-comment", default=flag_default("user_agent_comment"),
        type=_user_agent_comment_type,
        help="Add a comment to the default user agent string. May be used when repackaging Certbot "
             "or calling it from another tool to allow additional statistical data to be collected."
             " Ignored if --user-agent is set. (Example: Foo-Wrapper/1.0)")
    helpful.add("certonly",
                "--csr", default=flag_default("csr"), type=read_file,
                help="Path to a Certificate Signing Request (CSR) in DER or PEM format."
                " Currently --csr only works with the 'certonly' subcommand.")
    helpful.add("revoke",
                "--reason", dest="reason",
                choices=CaseInsensitiveList(sorted(constants.REVOCATION_REASONS,
                                                   key=constants.REVOCATION_REASONS.get)),
                action=_EncodeReasonAction, default=flag_default("reason"),
                help="Specify reason for revoking certificate. (default: unspecified)")
    helpful.add("revoke",
                "--delete-after-revoke", action="store_true",
                default=flag_default("delete_after_revoke"),
                help="Delete certificates after revoking them, along with all previous and later "
                "versions of those certificates.")
    helpful.add("revoke",
                "--no-delete-after-revoke", action="store_false",
                dest="delete_after_revoke",
                default=flag_default("delete_after_revoke"),
                help="Do not delete certificates after revoking them. This "
                     "option should be used with caution because the 'renew' "
                     "subcommand will attempt to renew undeleted revoked "
                     "certificates.")
    helpful.add("rollback",
                "--checkpoints", type=int, metavar="N",
                default=flag_default("rollback_checkpoints"),
                help="Revert configuration N number of checkpoints.")
    helpful.add("plugins",
                "--init", action="store_true", default=flag_default("init"),
                help="Initialize plugins.")
    helpful.add("plugins",
                "--prepare", action="store_true", default=flag_default("prepare"),
                help="Initialize and prepare plugins.")
    helpful.add("plugins",
                "--authenticators", action="append_const", dest="ifaces",
                default=flag_default("ifaces"),
                const=interfaces.IAuthenticator, help="Limit to authenticator plugins only.")
    helpful.add("plugins",
                "--installers", action="append_const", dest="ifaces",
                default=flag_default("ifaces"),
                const=interfaces.IInstaller, help="Limit to installer plugins only.")


class CaseInsensitiveList(list):
    """A list that will ignore case when searching.

    This class is passed to the `choices` argument of `argparse.add_arguments`
    through the `helpful` wrapper. It is necessary due to special handling of
    command line arguments by `set_by_cli` in which the `type_func` is not applied."""
    def __contains__(self, element):
        return super(CaseInsensitiveList, self).__contains__(element.lower())


def _paths_parser(helpful):
    add = helpful.add
    verb = helpful.verb
    if verb == "help":
        verb = helpful.help_arg

    cph = "Path to where certificate is saved (with auth --csr), installed from, or revoked."
    sections = ["paths", "install", "revoke", "certonly", "manage"]
    if verb == "certonly":
        add(sections, "--cert-path", type=os.path.abspath,
            default=flag_default("auth_cert_path"), help=cph)
    elif verb == "revoke":
        add(sections, "--cert-path", type=read_file, required=False, help=cph)
    else:
        add(sections, "--cert-path", type=os.path.abspath, help=cph)

    section = "paths"
    if verb in ("install", "revoke"):
        section = verb
    # revoke --key-path reads a file, install --key-path takes a string
    add(section, "--key-path",
        type=((verb == "revoke" and read_file) or os.path.abspath),
        help="Path to private key for certificate installation "
             "or revocation (if account key is missing)")

    default_cp = None
    if verb == "certonly":
        default_cp = flag_default("auth_chain_path")
    add(["paths", "install"], "--fullchain-path", default=default_cp, type=os.path.abspath,
        help="Accompanying path to a full certificate chain (certificate plus chain).")
    add("paths", "--chain-path", default=default_cp, type=os.path.abspath,
        help="Accompanying path to a certificate chain.")
    add("paths", "--config-dir", default=flag_default("config_dir"),
        help=config_help("config_dir"))
    add("paths", "--work-dir", default=flag_default("work_dir"),
        help=config_help("work_dir"))
    add("paths", "--logs-dir", default=flag_default("logs_dir"),
        help="Logs directory.")
    add("paths", "--server", default=flag_default("server"),
        help=config_help("server"))


def _plugins_parsing(helpful, plugins):
    # It's nuts, but there are two "plugins" topics.  Somehow this works
    helpful.add_group(
        "plugins", description="Plugin Selection: Certbot client supports an "
        "extensible plugins architecture. See '%(prog)s plugins' for a "
        "list of all installed plugins and their names. You can force "
        "a particular plugin by setting options provided below. Running "
        "--help <plugin_name> will list flags specific to that plugin.")

    helpful.add("plugins", "--configurator", default=flag_default("configurator"),
                help="Name of the plugin that is both an authenticator and an installer."
                " Should not be used together with --authenticator or --installer. "
                "(default: Ask)")
    helpful.add("plugins", "-a", "--authenticator", default=flag_default("authenticator"),
                help="Authenticator plugin name.")
    helpful.add("plugins", "-i", "--installer", default=flag_default("installer"),
                help="Installer plugin name (also used to find domains).")
    helpful.add(["plugins", "certonly", "run", "install", "config_changes"],
                "--apache", action="store_true", default=flag_default("apache"),
                help="Obtain and install certificates using Apache")
    helpful.add(["plugins", "certonly", "run", "install", "config_changes"],
                "--nginx", action="store_true", default=flag_default("nginx"),
                help="Obtain and install certificates using Nginx")
    helpful.add(["plugins", "certonly"], "--standalone", action="store_true",
                default=flag_default("standalone"),
                help='Obtain certificates using a "standalone" webserver.')
    helpful.add(["plugins", "certonly"], "--manual", action="store_true",
                default=flag_default("manual"),
                help="Provide laborious manual instructions for obtaining a certificate")
    helpful.add(["plugins", "certonly"], "--webroot", action="store_true",
                default=flag_default("webroot"),
                help="Obtain certificates by placing files in a webroot directory.")
    helpful.add(["plugins", "certonly"], "--dns-cloudflare", action="store_true",
                default=flag_default("dns_cloudflare"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                      "using Cloudflare for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-cloudxns", action="store_true",
                default=flag_default("dns_cloudxns"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                     "using CloudXNS for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-digitalocean", action="store_true",
                default=flag_default("dns_digitalocean"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                      "using DigitalOcean for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-dnsimple", action="store_true",
                default=flag_default("dns_dnsimple"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                      "using DNSimple for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-dnsmadeeasy", action="store_true",
                default=flag_default("dns_dnsmadeeasy"),
                help=("Obtain certificates using a DNS TXT record (if you are"
                      "using DNS Made Easy for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-gehirn", action="store_true",
                default=flag_default("dns_gehirn"),
                help=("Obtain certificates using a DNS TXT record "
                     "(if you are using Gehirn Infrastracture Service for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-google", action="store_true",
                default=flag_default("dns_google"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                      "using Google Cloud DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-linode", action="store_true",
                default=flag_default("dns_linode"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                      "using Linode for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-luadns", action="store_true",
                default=flag_default("dns_luadns"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                      "using LuaDNS for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-nsone", action="store_true",
                default=flag_default("dns_nsone"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                      "using NS1 for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-ovh", action="store_true",
                default=flag_default("dns_ovh"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                      "using OVH for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-rfc2136", action="store_true",
                default=flag_default("dns_rfc2136"),
                help="Obtain certificates using a DNS TXT record (if you are using BIND for DNS).")
    helpful.add(["plugins", "certonly"], "--dns-route53", action="store_true",
                default=flag_default("dns_route53"),
                help=("Obtain certificates using a DNS TXT record (if you are using Route53 for "
                      "DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-sakuracloud", action="store_true",
                default=flag_default("dns_sakuracloud"),
                help=("Obtain certificates using a DNS TXT record "
                     "(if you are using Sakura Cloud for DNS)."))

    # things should not be reorder past/pre this comment:
    # plugins_group should be displayed in --help before plugin
    # specific groups (so that plugins_group.description makes sense)

    helpful.add_plugin_args(plugins)


class _EncodeReasonAction(argparse.Action):
    """Action class for parsing revocation reason."""

    def __call__(self, parser, namespace, reason, option_string=None):
        """Encodes the reason for certificate revocation."""
        code = constants.REVOCATION_REASONS[reason.lower()]
        setattr(namespace, self.dest, code)



class _PrefChallAction(argparse.Action):
    """Action class for parsing preferred challenges."""

    def __call__(self, parser, namespace, pref_challs, option_string=None):
        try:
            challs = parse_preferred_challenges(pref_challs.split(","))
        except errors.Error as error:
            raise argparse.ArgumentError(self, str(error))
        namespace.pref_challs.extend(challs)


def parse_preferred_challenges(pref_challs):
    """Translate and validate preferred challenges.

    :param pref_challs: list of preferred challenge types
    :type pref_challs: `list` of `str`

    :returns: validated list of preferred challenge types
    :rtype: `list` of `str`

    :raises errors.Error: if pref_challs is invalid

    """
    aliases = {"dns": "dns-01", "http": "http-01", "tls-sni": "tls-sni-01"}
    challs = [c.strip() for c in pref_challs]
    challs = [aliases.get(c, c) for c in challs]
    unrecognized = ", ".join(name for name in challs
                             if name not in challenges.Challenge.TYPES)
    if unrecognized:
        raise errors.Error(
            "Unrecognized challenges: {0}".format(unrecognized))
    return challs

def _user_agent_comment_type(value):
    if "(" in value or ")" in value:
        raise argparse.ArgumentTypeError("may not contain parentheses")
    return value

class _DeployHookAction(argparse.Action):
    """Action class for parsing deploy hooks."""

    def __call__(self, parser, namespace, values, option_string=None):
        renew_hook_set = namespace.deploy_hook != namespace.renew_hook
        if renew_hook_set and namespace.renew_hook != values:
            raise argparse.ArgumentError(
                self, "conflicts with --renew-hook value")
        namespace.deploy_hook = namespace.renew_hook = values


class _RenewHookAction(argparse.Action):
    """Action class for parsing renew hooks."""

    def __call__(self, parser, namespace, values, option_string=None):
        deploy_hook_set = namespace.deploy_hook is not None
        if deploy_hook_set and namespace.deploy_hook != values:
            raise argparse.ArgumentError(
                self, "conflicts with --deploy-hook value")
        namespace.renew_hook = values


def nonnegative_int(value):
    """Converts value to an int and checks that it is not negative.

    This function should used as the type parameter for argparse
    arguments.

    :param str value: value provided on the command line

    :returns: integer representation of value
    :rtype: int

    :raises argparse.ArgumentTypeError: if value isn't a non-negative integer

    """
    try:
        int_value = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("value must be an integer")

    if int_value < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return int_value
