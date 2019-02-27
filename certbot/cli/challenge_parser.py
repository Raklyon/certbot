import argparse
from acme import challenges
from certbot import errors


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
