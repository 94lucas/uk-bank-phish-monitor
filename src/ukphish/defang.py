"""Defang indicators so they are safe to share in alerts and reports."""


def defang(indicator: str) -> str:
    """barclays-verify.com -> barclays-verify[.]com, https:// -> hxxps://"""
    return (
        indicator.replace("https://", "hxxps://")
        .replace("http://", "hxxp://")
        .replace(".", "[.]")
    )


def refang(indicator: str) -> str:
    return (
        indicator.replace("[.]", ".")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
    )
