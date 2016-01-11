#!/usr/bin/python3
import base64
import getpass
import hashlib
import random
import subprocess

SALT_BYTES = 16

rng = random.SystemRandom()

USER_TEMPLATE = """\
dn: uid={uid},ou=Account,{base}
objectClass: inetOrgPerson
objectClass: inetLocalMailRecipient
uid: {uid}
cn: {cn}
sn: {sn}
givenName: {given_name}
mail: {mail}
userPassword:: {password_base64}\n"""

PASSWD_TEMPLATE = """\
dn: uid={uid},ou=Account,{base}
changetype: modify
replace: userPassword
userPassword:: {password_base64}
-\n"""

USERDEL_TEMPLATE = """\
dn: uid={uid},ou=Account,{base}
changetype: delete\n"""

ADD_MAIL_ALIAS_TEMPLATE = """\
add: mailLocalAddress
mailLocalAddress: {addr}
-\n"""

REMOVE_MAIL_ALIAS_TEMPLATE = """\
delete: mailLocalAddress
mailLocalAddress: {addr}
-\n"""

ENABLE_LOGIN_TEMPLATE = """\
dn: uid={uid},ou=Account,{base}
changetype: modify
add: objectclass
objectclass: posixAccount
-
add: uidNumber
uidNumber: {uid_number}
-
add: gidNumber
gidNumber: {gid_number}
-
add: homeDirectory
homeDirectory: {home}
-
add: loginShell
loginShell: /bin/bash
-\n"""


def ask_pass():
    pwd1 = getpass.getpass().encode("utf-8")
    if not pwd1:
        raise ValueError("password must not be empty")
    return pwd1


def ask_pass_new():
    pwd1 = getpass.getpass().encode("utf-8")
    pwd2 = getpass.getpass('Confirm: ').encode("utf-8")
    if pwd1 != pwd2:
        raise ValueError("passwords do not match")
    if not pwd1:
        raise ValueError("password must not be empty")
    return pwd1


def ask_pass_or_exit(asker=ask_pass):
    try:
        return asker()
    except ValueError as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)


def ssha_password(password):
    sha1 = hashlib.sha1()
    salt = rng.getrandbits(SALT_BYTES*8).to_bytes(SALT_BYTES, "little")
    sha1.update(password)
    sha1.update(salt)

    digest = sha1.digest()
    passwd = b"{SSHA}" + base64.b64encode(digest + salt)
    return passwd


def useradd(args):
    if args.password is None:
        args.password = ask_pass_or_exit(ask_pass_new)

    instance = USER_TEMPLATE.format(
        uid=args.uid,
        cn=args.cn,
        sn=args.sn,
        given_name=args.given_name,
        mail=args.mail,
        base=args.base,
        password_base64=base64.b64encode(ssha_password(args.password)).decode(
            "ascii"))

    if args.dry_run:
        print(instance)
        return

    try:
        print(subprocess.check_output(
            [
                "ldapadd",
                "-Y", "EXTERNAL",
                "-H", "ldapi://"
            ],
            input=instance.encode()
        ).decode())
    except subprocess.CalledProcessError:
        print("failed")
        sys.exit(1)


def passwd(args):
    if args.password is None:
        args.password = ask_pass_or_exit(ask_pass_new)

    instance = PASSWD_TEMPLATE.format(
        uid=args.uid,
        base=args.base,
        password_base64=base64.b64encode(ssha_password(args.password)).decode(
            "ascii"))

    if args.dry_run:
        print(instance)
        return

    try:
        print(subprocess.check_output(
            [
                "ldapmodify",
                "-Y", "EXTERNAL",
                "-H", "ldapi://"
            ],
            input=instance.encode()
        ).decode())
    except subprocess.CalledProcessError:
        print("failed")
        sys.exit(1)


def mailaddress_add(args):
    instance = "dn: uid={},ou=Account,{}\nchangetype: modify\n".format(args.uid, args.base)
    instance += "".join(
        ADD_MAIL_ALIAS_TEMPLATE.format(addr=addr)
        for addr in args.addrs
    )

    if args.dry_run:
        print(instance)
        return

    try:
        print(subprocess.check_output(
            [
                "ldapmodify",
                "-Y", "EXTERNAL",
                "-H", "ldapi://"
            ],
            input=instance.encode()
        ).decode())
    except subprocess.CalledProcessError:
        print("failed")
        sys.exit(1)


def mailaddress_remove(args):
    instance = "dn: uid={},ou=Account,{}\nchangetype: modify\n".format(args.uid, args.base)
    instance += "".join(
        REMOVE_MAIL_ALIAS_TEMPLATE.format(addr=addr)
        for addr in args.addrs
    )

    if args.dry_run:
        print(instance)
        return

    try:
        print(subprocess.check_output(
            [
                "ldapmodify",
                "-Y", "EXTERNAL",
                "-H", "ldapi://"
            ],
            input=instance.encode()
        ).decode())
    except subprocess.CalledProcessError:
        print("failed")
        sys.exit(1)


def enable_login(args):
    instance = ENABLE_LOGIN_TEMPLATE.format(
        uid=args.uid,
        base=args.base,
        uid_number=args.uid_number,
        gid_number=args.gid_number,
        home=args.home or "/home/{}".format(args.uid)
    )

    if args.dry_run:
        print(instance)
        return

    try:
        print(subprocess.check_output(
            [
                "ldapmodify",
                "-Y", "EXTERNAL",
                "-H", "ldapi://"
            ],
            input=instance.encode()
        ).decode())
    except subprocess.CalledProcessError:
        print("failed")
        sys.exit(1)


def userdel(args):
    instance = USERDEL_TEMPLATE.format(
        uid=args.uid,
        base=args.base,
    )

    if args.dry_run:
        print(instance)
        return

    try:
        print(subprocess.check_output(
            [
                "ldapmodify",
                "-Y", "EXTERNAL",
                "-H", "ldapi://"
            ],
            input=instance.encode()
        ).decode())
    except subprocess.CalledProcessError:
        print("failed")
        sys.exit(1)


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d", "--dry-run",
        default=False,
        action="store_true",
        help="Do not make any changes, but dump possible ldif output to stdout"
    )

    parser.add_argument(
        "base",
        help="Base DN to use"
    )

    subparsers = parser.add_subparsers(
        help="Function to invoke",
    )

    sparser = subparsers.add_parser("userdel")
    sparser.set_defaults(func=userdel)
    sparser.add_argument(
        "uid",
        metavar="USERNAME",
        help="Alphanumeric user identifier of the user to delete"
    )

    sparser = subparsers.add_parser("useradd")
    sparser.set_defaults(func=useradd)
    sparser.add_argument(
        "--password",
        default=None,
        metavar="PASSWORD",
        help="Initial password. If omitted, prompt for password on stdin."
    )
    sparser.add_argument(
        "uid",
        metavar="USERNAME",
        help="Alphanumeric user identifier. Must be unique, cannot be changed"
    )
    sparser.add_argument(
        "cn",
        metavar="DISPLAYNAME",
        help="Ideally full name, displayed possibly everywhere"
    )
    sparser.add_argument(
        "--sn",
        metavar="SURNAME",
        default="XXX",
        help="Family name"
    )
    sparser.add_argument(
        "--given-name",
        metavar="GIVENNAME",
        default="XXX",
        help="Given name"
    )
    sparser.add_argument(
        "mail",
        metavar="MAIL",
        help="E-Mail address under which the user can be reached"
    )

    sparser = subparsers.add_parser("passwd")
    sparser.set_defaults(func=passwd)
    sparser.add_argument(
        "--password",
        default=None,
        metavar="PASSWORD",
        help="New password. If omitted, prompt for password on stdin."
    )
    sparser.add_argument(
        "uid",
        metavar="USERNAME",
        help="Alphanumeric user identifier of the user whose password shall be"
        " changed"
    )

    sparser = subparsers.add_parser("mailaddress-add")
    sparser.set_defaults(func=mailaddress_add)
    sparser.add_argument(
        "uid",
        metavar="USERNAME",
        help="UID of the user to modify"
    )
    sparser.add_argument(
        "addrs",
        nargs="+",
        metavar="MAILADDRESS",
        help="Mail aliases to add, must be full mail addresses"
    )

    sparser = subparsers.add_parser("mailaddress-remove")
    sparser.set_defaults(func=mailaddress_remove)
    sparser.add_argument(
        "uid",
        metavar="USERNAME",
        help="UID of the user to modify"
    )
    sparser.add_argument(
        "addrs",
        nargs="+",
        metavar="MAILADDRESS",
        help="Mail aliases to add, must be full mail addresses"
    )

    sparser = subparsers.add_parser("login-enable")
    sparser.set_defaults(func=enable_login)
    sparser.add_argument(
        "-d", "--home-directory",
        dest="home",
        default=None,
        help="Home directory, defaults to /home/{uid}"
    )
    sparser.add_argument(
        "uid",
        metavar="USERNAME",
        help="UID of the user to modify"
    )
    sparser.add_argument(
        "uid_number",
        type=int,
        help="Numeric UID to assign to the user",
        metavar="NUMBER"
    )
    sparser.add_argument(
        "gid_number",
        type=int,
        help="Numeric GID to assign to the user",
        metavar="NUMBER"
    )

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        print("no function selected")
        sys.exit(1)

    args.func(args)
